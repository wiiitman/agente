#!/usr/bin/env python3
"""
Nuqleo VPS Agent v2 — Seguro, con firma HMAC en cada request.

Mejoras de seguridad vs v1:
  - Firma HMAC-SHA256 de timestamp+body (anti-replay, anti-tampering)
  - Rate limiting: bloquea IPs tras 5 fallos en 60 s
  - Validación estricta de inputs (container, módulo, dominio, puerto)
  - Protección path-traversal en escritura de archivos
  - Escucha en 127.0.0.1 por defecto (UFW controla el acceso externo)
  - Versión de Odoo validada contra whitelist
"""

import json, os, re, subprocess, tempfile, zipfile, base64
import hashlib, hmac, time, threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import defaultdict
from urllib.parse import urlparse, parse_qs

# ── Configuración ───────────────────────────────────────────────
PORT     = int(os.environ.get('NUQLEO_PORT', 9876))
API_KEY  = os.environ.get('NUQLEO_API_KEY', '')
ODOO_DIR = '/opt/nuqleo-odoo'
LOG_FILE = '/var/log/nuqleo-agent.log'
BIND     = os.environ.get('NUQLEO_BIND', '127.0.0.1')  # solo loopback por defecto; UFW controla acceso externo

# ── Snapshots diarios automáticos (retención corta, no reemplazan el backup
#    manual que el cliente descarga) — uno por día por instancia, se purgan
#    solos pasados SNAPSHOT_RETENTION_DAYS días. ──
SNAPSHOT_ROOT            = '/opt/nuqleo-snapshots'
SNAPSHOT_RETENTION_DAYS  = 7

# Versiones permitidas de Odoo
ALLOWED_ODOO_VERSIONS = {'16', '17', '18', '19'}  # odoo:20 aún no existe en Docker Hub

# Rango de puertos permitidos para Odoo
PORT_MIN, PORT_MAX = 8000, 9999

# ── Librería de módulos custom (repo git privado) ────────────────
# Repo con tus módulos propios, organizados en carpetas por versión: /17 /18 /19.
# El agente lo clona/actualiza y los hace seleccionables/instalables en cada deploy.
MODULES_REPO  = os.environ.get('NUQLEO_MODULES_REPO', '')    # ej: github.com/wiiitman/nuqleo-modulos.git
MODULES_TOKEN = os.environ.get('NUQLEO_MODULES_TOKEN', '')   # PAT de lectura (repo privado)
MODULES_DIR   = '/opt/nuqleo-modulos'

# ── Postgres compartido ──────────────────────────────────────────
SHARED_PG_NAME  = 'nuqleo_postgres_shared'
SHARED_PG_PASS  = os.environ.get('NUQLEO_PG_PASS', '')  # ¡Definir NUQLEO_PG_PASS en el entorno!
SHARED_PG_ADMIN = 'postgres'   # superusuario para gestión interna
SHARED_PG_USER  = 'odoo'       # rol que usa Odoo (no 'postgres' — Odoo lo rechaza)
_pg_lock = threading.Lock()

# ── Rate limiting ────────────────────────────────────────────────
_rate_lock   = threading.Lock()
_fail_counts = defaultdict(list)   # ip → [timestamps de fallos]
RATE_WINDOW  = 60    # segundos
RATE_MAX     = 5     # fallos máximos antes de bloquear

# ── Deploy stage tracking ────────────────────────────────────────
_deploy_stages: dict = {}  # container_name → etapa actual

# ── Chunk upload tracking ────────────────────────────────────────
# upload_id → {'chunks': {idx: bytes}, 'total': N, 'container': str, 'module': str, 'ts': float}
_chunk_uploads: dict = {}
_chunk_lock = threading.Lock()

def _set_stage(container: str, stage: str):
    _deploy_stages[container] = stage
    log(f'[deploy] {container}: {stage}')


def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    with _rate_lock:
        _fail_counts[ip] = [t for t in _fail_counts[ip] if now - t < RATE_WINDOW]
        return len(_fail_counts[ip]) >= RATE_MAX


def _record_fail(ip: str):
    with _rate_lock:
        _fail_counts[ip].append(time.time())


# ── Logging ──────────────────────────────────────────────────────
def log(msg: str):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(line + '\n')
    except Exception:
        pass


# ── Postgres compartido ──────────────────────────────────────────

def _pg_running() -> bool:
    r = run(['docker', 'inspect', '--format', '{{.State.Status}}', SHARED_PG_NAME])
    return r['ok'] and r['stdout'].strip() == 'running'

def _ensure_odoo_role():
    """Crear rol odoo si no existe (Odoo rechaza conectarse como 'postgres')."""
    run(['docker', 'exec', SHARED_PG_NAME, 'psql', '-U', SHARED_PG_ADMIN, '-c',
         f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{SHARED_PG_USER}') "
         f"THEN CREATE ROLE {SHARED_PG_USER} WITH LOGIN CREATEDB PASSWORD '{SHARED_PG_PASS}'; END IF; END $$"])

def _ensure_shared_postgres() -> bool:
    if _pg_running():
        _ensure_odoo_role()  # asegurar rol aunque el container ya esté corriendo
        return True
    log('[pg] Iniciando postgres compartido...')
    run(f'docker rm -f {SHARED_PG_NAME} 2>/dev/null || true')
    r = run([
        'docker', 'run', '-d',
        '--name', SHARED_PG_NAME,
        '--network', 'nuqleo-net',
        '-e', f'POSTGRES_PASSWORD={SHARED_PG_PASS}',
        # El superusuario admin debe ser 'postgres' (SHARED_PG_ADMIN): el agente
        # gestiona postgres con `psql -U postgres`. El rol 'odoo' (con el que conecta
        # Odoo) se crea aparte en _ensure_odoo_role(). Si aquí se pone 'odoo' como
        # POSTGRES_USER, NO existe el rol 'postgres' → todos los _pg_exec fallan →
        # "no se pudo crear la base de datos".
        '-e', f'POSTGRES_USER={SHARED_PG_ADMIN}',
        '-v', '/opt/nuqleo-pgdata:/var/lib/postgresql/data',
        '--restart', 'unless-stopped',
        'postgres:15-alpine',
    ])
    if not r['ok']:
        log(f'[pg] Error iniciando postgres: {r["stderr"]}')
        return False
    # Poll hasta que Postgres acepte conexiones (evita sleep fijo de 6s)
    for _ in range(20):
        if run(['docker', 'exec', SHARED_PG_NAME, 'pg_isready', '-U', SHARED_PG_ADMIN])['ok']:
            break
        time.sleep(1)
    _ensure_odoo_role()
    log('[pg] Postgres compartido listo.')
    return True

def _pg_exec(sql: str) -> dict:
    return run(['docker', 'exec', SHARED_PG_NAME, 'psql', '-U', SHARED_PG_ADMIN, '-c', sql])

def _pg_query(sql: str) -> str:
    r = run(['docker', 'exec', SHARED_PG_NAME, 'psql', '-U', SHARED_PG_ADMIN, '-tAc', sql])
    return r['stdout'].strip() if r['ok'] else ''

def _template_exists(version: str) -> bool:
    name = f'odoo{version}_template'
    return _pg_query(f"SELECT 1 FROM pg_database WHERE datname='{name}'") == '1'

def _pg_query_db(dbname: str, sql: str) -> str:
    r = run(['docker', 'exec', SHARED_PG_NAME, 'psql', '-U', SHARED_PG_ADMIN, '-d', dbname, '-tAc', sql])
    return r['stdout'].strip() if r['ok'] else ''

def _template_init_ok(name: str) -> bool:
    """Verifica que el init realmente terminó (no solo que el proceso salió sin
    reventar): el usuario admin debe existir con password. Sin esto, un init que
    truena a medias (timeout, red) deja una BD vacía que _template_exists() daría
    por buena para siempre — contaminando todos los deploys futuros de esa versión
    con un template roto (admin/admin no funciona pero Odoo igual levanta)."""
    _pg_exec(f"UPDATE pg_database SET datallowconn=true WHERE datname='{name}'")
    result = _pg_query_db(name, "SELECT 1 FROM res_users WHERE login='admin' AND password IS NOT NULL")
    return result == '1'

def _ensure_template_db(version: str) -> bool:
    """Crea la BD plantilla para la versión dada (solo la primera vez, ~3 min)."""
    name = f'odoo{version}_template'
    if _template_exists(version):
        return True
    with _pg_lock:
        if _template_exists(version):  # doble check dentro del lock
            return True
        log(f'[pg] Creando template odoo{version} sin demo data (primera vez, ~3 min)...')
        _pg_exec(f'CREATE DATABASE {name} OWNER {SHARED_PG_USER}')
        _pg_exec(f'GRANT ALL PRIVILEGES ON DATABASE {name} TO {SHARED_PG_USER}')
        tmp = f'odoo_init_{version}_{int(time.time())}'
        try:
            r = run(
                f'docker run --rm --name {tmp} --network nuqleo-net '
                f'-e HOST={SHARED_PG_NAME} -e USER={SHARED_PG_USER} -e PASSWORD={SHARED_PG_PASS} '
                f'odoo:{version} -- --database {name} --init base --stop-after-init --no-http --without-demo=all',
                timeout=360
            )
        except Exception as e:
            log(f'[pg] Timeout/error corriendo init de template odoo{version}: {e}')
            r = {'ok': False, 'stdout': '', 'stderr': str(e)}

        looks_done = r['ok'] or 'stop' in (r['stdout'] + r['stderr']).lower()
        if looks_done and _template_init_ok(name):
            _pg_exec(f"UPDATE pg_database SET datistemplate=true, datallowconn=false WHERE datname='{name}'")
            log(f'[pg] Template odoo{version} listo.')
            return True

        # Init falló o quedó a medias: NO dejar la BD vacía/corrupta ahí — la
        # borramos para que el próximo deploy la reconstruya en vez de heredar
        # para siempre un template roto (_template_exists solo mira el nombre).
        log(f'[pg] Error creando template odoo{version} (proceso_ok={looks_done}): {r["stderr"][:300]}')
        run(['docker', 'rm', '-f', tmp])
        _pg_exec(f"UPDATE pg_database SET datallowconn=false WHERE datname='{name}'")
        _pg_exec(f'DROP DATABASE IF EXISTS {name}')
        return False


# ── Correo saliente: Postfix local en el host, compartido por todas las
#    instancias del VPS. Envío DIRECTO a internet (sin relay externo de pago) —
#    los contenedores lo alcanzan vía host.docker.internal (extra_hosts en cada
#    docker-compose.yml). Solo acepta conexiones desde la red de Docker
#    (mynetworks), nunca desde internet, para no volverse un open relay.
#    Entregabilidad: depende de que el proveedor del VPS no bloquee el puerto 25
#    saliente y de que el destino no rechace por falta de SPF/DKIM/PTR — sin
#    esos registros DNS, buena parte del correo puede caer en spam. Es la
#    limitación conocida de un envío directo sin relay.
POSTFIX_MYNETWORKS = '127.0.0.0/8 172.16.0.0/12'

def _postfix_active() -> bool:
    return run(['systemctl', 'is-active', 'postfix'])['ok']

def _ensure_host_postfix() -> bool:
    if _postfix_active():
        return True
    log('[mail] Instalando Postfix local (envío directo, sin relay externo)...')
    hostname = (run(['hostname', '-f'])['stdout'] or run(['hostname'])['stdout'] or 'localhost').strip()
    run(f'echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections')
    run(f'echo "postfix postfix/mailname string {hostname}" | debconf-set-selections')
    r = run('DEBIAN_FRONTEND=noninteractive apt-get install -y postfix', timeout=180)
    if not r['ok'] and not _postfix_active():
        log(f'[mail] Error instalando postfix: {r["stderr"][:300]}')
        return False
    run(['postconf', '-e', 'inet_interfaces = all'])
    run(['postconf', '-e', f'mynetworks = {POSTFIX_MYNETWORKS}'])
    run(['postconf', '-e', 'smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination'])
    run(['postconf', '-e', 'smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination'])
    run(['systemctl', 'enable', '--now', 'postfix'])
    run(['systemctl', 'restart', 'postfix'])
    # UFW por defecto niega todo INPUT no explícitamente permitido, y el tráfico
    # contenedor→host pasa por esa cadena — sin esta regla los contenedores no
    # alcanzan el postfix del host aunque escuche en 0.0.0.0:25. Restringida a la
    # subred de Docker, nunca abierta a internet (ufw ya deniega 25 desde fuera).
    run(['ufw', 'allow', 'from', '172.16.0.0/12', 'to', 'any', 'port', '25', 'proto', 'tcp'])
    ok = _postfix_active()
    log(f'[mail] Postfix local {"listo" if ok else "NO pudo iniciar"} (solo acepta desde contenedores Docker).')
    if ok:
        _log_port25_egress_test()
    return ok

def _log_port25_egress_test():
    """Diagnóstico único: muchos proveedores de VPS bloquean el puerto 25 saliente
    para frenar spam — sin esta prueba no hay forma de saber si el correo directo
    puede siquiera salir de este servidor hasta que un cliente reporte que no le
    llegan correos."""
    r = run('timeout 5 bash -c "echo > /dev/tcp/aspmx.l.google.com/25" 2>&1 && echo ABIERTO || echo BLOQUEADO')
    estado = 'ABIERTO' if 'ABIERTO' in r['stdout'] else 'BLOQUEADO'
    log(f'[mail] Prueba de egress puerto 25: {estado} '
        f'({"el correo directo debería poder salir" if estado == "ABIERTO" else "el proveedor del VPS lo está bloqueando, el correo NO saldrá hasta resolverlo con soporte"})')

def _create_db_from_template(db_name: str, version: str) -> bool:
    """Crea la BD del cliente copiando la plantilla (instantáneo).
    La BD se crea propiedad del rol 'odoo' compartido (dueño de las tablas del
    template) para que la instalación de módulos no falle por permisos.
    Las credenciales de Postgres son internas (solo el agente las usa); el
    aislamiento entre clientes lo da --db-filter en el contenedor de cada uno,
    no un rol de Postgres por cliente."""
    tpl = f'odoo{version}_template'
    # Permitir conexiones al template temporalmente para la copia
    _pg_exec(f"UPDATE pg_database SET datallowconn=true WHERE datname='{tpl}'")
    r = _pg_exec(f"CREATE DATABASE {db_name} TEMPLATE {tpl} OWNER {SHARED_PG_USER}")
    _pg_exec(f"UPDATE pg_database SET datallowconn=false WHERE datname='{tpl}'")
    return r['ok']


# ── Helpers ──────────────────────────────────────────────────────
def run(cmd: list | str, timeout=120) -> dict:
    """Ejecuta comando. Prefiere lista para evitar shell injection."""
    if isinstance(cmd, str):
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    else:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return {
        'ok':     result.returncode == 0,
        'stdout': result.stdout.strip(),
        'stderr': result.stderr.strip(),
        'code':   result.returncode,
    }


def _detect_compose() -> str:
    """Detecta el comando de compose disponible: 'docker compose' (v2, plugin) o
    'docker-compose' (v1, standalone). El docker.io de Ubuntu no trae el plugin v2,
    así que sin esto el deploy falla con 'unknown shorthand flag: d'."""
    if run(['docker', 'compose', 'version'])['ok']:
        return 'docker compose'
    if run(['docker-compose', 'version'])['ok']:
        return 'docker-compose'
    return 'docker compose'  # fallback; setup.sh instala docker-compose-v2

COMPOSE = _detect_compose()


# ── Librería de módulos custom (repo git privado, carpetas por versión) ──
def _sync_custom_modules() -> bool:
    """Clona/actualiza el repo de módulos custom en MODULES_DIR (swap atómico)."""
    if not MODULES_REPO:
        return False
    run('command -v git >/dev/null 2>&1 || (DEBIAN_FRONTEND=noninteractive apt-get install -y git >/dev/null 2>&1)')
    auth_url = f'https://{MODULES_TOKEN}@{MODULES_REPO}' if MODULES_TOKEN else f'https://{MODULES_REPO}'
    tmp = MODULES_DIR + '.tmp'
    # Contabo pierde ~50-70% de SYN TCP → un clone "largo" casi siempre expira.
    # Estrategia: muchos intentos CORTOS (cap 45s con `timeout`) hasta que un SYN
    # logre conectar. Abortar rápido y reintentar es mucho más fiable que esperar.
    clone = (f'timeout 45 git -c http.lowSpeedLimit=1000 -c http.lowSpeedTime=15 '
             f'clone --depth 1 {auth_url} {tmp}')
    last = ''
    for attempt in range(1, 9):
        run(f'rm -rf {tmp}')
        r = run(clone, timeout=60)
        if r['ok'] and os.path.isdir(tmp):
            run(f'rm -rf {MODULES_DIR} && mv {tmp} {MODULES_DIR}')
            log(f"[modules] sync OK (intento {attempt})")
            return True
        last = (r.get('stderr') or '')[:150]
        # Si es error de auth (no de red), no tiene sentido reintentar.
        if 'not granted' in last or 'Authentication' in last or '403' in last:
            break
    run(f'rm -rf {tmp}')
    log(f"[modules] sync FAIL tras reintentos: {last}")
    return False


OM_ACCOUNT_REPO  = 'https://github.com/odoomates/odooapps.git'
OM_ACCOUNT_CACHE = '/opt/nuqleo-modulos/om_account'  # caché local por versión

# Módulos de contabilidad completa a instalar desde odoomates/odooapps.
# Se hace sparse checkout de todos en un solo clone (eficiente).
OM_ACCOUNT_MODULES = [
    'om_account_accountant',        # contabilidad completa (reportes, diario, asientos)
    'om_account_asset',             # gestión de activos fijos
    'om_account_budget',            # presupuestos
    'om_account_followup',          # seguimiento de cobros a clientes
    'om_account_bank_statement_import',  # importar extractos bancarios (OFX/CSV)
    'om_fiscal_year',               # año fiscal personalizable
]

def _fetch_om_accounting(version: str, addons_dir: str) -> list:
    """Descarga todos los módulos de contabilidad de odoomates/odooapps para la versión
    dada. Usa caché local por versión. Retorna lista de módulos copiados exitosamente."""
    branch   = f'{version}.0'
    cache_dir = os.path.join(OM_ACCOUNT_CACHE, version)

    # Determinar qué módulos faltan en addons y cuáles no están en caché
    need_download = []
    cached = []
    for mod in OM_ACCOUNT_MODULES:
        in_addons = os.path.isdir(os.path.join(addons_dir, mod))
        in_cache  = os.path.isdir(os.path.join(cache_dir, mod)) and \
                    os.path.exists(os.path.join(cache_dir, mod, '__manifest__.py'))
        if in_addons:
            cached.append(mod)  # ya está listo
        elif in_cache:
            run(f'cp -r {os.path.join(cache_dir, mod)} {addons_dir}/')
            cached.append(mod)
        else:
            need_download.append(mod)

    if not need_download:
        log(f'[om_account] {version}: todos los módulos ya en caché/addons')
        return cached

    # Descargar del repo con sparse checkout (un solo clone, carpetas separadas)
    log(f'[om_account] {version}: descargando {len(need_download)} módulos desde GitHub branch {branch}...')
    tmp = f'/tmp/om_acc_{version}_{int(time.time())}'

    clone_cmd = (
        f'timeout 90 git -c http.lowSpeedLimit=500 -c http.lowSpeedTime=20 '
        f'clone --depth 1 -b {branch} --filter=blob:none --sparse '
        f'{OM_ACCOUNT_REPO} {tmp}'
    )
    cloned = False
    for attempt in range(1, 6):
        run(f'rm -rf {tmp}')
        r = run(clone_cmd, timeout=100)
        if r['ok'] and os.path.isdir(tmp):
            cloned = True
            break
        log(f'[om_account] clone intento {attempt} falló: {(r["stderr"] or "")[:100]}')

    if not cloned:
        log(f'[om_account] {version}: no se pudo clonar — usando solo módulos en caché')
        run(f'rm -rf {tmp}')
        return cached

    # Sparse checkout de todos los módulos necesarios en una sola operación
    sparse_paths = ' '.join(need_download)
    run(f'cd {tmp} && git sparse-checkout set {sparse_paths}', timeout=60)

    os.makedirs(cache_dir, exist_ok=True)
    for mod in need_download:
        mod_src = os.path.join(tmp, mod)
        if os.path.isdir(mod_src) and os.path.exists(os.path.join(mod_src, '__manifest__.py')):
            run(f'cp -r {mod_src} {os.path.join(cache_dir, mod)}')
            run(f'cp -r {mod_src} {addons_dir}/')
            cached.append(mod)
            log(f'[om_account] {version}: {mod} instalado OK')
        else:
            log(f'[om_account] {version}: {mod} no existe en branch {branch} (skip)')

    run(f'rm -rf {tmp}')
    log(f'[om_account] {version}: módulos listos → {cached}')
    return cached


# ── Firma digital: 'sign' (Odoo Sign) es exclusivo de Enterprise — NO existe
#    en la imagen odoo:18 Community, así que ofrecerlo como opción en el wizard
#    sin esto era un módulo fantasma (el cliente lo seleccionaba y no pasaba
#    nada). sign_oca de OCA es el equivalente real y libre para Community. ──
OCA_SIGN_REPO   = 'https://github.com/OCA/sign.git'
OCA_SIGN_CACHE  = '/opt/nuqleo-modulos/oca_sign'
OCA_SIGN_MODULES = ['sign_oca']

def _fetch_oca_sign(version: str, addons_dir: str) -> list:
    """Descarga sign_oca (firma digital, licencia AGPL-3) desde OCA/sign para la
    versión dada. Mismo patrón de caché/sparse-checkout que _fetch_om_accounting."""
    branch    = f'{version}.0'
    cache_dir = os.path.join(OCA_SIGN_CACHE, version)

    need_download = []
    cached = []
    for mod in OCA_SIGN_MODULES:
        in_addons = os.path.isdir(os.path.join(addons_dir, mod))
        in_cache  = os.path.isdir(os.path.join(cache_dir, mod)) and \
                    os.path.exists(os.path.join(cache_dir, mod, '__manifest__.py'))
        if in_addons:
            cached.append(mod)
        elif in_cache:
            run(f'cp -r {os.path.join(cache_dir, mod)} {addons_dir}/')
            cached.append(mod)
        else:
            need_download.append(mod)

    if not need_download:
        log(f'[oca_sign] {version}: todos los módulos ya en caché/addons')
        return cached

    log(f'[oca_sign] {version}: descargando {len(need_download)} módulos desde GitHub branch {branch}...')
    tmp = f'/tmp/oca_sign_{version}_{int(time.time())}'

    clone_cmd = (
        f'timeout 90 git -c http.lowSpeedLimit=500 -c http.lowSpeedTime=20 '
        f'clone --depth 1 -b {branch} --filter=blob:none --sparse '
        f'{OCA_SIGN_REPO} {tmp}'
    )
    cloned = False
    for attempt in range(1, 6):
        run(f'rm -rf {tmp}')
        r = run(clone_cmd, timeout=100)
        if r['ok'] and os.path.isdir(tmp):
            cloned = True
            break
        log(f'[oca_sign] clone intento {attempt} falló: {(r["stderr"] or "")[:100]}')

    if not cloned:
        log(f'[oca_sign] {version}: no se pudo clonar — usando solo módulos en caché')
        run(f'rm -rf {tmp}')
        return cached

    sparse_paths = ' '.join(need_download)
    run(f'cd {tmp} && git sparse-checkout set {sparse_paths}', timeout=60)

    os.makedirs(cache_dir, exist_ok=True)
    for mod in need_download:
        mod_src = os.path.join(tmp, mod)
        if os.path.isdir(mod_src) and os.path.exists(os.path.join(mod_src, '__manifest__.py')):
            run(f'cp -r {mod_src} {os.path.join(cache_dir, mod)}')
            run(f'cp -r {mod_src} {addons_dir}/')
            cached.append(mod)
            log(f'[oca_sign] {version}: {mod} instalado OK')
        else:
            log(f'[oca_sign] {version}: {mod} no existe en branch {branch} (skip)')

    run(f'rm -rf {tmp}')
    log(f'[oca_sign] {version}: módulos listos → {cached}')
    return cached


# ── Nómina: hr_payroll de Odoo también es de Enterprise a partir de v17. El
#    equivalente libre para Community es 'payroll' de OCA/payroll (backport de
#    Odoo SA, licencia AGPL-3, mantenido para 16.0-19.0). ──
OCA_PAYROLL_REPO    = 'https://github.com/OCA/payroll.git'
OCA_PAYROLL_CACHE   = '/opt/nuqleo-modulos/oca_payroll'
OCA_PAYROLL_MODULES = ['payroll', 'payroll_account']

def _fetch_oca_payroll(version: str, addons_dir: str) -> list:
    """Descarga payroll + payroll_account desde OCA/payroll. Mismo patrón de
    caché/sparse-checkout que _fetch_om_accounting / _fetch_oca_sign."""
    branch    = f'{version}.0'
    cache_dir = os.path.join(OCA_PAYROLL_CACHE, version)

    need_download = []
    cached = []
    for mod in OCA_PAYROLL_MODULES:
        in_addons = os.path.isdir(os.path.join(addons_dir, mod))
        in_cache  = os.path.isdir(os.path.join(cache_dir, mod)) and \
                    os.path.exists(os.path.join(cache_dir, mod, '__manifest__.py'))
        if in_addons:
            cached.append(mod)
        elif in_cache:
            run(f'cp -r {os.path.join(cache_dir, mod)} {addons_dir}/')
            cached.append(mod)
        else:
            need_download.append(mod)

    if not need_download:
        log(f'[oca_payroll] {version}: todos los módulos ya en caché/addons')
        return cached

    log(f'[oca_payroll] {version}: descargando {len(need_download)} módulos desde GitHub branch {branch}...')
    tmp = f'/tmp/oca_payroll_{version}_{int(time.time())}'

    clone_cmd = (
        f'timeout 90 git -c http.lowSpeedLimit=500 -c http.lowSpeedTime=20 '
        f'clone --depth 1 -b {branch} --filter=blob:none --sparse '
        f'{OCA_PAYROLL_REPO} {tmp}'
    )
    cloned = False
    for attempt in range(1, 6):
        run(f'rm -rf {tmp}')
        r = run(clone_cmd, timeout=100)
        if r['ok'] and os.path.isdir(tmp):
            cloned = True
            break
        log(f'[oca_payroll] clone intento {attempt} falló: {(r["stderr"] or "")[:100]}')

    if not cloned:
        log(f'[oca_payroll] {version}: no se pudo clonar — usando solo módulos en caché')
        run(f'rm -rf {tmp}')
        return cached

    sparse_paths = ' '.join(need_download)
    run(f'cd {tmp} && git sparse-checkout set {sparse_paths}', timeout=60)

    os.makedirs(cache_dir, exist_ok=True)
    for mod in need_download:
        mod_src = os.path.join(tmp, mod)
        if os.path.isdir(mod_src) and os.path.exists(os.path.join(mod_src, '__manifest__.py')):
            run(f'cp -r {mod_src} {os.path.join(cache_dir, mod)}')
            run(f'cp -r {mod_src} {addons_dir}/')
            cached.append(mod)
            log(f'[oca_payroll] {version}: {mod} instalado OK')
        else:
            log(f'[oca_payroll] {version}: {mod} no existe en branch {branch} (skip)')

    run(f'rm -rf {tmp}')
    log(f'[oca_payroll] {version}: módulos listos → {cached}')
    return cached


def _list_custom_modules(version: str) -> list:
    """Lista módulos disponibles en MODULES_DIR/{version} (dirs con __manifest__.py)."""
    base = os.path.join(MODULES_DIR, str(version))
    out = []
    if not os.path.isdir(base):
        return out
    for name in sorted(os.listdir(base)):
        manifest = os.path.join(base, name, '__manifest__.py')
        if os.path.isdir(os.path.join(base, name)) and os.path.exists(manifest):
            label = name
            try:
                m = re.search(r"['\"]name['\"]\s*:\s*['\"]([^'\"]+)['\"]",
                              open(manifest, encoding='utf-8').read())
                if m:
                    label = m.group(1)
            except Exception:
                pass
            out.append({'name': name, 'label': label})
    return out


def _sanitize_name(value: str) -> str:
    """Solo letras, números y guiones. Máx 60 chars."""
    return re.sub(r'[^a-zA-Z0-9\-_]', '', value)[:60]


def _sanitize_domain(value: str) -> str:
    """Dominio válido: letras, números, puntos, guiones."""
    return re.sub(r'[^a-zA-Z0-9.\-]', '', value)[:253]


def _sanitize_url(value: str) -> str:
    """URL http(s) simple para web.base.url (evita inyección en SQL/shell)."""
    v = str(value or '').strip()
    if not re.match(r'^https?://[a-zA-Z0-9.\-]+(:[0-9]{1,5})?(/[a-zA-Z0-9./\-_]*)?$', v):
        return ''
    return v[:255]


def _safe_path(base_dir: str, rel_path: str) -> str | None:
    """Resuelve una ruta y verifica que esté dentro de base_dir."""
    full = os.path.realpath(os.path.join(base_dir, rel_path.lstrip('/')))
    return full if full.startswith(os.path.realpath(base_dir) + os.sep) else None


def _set_web_base_url(db_name: str, url: str) -> None:
    """Fija web.base.url (y la congela) en la BD del deploy → Odoo genera enlaces
    con la URL pública (https://IP:puerto) en vez de localhost:8069."""
    if not url:
        return
    sql = (
        f"UPDATE ir_config_parameter SET value='{url}' WHERE key='web.base.url'; "
        f"INSERT INTO ir_config_parameter(key,value) SELECT 'web.base.url.freeze','True' "
        f"WHERE NOT EXISTS (SELECT 1 FROM ir_config_parameter WHERE key='web.base.url.freeze');"
    )
    run(f'docker exec {SHARED_PG_NAME} psql -U {SHARED_PG_ADMIN} -d {db_name} -c "{sql}"')


def _configure_local_mail_server(models, uid, db_name: str, domain: str):
    """Apunta el correo saliente de Odoo al Postfix local del VPS (host.docker.internal,
    ver _ensure_host_postfix). Best-effort: si esto falla, Odoo sigue funcionando
    normalmente, el cliente solo no tiene correo saliente automático."""
    try:
        vals = {
            'name':            'Nuqleo (correo directo del servidor)',
            'smtp_host':       'host.docker.internal',
            'smtp_port':       25,
            'smtp_encryption': 'none',
            'sequence':        1,
        }
        existing = models.execute_kw(db_name, uid, 'admin', 'ir.mail_server', 'search',
                                      [[['smtp_host', '=', 'host.docker.internal']]])
        if existing:
            models.execute_kw(db_name, uid, 'admin', 'ir.mail_server', 'write', [existing, vals])
        else:
            models.execute_kw(db_name, uid, 'admin', 'ir.mail_server', 'create', [vals])
        if domain:
            models.execute_kw(db_name, uid, 'admin', 'ir.config_parameter', 'set_param',
                               ['mail.catchall.domain', domain])
        log(f'[mail] {db_name}: servidor de correo local configurado (dominio={domain or "n/a"})')
    except Exception as e:
        log(f'[mail] {db_name}: no se pudo configurar el servidor de correo local: {e}')


def _retry_on_serialization_failure(fn, tries: int = 4, base_delay: float = 6.0):
    """Reintenta una llamada XML-RPC que puede chocar con
    'psycopg2.errors.SerializationFailure: could not serialize access due to
    concurrent update' — transitorio y esperado bajo carga (Odoo corre con
    --workers=2, hay crons y requests de otros workers tocando las mismas
    tablas mientras button_immediate_install recarga el registro entero).
    Confirmado en vivo: Odoo YA reintenta internamente unas pocas veces y aun
    así puede agotarlas; sin este reintento externo el módulo/idioma quedaba
    sin instalar en silencio y el fallback (contenedor one-off contra la
    misma BD que el contenedor principal, ya corriendo) tampoco es confiable."""
    last_err = None
    for attempt in range(1, tries + 1):
        try:
            return fn()
        except Exception as e:
            last_err = e
            if 'serializ' not in str(e).lower() and 'concurrent update' not in str(e).lower():
                raise
            log(f'[rpc] intento {attempt}/{tries} chocó con conflicto de concurrencia en Postgres, reintentando...')
            time.sleep(base_delay * attempt)
    raise last_err


def _install_modules_rpc(container: str, db_name: str, mods_list: list, port: int, version: str, lang: str = 'es_CO', domain: str = '') -> bool:
    """Instala módulos e idioma via XML-RPC mientras Odoo está corriendo.
    Espera hasta que Odoo responda, instala módulos, activa idioma y Odoo se reinicia solo."""
    import xmlrpc.client
    url = f'http://127.0.0.1:{port}'

    # Esperar que Odoo esté listo — espera inicial de 20s (Odoo nunca responde antes),
    # luego polling cada 3s hasta 5 min. Sin el restart previo Odoo suele estar listo
    # en 40-80s desde el compose up.
    _set_stage(container, 'Odoo iniciando — esperando disponibilidad...')
    time.sleep(20)
    ready = False
    for _ in range(100):
        r = run(f'curl -sf --max-time 3 {url}/web/health 2>/dev/null', timeout=6)
        if r['ok']:
            ready = True
            break
        r2 = run(f'curl -sf --max-time 3 -o /dev/null -w "%{{http_code}}" {url}/web/login 2>/dev/null', timeout=6)
        if r2['ok'] and r2['stdout'].strip() in ('200', '303'):
            ready = True
            break
        time.sleep(3)

    if not ready:
        log(f'[rpc] {container}: Odoo no respondió en 4min, módulos pendientes')
        _set_stage(container, 'Odoo listo (módulos: instalar manualmente)')
        return False

    _set_stage(container, f'Instalando módulos e idioma {lang}...')
    try:
        common = xmlrpc.client.ServerProxy(f'{url}/xmlrpc/2/common', allow_none=True)
        uid = common.authenticate(db_name, 'admin', 'admin', {})
        if not uid:
            raise RuntimeError('auth falló con admin/admin')

        models = xmlrpc.client.ServerProxy(f'{url}/xmlrpc/2/object', allow_none=True)

        # 0. Correo saliente vía Postfix local del VPS (best-effort, no aborta el deploy).
        _configure_local_mail_server(models, uid, db_name, domain)

        # 1. Instalar módulos seleccionados (solo los que faltan)
        if mods_list:
            pending = models.execute_kw(
                db_name, uid, 'admin',
                'ir.module.module', 'search',
                [[['name', 'in', mods_list], ['state', 'not in', ['installed', 'to install', 'to upgrade']]]]
            )
            if pending:
                log(f'[rpc] {container}: instalando {len(pending)} módulos via XML-RPC')
                _retry_on_serialization_failure(lambda: models.execute_kw(
                    db_name, uid, 'admin',
                    'ir.module.module', 'button_immediate_install',
                    [pending]
                ))
                # button_immediate_install reinicia los workers de Odoo internamente.
                # Hay que esperar a que Odoo vuelva antes de continuar.
                log(f'[rpc] {container}: esperando que Odoo vuelva tras reinicio de workers...')
                time.sleep(8)
                for _ in range(30):
                    try:
                        uid = common.authenticate(db_name, 'admin', 'admin', {})
                        if uid:
                            break
                    except Exception:
                        pass
                    time.sleep(3)

        # 2. Activar idioma (si no es en_US que viene por defecto).
        #    Se hace DESPUÉS del reinicio post-módulos para que la conexión sea estable.
        if lang and lang != 'en_US':
            try:
                # load_lang activa el idioma e importa las traducciones
                try:
                    _retry_on_serialization_failure(lambda: models.execute_kw(
                        db_name, uid, 'admin', 'res.lang', 'load_lang', [lang]))
                except Exception:
                    # Fallback: wizard base.language.install. En Odoo 18 el campo
                    # es 'lang_ids' (many2many de res.lang), NO 'lang' — con 'lang'
                    # tiraba "Invalid field 'lang' on model 'base.language.install'"
                    # y el deploy se quedaba en inglés en silencio. El registro de
                    # res.lang para el idioma existe pero inactivo por defecto, así
                    # que hay que buscarlo con active_test=False.
                    lang_recs = models.execute_kw(
                        db_name, uid, 'admin', 'res.lang', 'search', [[['code', '=', lang]]],
                        {'context': {'active_test': False}}
                    )
                    if not lang_recs:
                        raise RuntimeError(f"res.lang sin registro para código '{lang}'")
                    wiz = models.execute_kw(db_name, uid, 'admin', 'base.language.install', 'create',
                                            [{'lang_ids': [(6, 0, lang_recs)], 'overwrite': False}])
                    _retry_on_serialization_failure(lambda: models.execute_kw(
                        db_name, uid, 'admin', 'base.language.install', 'lang_install', [[wiz]]))

                # Idioma del usuario admin
                admin_ids = models.execute_kw(db_name, uid, 'admin', 'res.users', 'search',
                                              [[['login', '=', 'admin']]])
                if admin_ids:
                    models.execute_kw(db_name, uid, 'admin', 'res.users', 'write',
                                      [admin_ids, {'lang': lang}])

                # Idioma por defecto de la compañía
                company_ids = models.execute_kw(db_name, uid, 'admin', 'res.company', 'search', [[]])
                if company_ids:
                    try:
                        models.execute_kw(db_name, uid, 'admin', 'res.company', 'write',
                                          [company_ids[:1], {'default_lang': lang}])
                    except Exception:
                        pass  # default_lang no existe en todas las versiones

                log(f'[rpc] {container}: idioma {lang} activado OK')
            except Exception as le:
                log(f'[rpc] {container}: idioma {lang} FALLÓ: {le}')

        _set_stage(container, 'Listo ✓')
        log(f'[rpc] {container}: módulos e idioma OK via XML-RPC')
        return True

    except Exception as e:
        log(f'[rpc] {container}: XML-RPC falló ({e}), usando one-off como fallback')
        # Fallback: one-off container (método original, más lento pero más robusto)
        addons_dir = os.path.join(ODOO_DIR, container, 'addons')
        mods_csv = ','.join(mods_list)
        lang_flag = f'--load-language {lang}' if lang else ''
        inst = run(
            f'docker run --rm --network nuqleo-net '
            f'-v {addons_dir}:/mnt/extra-addons '
            f'-e HOST={SHARED_PG_NAME} -e USER={SHARED_PG_USER} -e PASSWORD={SHARED_PG_PASS} '
            f'odoo:{version} -- --database {db_name} '
            f'{"--init " + mods_csv if mods_csv else ""} {lang_flag} --stop-after-init --no-http',
            timeout=900
        )
        ok = inst['ok'] or 'stop' in (inst['stdout'] + inst['stderr']).lower()
        _set_stage(container, 'Listo ✓' if ok else f'Aviso: módulos no instalados ({mods_csv})')
        log(f'[rpc-fallback] {container}: one-off ok={ok}')
        return ok


# ── Subida de módulo a un deployment YA existente: snapshot + instalar + revertir
#    si algo sale mal. Antes esto solo copiaba el ZIP y reiniciaba el contenedor,
#    dejando la activación del módulo 100% manual (ir a Apps en Odoo) y sin ninguna
#    protección — si el módulo tenía un bug, el cliente se quedaba con el Odoo roto
#    sin aviso claro del error ni forma de volver atrás. ──

def _get_odoo_port(container: str) -> int:
    """Puerto HOST publicado del contenedor (para hablarle por XML-RPC/curl local)."""
    r = run(['docker', 'inspect', '--format',
             '{{range $p, $c := .NetworkSettings.Ports}}{{range $c}}{{.HostPort}} {{end}}{{end}}',
             container])
    if r['ok']:
        m = re.search(r'(\d+)', r['stdout'])
        if m:
            return int(m.group(1))
    return 0

def _derive_db_name(container: str) -> str:
    if container.startswith('odoo_'):
        return 'odb_' + container[len('odoo_'):]
    return container

def _pg_dump_db(db_name: str, out_path: str) -> bool:
    r = run(f'docker exec {SHARED_PG_NAME} pg_dump -U odoo {db_name} > {out_path}', timeout=180)
    return r['ok'] and os.path.exists(out_path) and os.path.getsize(out_path) > 0

def _pg_restore_db(db_name: str, sql_path: str) -> bool:
    """Recrea la BD desde un dump previo — usado para revertir un módulo que rompió Odoo."""
    if not os.path.exists(sql_path) or os.path.getsize(sql_path) == 0:
        return False
    run(f'docker exec {SHARED_PG_NAME} psql -U postgres -c '
        f'"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=\'{db_name}\'"')
    run(f'docker exec {SHARED_PG_NAME} psql -U postgres -c "DROP DATABASE IF EXISTS {db_name}"')
    r1 = run(f'docker exec {SHARED_PG_NAME} psql -U postgres -c "CREATE DATABASE {db_name} OWNER {SHARED_PG_USER}"')
    if not r1['ok']:
        return False
    r2 = run(f'cat {sql_path} | docker exec -i {SHARED_PG_NAME} psql -U postgres -d {db_name}', timeout=180)
    return r2['ok']

def _install_python_requirements(container: str, addons_dir: str, module_dirs: list) -> tuple:
    """Busca requirements.txt y external_dependencies.python en cada módulo recién
    subido, e instala esas librerías DENTRO del contenedor de Odoo (ahí vive el
    intérprete que Odoo usa de verdad, no el del host). La UI de subida ya prometía
    "se instalarán automáticamente" pero no existía ninguna implementación real."""
    import ast
    pkgs = set()
    for mod in module_dirs:
        mod_dir = os.path.join(addons_dir, mod)
        req_file = os.path.join(mod_dir, 'requirements.txt')
        if os.path.isfile(req_file):
            try:
                with open(req_file) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            pkgs.add(line)
            except Exception:
                pass
        manifest_file = os.path.join(mod_dir, '__manifest__.py')
        if os.path.isfile(manifest_file):
            try:
                with open(manifest_file) as f:
                    manifest = ast.literal_eval(f.read())
                pkgs.update(manifest.get('external_dependencies', {}).get('python', []))
            except Exception:
                pass
    if not pkgs:
        return True, ''
    safe_pkgs = [re.sub(r'[^a-zA-Z0-9_\-.=<>]', '', p) for p in pkgs]
    safe_pkgs = [p for p in safe_pkgs if p]
    if not safe_pkgs:
        return True, ''
    log(f'[module] {container}: instalando librerías Python: {safe_pkgs}')
    r = run(['docker', 'exec', container, 'pip3', 'install', '--no-cache-dir',
             '--break-system-packages'] + safe_pkgs, timeout=180)
    if not r['ok']:
        # Imágenes con pip más viejo no reconocen --break-system-packages
        r = run(['docker', 'exec', container, 'pip3', 'install', '--no-cache-dir'] + safe_pkgs, timeout=180)
    return r['ok'], ('' if r['ok'] else r['stderr'][:500])

def _rollback_module_snapshot(container: str, db_name: str, snap_sql: str, snap_addons: str, addons_dir: str):
    log(f'[module] {container}: revirtiendo al snapshot previo (BD + addons)')
    if os.path.isdir(snap_addons):
        run(f'rm -rf {addons_dir}')
        run(f'cp -a {snap_addons} {addons_dir}')
        run(f'chown -R 100:101 {addons_dir}')
    _pg_restore_db(db_name, snap_sql)
    run(['docker', 'restart', container])

def _install_or_upgrade_module_safe(container: str, db_name: str, port: int, mods: list,
                                     snap_sql: str, snap_addons: str, addons_dir: str) -> tuple:
    """Espera a que Odoo vuelva tras el restart, instala/actualiza el módulo vía
    XML-RPC, y si algo falla (Odoo no vuelve, o la instalación tira error) revierte
    automáticamente al snapshot tomado antes de tocar nada. Devuelve (ok, mensaje, revirtió)."""
    import xmlrpc.client
    if not port:
        _rollback_module_snapshot(container, db_name, snap_sql, snap_addons, addons_dir)
        return False, 'No se pudo determinar el puerto de Odoo. Se revirtió automáticamente.', True

    url = f'http://127.0.0.1:{port}'
    time.sleep(15)
    ready = False
    for _ in range(60):
        r2 = run(f'curl -sf --max-time 3 -o /dev/null -w "%{{http_code}}" {url}/web/login 2>/dev/null', timeout=6)
        if r2['ok'] and r2['stdout'].strip() in ('200', '303'):
            ready = True
            break
        time.sleep(3)

    if not ready:
        _rollback_module_snapshot(container, db_name, snap_sql, snap_addons, addons_dir)
        return False, ('Odoo no volvió a responder después de copiar el módulo (probable error '
                        'de arranque en el código). Se revirtió automáticamente al estado anterior.'), True

    try:
        common = xmlrpc.client.ServerProxy(f'{url}/xmlrpc/2/common', allow_none=True)
        uid = common.authenticate(db_name, 'admin', 'admin', {})
        if not uid:
            raise RuntimeError('auth falló con admin/admin')
        models = xmlrpc.client.ServerProxy(f'{url}/xmlrpc/2/object', allow_none=True)

        # Refrescar el listado de apps para que Odoo vea la carpeta nueva/actualizada
        models.execute_kw(db_name, uid, 'admin', 'ir.module.module', 'update_list', [])

        found = models.execute_kw(db_name, uid, 'admin', 'ir.module.module', 'search',
                                   [[['name', 'in', mods]]])
        if not found:
            _rollback_module_snapshot(container, db_name, snap_sql, snap_addons, addons_dir)
            return False, (f"No se encontró ningún módulo Odoo válido en el ZIP (falta "
                            f"__manifest__.py). Carpetas subidas: {', '.join(mods)}. Se revirtió."), True

        to_install = models.execute_kw(db_name, uid, 'admin', 'ir.module.module', 'search',
                                        [[['id', 'in', found], ['state', 'not in', ['installed', 'to upgrade']]]])
        to_upgrade = models.execute_kw(db_name, uid, 'admin', 'ir.module.module', 'search',
                                        [[['id', 'in', found], ['state', '=', 'installed']]])

        if to_install:
            models.execute_kw(db_name, uid, 'admin', 'ir.module.module', 'button_immediate_install', [to_install])
        if to_upgrade:
            models.execute_kw(db_name, uid, 'admin', 'ir.module.module', 'button_immediate_upgrade', [to_upgrade])

        return True, f"Módulo(s) instalado(s)/actualizado(s) correctamente: {', '.join(mods)}.", False

    except Exception as e:
        err = str(e).strip()
        short_err = err.splitlines()[-1] if err else str(e)
        _rollback_module_snapshot(container, db_name, snap_sql, snap_addons, addons_dir)
        return False, (f"El módulo falló al instalar/actualizar: {short_err} — Se revirtió "
                        f"automáticamente al estado anterior (base de datos y archivos)."), True


# ── Snapshots diarios automáticos (BD + addons + filestore), retención de
#    SNAPSHOT_RETENTION_DAYS días, restaurables a cualquier día disponible desde
#    /plataforma. Corren solos vía _snapshot_scheduler_loop (hilo daemon iniciado
#    en el arranque del agente); no dependen de que el cliente pulse nada. ──
def _deployed_containers() -> list:
    """Contenedores odoo_* presentes en el VPS (running o parados sin purgar)."""
    r = run(['docker', 'ps', '-a', '--format', '{{.Names}}'])
    if not r['ok']:
        return []
    return [n for n in r['stdout'].splitlines() if n.startswith('odoo_')]

def _create_daily_snapshot(container: str) -> bool:
    db_name    = _derive_db_name(container)
    deploy_dir = os.path.join(ODOO_DIR, container)
    addons_dir = os.path.join(deploy_dir, 'addons')
    data_dir   = os.path.join(deploy_dir, 'odoo-data')
    if not os.path.isdir(deploy_dir):
        return False

    import datetime
    date_str = datetime.datetime.utcnow().strftime('%Y-%m-%d')
    snap_dir = os.path.join(SNAPSHOT_ROOT, container, date_str)
    run(f'rm -rf {snap_dir}')
    os.makedirs(snap_dir, exist_ok=True)

    ok_db = _pg_dump_db(db_name, os.path.join(snap_dir, 'db.sql'))
    if os.path.isdir(addons_dir):
        run(f'tar --exclude=__pycache__ -czf {os.path.join(snap_dir, "addons.tar.gz")} -C {deploy_dir} addons',
            timeout=300)
    if os.path.isdir(data_dir):
        run(f'tar -czf {os.path.join(snap_dir, "odoo-data.tar.gz")} -C {deploy_dir} odoo-data', timeout=300)

    if not ok_db:
        log(f'[snapshot] {container}: pg_dump falló para el snapshot de {date_str}')
    else:
        log(f'[snapshot] {container}: snapshot de {date_str} creado')
    return ok_db

def _prune_old_snapshots(container: str):
    import datetime
    root = os.path.join(SNAPSHOT_ROOT, container)
    if not os.path.isdir(root):
        return
    cutoff = datetime.datetime.utcnow().date() - datetime.timedelta(days=SNAPSHOT_RETENTION_DAYS)
    for name in os.listdir(root):
        try:
            d = datetime.datetime.strptime(name, '%Y-%m-%d').date()
        except ValueError:
            continue
        if d < cutoff:
            run(f'rm -rf {os.path.join(root, name)}')

def _run_daily_snapshots():
    containers = _deployed_containers()
    log(f'[snapshot] Ciclo diario: {len(containers)} instancia(s)')
    for c in containers:
        try:
            _create_daily_snapshot(c)
            _prune_old_snapshots(c)
        except Exception as e:
            log(f'[snapshot] {c}: error en snapshot diario: {e}')

def _snapshot_scheduler_loop():
    """Corre en un hilo daemon: espera hasta las 03:00 UTC de cada día y toma
    snapshot de todas las instancias. Si el agente estuvo caído a esa hora, el
    próximo ciclo simplemente cae al día siguiente (no hay backlog que recuperar,
    solo importa mantener los últimos SNAPSHOT_RETENTION_DAYS días)."""
    import datetime
    while True:
        now = datetime.datetime.utcnow()
        target = now.replace(hour=3, minute=0, second=0, microsecond=0)
        if target <= now:
            target += datetime.timedelta(days=1)
        time.sleep((target - now).total_seconds())
        try:
            _run_daily_snapshots()
        except Exception as e:
            log(f'[snapshot] error en ciclo diario: {e}')


# ── Dominio + SSL (reutilizable: lo usan el endpoint /configure-domain y el deploy
#    automático de subdominios). Emite cert por webroot y deja nginx proxyando con
#    HTTP/2 (clave para que el render no se rompa con la pérdida de paquetes: el
#    navegador usa una sola conexión multiplexada en vez de 6-8 que se caen). ──
def configure_domain_ssl(domain: str, port: int) -> dict:
    domain = _sanitize_domain(domain)
    if not domain or not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.\-]{1,252}$', domain):
        return {'ok': False, 'error': 'Dominio inválido'}
    if not (PORT_MIN <= port <= PORT_MAX):
        return {'ok': False, 'error': 'Puerto inválido'}

    # 1) Asegurar nginx + certbot (idempotente / auto-reparable).
    run('DEBIAN_FRONTEND=noninteractive apt-get install -y nginx certbot >/dev/null 2>&1 || true')
    run('systemctl enable --now nginx >/dev/null 2>&1 || true')

    webroot = '/var/www/certbot'
    os.makedirs(webroot, exist_ok=True)
    nginx_avail = f'/etc/nginx/sites-available/{domain}'

    # 2) Vhost HTTP temporal: sirve el challenge ACME y ya proxya al contenedor.
    http_conf = f"""server {{
    listen 80;
    server_name {domain};
    location /.well-known/acme-challenge/ {{ root {webroot}; }}
    location / {{
        proxy_pass http://127.0.0.1:{port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 600s;
        client_max_body_size 100m;
    }}
}}
"""
    with open(nginx_avail, 'w') as f:
        f.write(http_conf)
    run(f'ln -sf {nginx_avail} /etc/nginx/sites-enabled/{domain}')
    run('rm -f /etc/nginx/sites-enabled/default')
    test = run(['nginx', '-t'])
    if not test['ok']:
        return {'ok': False, 'error': 'Error Nginx (http)', 'detail': test['stderr'][:300]}
    run(['systemctl', 'reload', 'nginx'])

    # 3) Emitir certificado por webroot (no edita nginx; necesita que el DNS ya
    #    apunte a este servidor — para subdominios *.nuqleo.app lo cubre el wildcard).
    r = run(['certbot', 'certonly', '--webroot', '-w', webroot,
             '--non-interactive', '--agree-tos', '--keep-until-expiring',
             '-m', f'admin@{domain}', '-d', domain], timeout=180)
    log(f"[ssl] certbot {domain}: ok={r['ok']} {r['stderr'][:200]}")
    cert_path = f'/etc/letsencrypt/live/{domain}/fullchain.pem'

    # Si certbot falla, usar autofirmado como fallback (cliente puede acceder YA).
    # El cron intentará Let's Encrypt cada 1 hora hasta lograrlo.
    if not os.path.exists(cert_path):
        log(f"[ssl] {domain}: certbot falló, fallback a autofirmado (retry automático cada 1h)")
        cert_path, key_path = _ensure_selfsigned_cert_for_domain(domain)
        cert_status = 'pending_le'  # Indica que está en fallback, pending Let's Encrypt
    else:
        key_path = f'/etc/letsencrypt/live/{domain}/privkey.pem'
        cert_status = 'active'

    # 4) Vhost final: 80 redirige a 443; 443 proxya al contenedor con SSL + HTTP/2.
    full_conf = f"""server {{
    listen 80;
    server_name {domain};
    location /.well-known/acme-challenge/ {{ root {webroot}; }}
    location / {{ return 301 https://$host$request_uri; }}
}}
server {{
    listen 443 ssl http2;
    server_name {domain};
    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    # CSP mínima: solo restringe el framing sin romper los scripts inline de Odoo.
    add_header Content-Security-Policy "frame-ancestors 'self'" always;
    client_max_body_size 100m;
    location / {{
        proxy_pass http://127.0.0.1:{port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 600s;
    }}
}}
"""
    with open(nginx_avail, 'w') as f:
        f.write(full_conf)
    test2 = run(['nginx', '-t'])
    if not test2['ok']:
        return {'ok': False, 'error': 'Error Nginx (ssl)', 'detail': test2['stderr'][:300]}
    run(['systemctl', 'reload', 'nginx'])
    msg = f"SSL {cert_status} para {domain}"
    if cert_status == 'pending_le':
        msg += " (fallback autofirmado; retry automático cada 1h → Let's Encrypt)"
    return {'ok': True, 'domain': domain, 'ssl': True, 'cert_status': cert_status, 'message': msg}


# ── Autofirmado con CN/SAN del dominio real (fallback de configure_domain_ssl) ──
# El autofirmado genérico (CN=nuqleo-odoo, ver más abajo) sirve para el acceso por
# IP:puerto, pero si se reutiliza para un dominio real (ej: app.cliente.com) el
# navegador lo rechaza con ERR_CERT_COMMON_NAME_INVALID en vez del aviso normal de
# "no seguro" — el nombre del cert no coincide con el host pedido. Por eso, cuando
# Let's Encrypt falla para un dominio, generamos uno propio con ese dominio en el
# CN y el SAN (se cachea por dominio, no se regenera en cada intento).
def _ensure_selfsigned_cert_for_domain(domain: str) -> tuple[str, str]:
    safe = _sanitize_domain(domain)
    cert_dir = '/etc/nginx/ssl/domains'
    os.makedirs(cert_dir, exist_ok=True)
    cert_path = f'{cert_dir}/{safe}.crt'
    key_path  = f'{cert_dir}/{safe}.key'
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path
    run(f"openssl req -x509 -nodes -newkey rsa:2048 "
        f"-keyout {key_path} -out {cert_path} -days 3650 "
        f"-subj '/CN={safe}' -addext 'subjectAltName=DNS:{safe}'")
    return cert_path, key_path

# ── HTTPS autofirmado por contenedor (sin Let's Encrypt) ──────────
# Para VPS con red mala donde la validación de Let's Encrypt no pasa: cada Odoo
# se expone en https://IP:{https_port} con un cert autofirmado + HTTP/2. El navegador
# muestra "no seguro" pero el render sale bien (una sola conexión multiplexada).
SELF_CERT = '/etc/nginx/ssl/self.crt'
SELF_KEY  = '/etc/nginx/ssl/self.key'

def _ensure_selfsigned_cert():
    if os.path.exists(SELF_CERT) and os.path.exists(SELF_KEY):
        return
    os.makedirs('/etc/nginx/ssl', exist_ok=True)
    run(f"openssl req -x509 -nodes -newkey rsa:2048 "
        f"-keyout {SELF_KEY} -out {SELF_CERT} -days 3650 -subj '/CN=nuqleo-odoo'")

def configure_selfsigned_https(container: str, backend_port: int, https_port: int) -> dict:
    if not (PORT_MIN <= https_port <= PORT_MAX):
        return {'ok': False, 'error': 'https_port inválido'}
    run('DEBIAN_FRONTEND=noninteractive apt-get install -y nginx openssl >/dev/null 2>&1 || true')
    run('systemctl enable --now nginx >/dev/null 2>&1 || true')
    _ensure_selfsigned_cert()
    # Abrir el puerto en ufw si está activo (no-op si está inactivo).
    run(f"command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active' && ufw allow {https_port}/tcp || true")

    conf = f"""server {{
    listen {https_port} ssl http2;
    server_name _;
    ssl_certificate {SELF_CERT};
    ssl_certificate_key {SELF_KEY};
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "frame-ancestors 'self'" always;
    client_max_body_size 100m;
    location / {{
        proxy_pass http://127.0.0.1:{backend_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 600s;
    }}
}}
"""
    path = f'/etc/nginx/sites-available/selfssl_{container}'
    with open(path, 'w') as f:
        f.write(conf)
    run(f'ln -sf {path} /etc/nginx/sites-enabled/selfssl_{container}')
    test = run(['nginx', '-t'])
    if not test['ok']:
        return {'ok': False, 'error': 'Error Nginx', 'detail': test['stderr'][:300]}
    run(['systemctl', 'reload', 'nginx'])
    return {'ok': True, 'https_port': https_port}


# ── Handler ──────────────────────────────────────────────────────
class NuqleoHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        log(f"HTTP {self.address_string()} {fmt % args}")

    # ── Autenticación: API key + firma HMAC + timestamp ──────────
    def _auth(self, raw_body: bytes = b'') -> bool:
        ip = self.client_address[0]

        if _is_rate_limited(ip):
            log(f"[auth] IP bloqueada por rate limit: {ip}")
            return False

        # Rechazar si la API key no está configurada en el servidor
        if not API_KEY:
            log(f"[auth] CRÍTICO: NUQLEO_API_KEY no definida. Rechazando todo.")
            return False

        key = self.headers.get('X-Nuqleo-Key', '')
        if not hmac.compare_digest(key, API_KEY):
            _record_fail(ip)
            log(f"[auth] Clave inválida desde {ip}")
            return False

        # Verificar firma HMAC-SHA256 del cuerpo + timestamp (OBLIGATORIO)
        ts_str  = self.headers.get('X-Nuqleo-Timestamp', '')
        sig_rcv = self.headers.get('X-Nuqleo-Sig', '')

        if not ts_str or not sig_rcv:
            _record_fail(ip)
            log(f"[auth] Falta firma HMAC desde {ip}")
            return False

        try:
            ts = int(ts_str)
            if abs(time.time() - ts) > 120:   # ventana de 2 minutos
                _record_fail(ip)
                log(f"[auth] Timestamp expirado desde {ip}")
                return False
            payload  = f"{ts_str}:".encode() + raw_body
            expected = hmac.new(API_KEY.encode(), payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig_rcv, expected):
                _record_fail(ip)
                log(f"[auth] Firma inválida desde {ip}")
                return False
        except (ValueError, Exception) as e:
            _record_fail(ip)
            log(f"[auth] Error verificando firma: {e}")
            return False

        return True

    MAX_BODY = 50 * 1024 * 1024  # 50 MB — protección contra OOM

    def _read_body(self) -> bytes:
        length = int(self.headers.get('Content-Length', 0))
        if length > self.MAX_BODY:
            raise ValueError(f"Body demasiado grande: {length} bytes (máx {self.MAX_BODY})")
        return self.rfile.read(min(length, self.MAX_BODY)) if length else b''

    def _send(self, code: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: str, download_name: str):
        """Envía un archivo tal cual (no JSON) — usado para que el backup generado
        por /backup pueda descargarse de verdad en vez de quedar solo en el VPS."""
        if not os.path.isfile(path):
            return self._send(404, {'error': 'Archivo no encontrado. Genera un backup primero.'})
        size = os.path.getsize(path)
        self.send_response(200)
        self.send_header('Content-Type', 'application/gzip')
        self.send_header('Content-Length', str(size))
        self.send_header('Content-Disposition', f'attachment; filename="{download_name}"')
        self.end_headers()
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                try:
                    self.wfile.write(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    break

    # ── GET ──────────────────────────────────────────────────────
    def do_GET(self):
        if not self._auth():
            return self._send(401, {'error': 'Unauthorized'})

        if self.path == '/ping':
            docker = run(['docker', '--version'])
            self._send(200, {
                'ok':    True,
                'agent': '2.0',
                'docker': docker['stdout'],
                'host':  os.uname().nodename,
            })

        elif self.path.startswith('/custom-modules'):
            # Lista los módulos custom del repo privado para una versión (selección en panel).
            qs = parse_qs(urlparse(self.path).query)
            version = re.sub(r'[^0-9]', '', (qs.get('version', ['18'])[0]))[:2] or '18'
            # Responder YA desde la copia local (rápido). Un clone síncrono aquí
            # puede tardar más que el timeout del plugin (20s) por el packet loss
            # y dejaría el panel sin módulos. Refrescamos el repo en segundo plano
            # (startup + este hilo mantienen la copia al día para la próxima vez).
            if MODULES_REPO:
                threading.Thread(target=_sync_custom_modules, daemon=True).start()
            self._send(200, {'modules': _list_custom_modules(version)})

        elif self.path == '/deployments':
            r = run(['docker', 'ps', '--format', '{{.Names}}\t{{.Status}}\t{{.Ports}}'])
            containers = []
            for line in r['stdout'].splitlines():
                parts = line.split('\t')
                if len(parts) >= 2:
                    containers.append({'name': parts[0], 'status': parts[1],
                                       'ports': parts[2] if len(parts) > 2 else ''})
            self._send(200, {'ok': True, 'containers': containers})

        elif self.path.startswith('/status/'):
            cname = _sanitize_name(self.path[len('/status/'):])
            if not cname:
                return self._send(400, {'error': 'container requerido'})
            # Estado del contenedor
            r = run(['docker', 'inspect', '--format', '{{.State.Status}}{{if .State.Health}}\t{{.State.Health.Status}}{{end}}', cname])
            if not r['ok'] or not r['stdout'].strip():
                return self._send(200, {'ok': True, 'container': cname, 'state': 'missing', 'ready': False})
            parts = r['stdout'].strip().split('\t')
            state  = parts[0]  # running, exited, restarting, etc.
            health = parts[1] if len(parts) > 1 else ''
            # Verificar si Odoo responde en su puerto (conexión TCP al puerto del HOST)
            port_r = run(['docker', 'inspect', '--format',
                          '{{range $p, $c := .NetworkSettings.Ports}}{{range $c}}{{.HostPort}} {{end}}{{end}}',
                          cname])
            odoo_port = None
            if port_r['ok']:
                import re as _re
                m = _re.search(r'(\d+)', port_r['stdout'])
                if m:
                    odoo_port = int(m.group(1))
            web_ready = False
            if state == 'running' and odoo_port:
                import socket as _sock
                try:
                    s = _sock.create_connection(('127.0.0.1', odoo_port), timeout=2)
                    s.close()
                    web_ready = True
                except Exception:
                    pass
            self._send(200, {'ok': True, 'container': cname, 'state': state,
                             'health': health, 'port': odoo_port, 'ready': web_ready,
                             'stage': _deploy_stages.get(cname, '')})

        elif self.path.startswith('/backup-file'):
            # Descarga el .tar.gz que /backup ya dejó generado en el VPS. Antes de
            # esto, /backup solo devolvía la ruta en el propio VPS — el cliente
            # nunca recibía el archivo (el botón "Backup ahora" no descargaba nada).
            qs = parse_qs(urlparse(self.path).query)
            cname = _sanitize_name(qs.get('container', [''])[0])
            if not cname:
                return self._send(400, {'error': 'container requerido'})
            tar_path = os.path.join('/opt/nuqleo-backups', cname, f'{cname}.tar.gz')
            self._send_file(tar_path, f'{cname}-backup.tar.gz')

        elif self.path.startswith('/snapshots'):
            # Lista los snapshots diarios disponibles (últimos SNAPSHOT_RETENTION_DAYS
            # días) para que el cliente elija a qué día restaurar desde /plataforma.
            qs = parse_qs(urlparse(self.path).query)
            cname = _sanitize_name(qs.get('container', [''])[0])
            if not cname:
                return self._send(400, {'error': 'container requerido'})
            root = os.path.join(SNAPSHOT_ROOT, cname)
            items = []
            if os.path.isdir(root):
                for d in sorted(os.listdir(root), reverse=True):
                    if not re.match(r'^\d{4}-\d{2}-\d{2}$', d):
                        continue
                    size = 0
                    for fn in ('db.sql', 'addons.tar.gz', 'odoo-data.tar.gz'):
                        fp = os.path.join(root, d, fn)
                        if os.path.exists(fp):
                            size += os.path.getsize(fp)
                    items.append({'date': d, 'size_mb': round(size / (1024 * 1024), 1)})
            self._send(200, {'ok': True, 'snapshots': items, 'retention_days': SNAPSHOT_RETENTION_DAYS})

        else:
            self._send(404, {'error': 'Not found'})

    # ── POST ─────────────────────────────────────────────────────
    def do_POST(self):
        try:
            raw_body = self._read_body()
        except ValueError as e:
            log(f"[post] {e}")
            return self._send(413, {'error': str(e)})
        if not self._auth(raw_body):
            return self._send(401, {'error': 'Unauthorized'})


        try:
            body = json.loads(raw_body) if raw_body else {}
        except json.JSONDecodeError:
            return self._send(400, {'error': 'JSON inválido'})

        path = self.path.split('?')[0]

        if   path == '/deploy':           self._handle_deploy(body)
        elif path == '/module/upload':    self._handle_module_upload(body)
        elif path == '/configure-domain': self._handle_configure_domain(body)
        elif path == '/stop':             self._handle_stop(body)
        elif path == '/restart':          self._handle_restart(body)
        elif path == '/start':            self._handle_start(body)
        elif path == '/setup-postgres':   self._handle_setup_postgres(body)
        elif path == '/backup':           self._handle_backup(body)
        elif path == '/snapshot-restore': self._handle_snapshot_restore(body)
        else:                             self._send(404, {'error': 'Endpoint no encontrado'})

    # ── Setup Postgres compartido ─────────────────────────────────
    def _handle_setup_postgres(self, body: dict):
        versions = body.get('versions', ['17', '18'])
        self._send(200, {'ok': True, 'message': 'Pre-calentando postgres en background...'})
        def _do_setup():
            run('docker network create nuqleo-net 2>/dev/null || true')
            if not _ensure_shared_postgres():
                log('[setup] ERROR: no se pudo iniciar postgres compartido')
                return
            for v in versions:
                if str(v) in ALLOWED_ODOO_VERSIONS:
                    log(f'[setup] Pre-calentando template odoo{v}...')
                    _ensure_template_db(str(v))
            _ensure_host_postfix()
            log('[setup] Setup postgres completado.')
        threading.Thread(target=_do_setup, daemon=True).start()

    # ── Stop / Restart ───────────────────────────────────────────
    def _handle_stop(self, body: dict):
        name = _sanitize_name(body.get('container_name', ''))
        if not name:
            return self._send(400, {'error': 'container_name requerido'})
        run(['docker', 'stop', name])
        run(['docker', 'rm', '-f', name])  # forzar por si 'stop' ya había fallado
        _deploy_stages.pop(name, None)

        # purge=True → borrado DEFINITIVO del cliente (delete). Sin purge es un
        # "pausar" reversible: se quita el contenedor pero se conservan la BD y la
        # carpeta para poder re-desplegar. NUNCA borrar la BD en un pause.
        if not body.get('purge'):
            return self._send(200, {'ok': True, 'removed': name, 'purged': False})

        # 1) Base de datos del cliente. Si WP no la manda, la derivamos del nombre
        #    del contenedor: odoo_{u}_{sfx} → odb_{u}_{sfx}.
        db_name = _sanitize_name(body.get('db_name', ''))
        if not db_name and name.startswith('odoo_'):
            db_name = 'odb_' + name[len('odoo_'):]
        db_dropped = False
        if db_name.startswith('odb_'):
            _pg_exec(f'DROP DATABASE IF EXISTS {db_name}')
            db_dropped = True

        # 2) Carpeta de deploy (compose, addons, filestore) — con guard anti-traversal.
        deploy_dir = os.path.join(ODOO_DIR, name)
        if os.path.realpath(deploy_dir).startswith(os.path.realpath(ODOO_DIR) + os.sep):
            run(f'rm -rf {deploy_dir}')

        # 3) Vhosts de nginx del contenedor: el HTTPS autofirmado (selfssl_*) y, si
        #    WP lo manda, el del subdominio Let's Encrypt.
        run(f'rm -f /etc/nginx/sites-enabled/selfssl_{name} /etc/nginx/sites-available/selfssl_{name}')
        subdomain = _sanitize_domain(body.get('subdomain', ''))
        if subdomain:
            run(f'rm -f /etc/nginx/sites-enabled/{subdomain} /etc/nginx/sites-available/{subdomain}')
        run('systemctl reload nginx 2>/dev/null || true')

        self._send(200, {'ok': True, 'removed': name, 'purged': True, 'db_name': db_name, 'db_dropped': db_dropped})

    def _handle_restart(self, body: dict):
        name = _sanitize_name(body.get('container_name', ''))
        if not name:
            return self._send(400, {'error': 'container_name requerido'})
        r = run(['docker', 'restart', name])
        self._send(200 if r['ok'] else 500, r)

    def _handle_start(self, body: dict):
        name = _sanitize_name(body.get('container_name', ''))
        if not name:
            return self._send(400, {'error': 'container_name requerido'})
        deploy_dir = os.path.join(ODOO_DIR, name)
        compose_file = os.path.join(deploy_dir, 'docker-compose.yml')
        if not os.path.exists(compose_file):
            return self._send(404, {'error': f'No se encontró docker-compose.yml para {name}'})
        r = run(f'cd {deploy_dir} && {COMPOSE} up -d', timeout=60)
        self._send(200 if r['ok'] else 500, {'ok': r['ok'], 'stdout': r['stdout'], 'stderr': r['stderr']})

    # ── Backup manual del cliente ────────────────────────────────
    def _handle_backup(self, body: dict):
        name    = _sanitize_name(body.get('container_name', ''))
        db_name = _sanitize_name(body.get('db_name', ''))
        if not name:
            return self._send(400, {'error': 'container_name requerido'})

        # Derivar db_name si no viene (convención: odoo_xxx → odb_xxx)
        if not db_name and name.startswith('odoo_'):
            db_name = 'odb_' + name[len('odoo_'):]

        deploy_dir = os.path.join(ODOO_DIR, name)
        if not os.path.exists(deploy_dir):
            return self._send(404, {'error': f'Directorio del deployment no encontrado: {deploy_dir}'})

        backup_root = '/opt/nuqleo-backups'
        os.makedirs(backup_root, exist_ok=True)

        import datetime
        bak_dir = os.path.join(backup_root, name)
        os.makedirs(bak_dir, exist_ok=True)

        # Nombres fijos: cada ejecución sobreescribe el backup anterior
        sql_file = os.path.join(bak_dir, f'{db_name}.sql')
        tar_path = os.path.join(bak_dir, f'{name}.tar.gz')

        # 1) Dump PostgreSQL — vía docker exec: Postgres corre en un contenedor sin
        #    puerto publicado al host (nuqleo_postgres_shared no tiene -p), así que
        #    un pg_dump directo en el host con -h 127.0.0.1 SIEMPRE fallaba (host ni
        #    siquiera tiene pg_dump instalado) — el backup nunca incluía la BD real,
        #    solo el tar de addons/filestore. `docker exec ... > archivo` sí funciona
        #    porque el redirect corre en el host sobre el stdout del propio exec.
        pg = run(f'docker exec {SHARED_PG_NAME} pg_dump -U odoo {db_name} > {sql_file}', timeout=120)
        if not pg['ok']:
            log(f'[backup] {name}: pg_dump falló: {pg["stderr"][:300]}')
            sql_file = None

        # 2) Tar del directorio de addons/filestore (excluimos __pycache__)
        run(f'tar --exclude=__pycache__ -czf {tar_path} -C {ODOO_DIR} {name}', timeout=300)

        # 3) Tamaño legible
        size_str = ''
        try:
            sz  = os.path.getsize(tar_path)
            size_str = f'{sz // (1024*1024)} MB' if sz >= 1024*1024 else f'{sz // 1024} KB'
        except Exception:
            pass

        ts     = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
        result = {'path': tar_path, 'size': size_str, 'ts': ts}
        if sql_file and os.path.exists(sql_file):
            result['sql_path'] = sql_file

        self._send(200, {'ok': True, **result})

    # ── Restaurar snapshot diario a una fecha específica ─────────
    def _handle_snapshot_restore(self, body: dict):
        name     = _sanitize_name(body.get('container_name', ''))
        date_str = re.sub(r'[^0-9\-]', '', str(body.get('date', '')))[:10]
        if not name or not re.match(r'^\d{4}-\d{2}-\d{2}$', date_str):
            return self._send(400, {'error': 'container_name y date (YYYY-MM-DD) requeridos'})

        snap_dir = os.path.join(SNAPSHOT_ROOT, name, date_str)
        if not os.path.isdir(snap_dir):
            return self._send(404, {'error': f'No hay snapshot de {name} para el {date_str}'})

        db_name    = _derive_db_name(name)
        deploy_dir = os.path.join(ODOO_DIR, name)
        addons_dir = os.path.join(deploy_dir, 'addons')
        data_dir   = os.path.join(deploy_dir, 'odoo-data')
        sql_path   = os.path.join(snap_dir, 'db.sql')
        addons_tar = os.path.join(snap_dir, 'addons.tar.gz')
        data_tar   = os.path.join(snap_dir, 'odoo-data.tar.gz')

        log(f'[snapshot] {name}: restaurando snapshot del {date_str}')
        run(['docker', 'stop', name])

        ok_db = _pg_restore_db(db_name, sql_path) if os.path.exists(sql_path) else False

        if os.path.exists(addons_tar):
            run(f'rm -rf {addons_dir}')
            run(f'tar -xzf {addons_tar} -C {deploy_dir}')
        if os.path.exists(data_tar):
            run(f'rm -rf {data_dir}')
            run(f'tar -xzf {data_tar} -C {deploy_dir}')
        run(f'chown -R 100:101 {deploy_dir}')

        r = run(['docker', 'start', name])
        if ok_db and r['ok']:
            log(f'[snapshot] {name}: restauración del {date_str} completada')
            self._send(200, {'ok': True, 'message': f'Restaurado al snapshot del {date_str}.'})
        else:
            log(f'[snapshot] {name}: restauración del {date_str} con errores (db_ok={ok_db}, start_ok={r["ok"]})')
            self._send(500, {'ok': False, 'error': 'La restauración tuvo errores. Revisa el estado de la instancia.'})

    # ── Helpers para instalar módulos subidos a un deployment existente ──
    # (snapshot + rollback automático si el módulo rompe Odoo; ver _handle_module_chunk)

    # ── Deploy Odoo ──────────────────────────────────────────────
    def _handle_deploy(self, body: dict):
        container = _sanitize_name(body.get('container_name', ''))
        version   = _sanitize_name(body.get('odoo_version', '18'))
        db_name   = _sanitize_name(body.get('db_name', ''))
        db_user   = _sanitize_name(body.get('db_user', 'odoo'))
        db_pass   = body.get('db_pass', '')
        module    = _sanitize_name(body.get('module_name', 'modulo'))
        files     = body.get('files', {})
        port      = int(body.get('odoo_port', 0))
        # Módulos seleccionados por el cliente (CSV de nombres técnicos: sale, website…).
        # Solo letras/números/guion_bajo/comas para evitar inyección en el comando.
        modules   = re.sub(r'[^a-z0-9_,]', '', str(body.get('modules', '')).lower())
        # Subdominio automático opcional (ej: cliente.nuqleo.app) con Let's Encrypt.
        subdomain = _sanitize_domain(body.get('subdomain', ''))
        # Modo de acceso: 'selfsigned' → HTTPS+HTTP2 con cert autofirmado en https_port
        # (render fiable pese a packet loss, sin Let's Encrypt). 'subdomain' usa el de
        # arriba. Vacío → solo http://IP:puerto.
        ssl_mode   = str(body.get('ssl_mode', ''))
        https_port = int(body.get('https_port', 0) or 0)
        # URL pública que verá el cliente (https://IP:https_port). Se usa para fijar
        # web.base.url de Odoo y que no genere enlaces a localhost:8069.
        public_url = _sanitize_url(body.get('public_url', ''))
        # Código locale del idioma a activar en Odoo (ej: es_CO, en_US, pt_BR).
        lang   = re.sub(r'[^a-zA-Z_]', '', str(body.get('lang', 'es_CO')))[:10] or 'es_CO'
        # Módulo de localización fiscal (ej: l10n_co, l10n_mx). Vacío = sin paquete.
        fiscal = re.sub(r'[^a-z0-9_]', '', str(body.get('fiscal', '')).lower())[:30]

        # Validaciones
        if not container or not db_name:
            return self._send(400, {'error': 'container_name y db_name son requeridos'})
        if version not in ALLOWED_ODOO_VERSIONS:
            return self._send(400, {'error': f'Versión Odoo no permitida. Válidas: {", ".join(sorted(ALLOWED_ODOO_VERSIONS))}'})
        if not (PORT_MIN <= port <= PORT_MAX):
            return self._send(400, {'error': f'Puerto fuera de rango ({PORT_MIN}-{PORT_MAX})'})
        if not db_pass or len(db_pass) < 8:
            return self._send(400, {'error': 'db_pass debe tener al menos 8 caracteres'})

        deploy_dir = os.path.join(ODOO_DIR, container)
        addons_dir = os.path.join(deploy_dir, 'addons')
        module_dir = os.path.join(addons_dir, module)
        os.makedirs(module_dir, exist_ok=True)

        # Escribir archivos con protección path-traversal
        for rel_path, content in (files or {}).items():
            safe = _safe_path(module_dir, rel_path)
            if not safe:
                log(f"[deploy] Path traversal bloqueado: {rel_path}")
                continue
            os.makedirs(os.path.dirname(safe), exist_ok=True)
            with open(safe, 'w', encoding='utf-8') as f:
                f.write(content)

        # Compose solo Odoo — postgres compartido, sin container por deployment.
        # Conectar como el rol 'odoo' compartido (dueño de las tablas del template)
        # para evitar errores de permisos al instalar módulos.
        # Acceso:
        #  - selfsigned: el puerto 8069 se publica SOLO en 127.0.0.1 (lo consume nginx
        #    en https_port con HTTP/2). Así el cliente NO puede entrar al http://IP:8069
        #    (que con el packet loss de Contabo se ve roto): siempre va por el HTTPS bueno.
        #    Se activa --proxy-mode para que Odoo respete los headers X-Forwarded-* del proxy.
        #  - ip (sin proxy): se publica en 0.0.0.0 para acceso directo http://IP:puerto.
        # Workers: 2 HTTP + 1 cron (prefork). shm_size 256m requerido para workers.
        # mem_limit 1300m: 5 Odoos × 1.3GB = 6.5GB, deja ~1.5GB para sistema+postgres+WP en un VPS 8GB.
        # limit-time-real 1200 evita que tareas largas (importar XLS, informes pesados) maten workers.
        ODOO_PERF_FLAGS = '--workers=2 --limit-time-cpu=600 --limit-time-real=1200 --limit-memory-hard=1073741824 --limit-memory-soft=805306368'
        if ssl_mode == 'selfsigned' and PORT_MIN <= https_port <= PORT_MAX:
            port_bind = f'127.0.0.1:{port}:8069'
            odoo_cmd  = f'-- --proxy-mode --db-filter=^{db_name}$$ --no-database-list {ODOO_PERF_FLAGS}'
        else:
            port_bind = f'{port}:8069'
            odoo_cmd  = f'-- --db-filter=^{db_name}$$ --no-database-list {ODOO_PERF_FLAGS}'
        compose = f"""version: '3.9'
services:
  {container}:
    image: odoo:{version}
    container_name: {container}
    ports:
      - "{port_bind}"
    environment:
      HOST: {SHARED_PG_NAME}
      USER: {SHARED_PG_USER}
      PASSWORD: {SHARED_PG_PASS}
    # db-filter fija esta instancia a SU base de datos; no-database-list oculta
    # las demás bases del postgres compartido (aislamiento entre clientes).
    command: {odoo_cmd}
    volumes:
      - {deploy_dir}/odoo-data:/var/lib/odoo
      - {addons_dir}:/mnt/extra-addons
    extra_hosts:
      - "host.docker.internal:host-gateway"
    restart: unless-stopped
    shm_size: '256m'
    mem_limit: '1300m'
    memswap_limit: '1300m'
    security_opt:
      - no-new-privileges:true
    networks:
      - nuqleo-net

networks:
  nuqleo-net:
    external: true
"""
        with open(os.path.join(deploy_dir, 'docker-compose.yml'), 'w') as f:
            f.write(compose)

        run('docker network create nuqleo-net 2>/dev/null || true')

        # Responder inmediatamente — el trabajo pesado va en background
        self._send(200, {
            'ok':         True,
            'container':  container,
            'port':       port,
            'access_url': f'http://{os.uname().nodename}:{port}',
            'message':    f'Odoo {version} iniciando en puerto {port}',
        })

        def _do_deploy():
            # 1. Asegurar postgres compartido
            _set_stage(container, 'Verificando postgres compartido...')
            if not _ensure_shared_postgres():
                _set_stage(container, 'ERROR: no se pudo iniciar postgres compartido')
                return
            _ensure_host_postfix()  # correo saliente — best-effort, no bloquea el deploy si falla

            # 2. Verificar imagen Docker — SKIP pull si ya está en caché local.
            #    docker pull tarda 5-10s extra aunque la imagen esté al día porque
            #    contacta el registry. Con inspect lo sabemos en <1s.
            img_ok = run(f'docker image inspect odoo:{version}', timeout=10)['ok']
            if not img_ok:
                _set_stage(container, f'Descargando imagen Odoo {version}...')
                run(f'docker pull odoo:{version}', timeout=300)

            # 3. Crear BD desde template (instantáneo; solo tarda la primera vez que
            #    no existe el template, ~3 min, y nunca más).
            _set_stage(container, 'Preparando base de datos...')
            if not _ensure_template_db(version):
                _set_stage(container, 'ERROR: no se pudo inicializar la plantilla de base de datos')
                return
            if not _create_db_from_template(db_name, version):
                _set_stage(container, 'ERROR: no se pudo crear la base de datos')
                return

            # 4. Preparar directorios.
            odoo_data = os.path.join(deploy_dir, 'odoo-data')
            os.makedirs(odoo_data, exist_ok=True)

            # 5. Copiar módulos custom seleccionados al directorio de addons del deploy.
            mod_list = [m for m in modules.split(',') if m]
            if files:
                mod_list.append(module)
            mod_list = list(dict.fromkeys(mod_list))  # dedupe, conserva orden

            if MODULES_REPO and mod_list:
                src = os.path.join(MODULES_DIR, str(version))
                _have = lambda m: os.path.exists(os.path.join(src, m, '__manifest__.py'))
                if any(not _have(m) for m in mod_list):
                    _sync_custom_modules()
                for m in mod_list:
                    if _have(m):
                        run(f'cp -r {os.path.join(src, m)} {addons_dir}/')
                        log(f'[deploy] {container}: módulo custom {m} copiado a addons')

            # Si el cliente seleccionó Contabilidad, descargar suite completa de
            # contabilidad de odoomates/odooapps (reportes, activos, presupuestos,
            # extractos bancarios, seguimiento cobros, año fiscal).
            if 'account' in mod_list and version in ('17', '18', '19'):
                _set_stage(container, 'Descargando suite de contabilidad completa...')
                om_mods = _fetch_om_accounting(version, addons_dir)
                for m in om_mods:
                    if m not in mod_list:
                        mod_list.append(m)
                log(f'[deploy] {container}: suite contabilidad → {om_mods}')

            # Si el cliente seleccionó Firma Digital: 'sign' es de Enterprise y no
            # existe en la imagen Community — sin esto era un módulo fantasma que
            # el wizard ofrecía pero nunca instalaba nada. sign_oca (OCA) es el
            # equivalente real y libre.
            if 'sign' in mod_list and version in ('17', '18', '19'):
                _set_stage(container, 'Descargando módulo de firma digital (OCA)...')
                mod_list = [m for m in mod_list if m != 'sign']
                sign_mods = _fetch_oca_sign(version, addons_dir)
                for m in sign_mods:
                    if m not in mod_list:
                        mod_list.append(m)
                log(f'[deploy] {container}: firma digital (OCA) → {sign_mods}')

            # Si el cliente seleccionó Nómina: hr_payroll también es de Enterprise
            # desde Odoo 17 — 'payroll' de OCA es el equivalente libre.
            if 'payroll' in mod_list and version in ('16', '17', '18', '19'):
                _set_stage(container, 'Descargando módulo de nómina (OCA)...')
                payroll_mods = _fetch_oca_payroll(version, addons_dir)
                for m in payroll_mods:
                    if m not in mod_list:
                        mod_list.append(m)
                log(f'[deploy] {container}: nómina (OCA) → {payroll_mods}')

            # 6. Pre-chown DESPUÉS de copiar todos los addons. El usuario 'odoo' dentro
            #    de la imagen oficial odoo:16-19 es uid=100 gid=101 (verificado con
            #    `docker exec ... id`) — NO uid=101 como se asumía antes. Con chown a
            #    101:101, uid=100 solo coincidía en el grupo (sin bit de escritura de
            #    grupo) y Odoo tiraba 500 al no poder escribir en sessions/.
            #    Pre-crear sessions/ para que Odoo no intente crearlo con makedirs(mode=0o700)
            #    sobre un directorio recién montado: si la carpeta no existe Odoo la crea bien;
            #    pero si existe y fue creada por root (ej: restart en caliente) da PermissionError.
            os.makedirs(os.path.join(odoo_data, 'sessions'), exist_ok=True)
            run(f'chown -R 100:101 {odoo_data} {addons_dir}')

            # 7. Levantar Odoo — sin restart porque los permisos ya están correctos.
            _set_stage(container, 'Iniciando Odoo...')
            r = run(f'cd {deploy_dir} && {COMPOSE} up -d', timeout=120)
            if not r['ok']:
                _set_stage(container, f'ERROR compose: {(r["stderr"] or r["stdout"])[:120]}')
                log(f"[deploy] {container}: ERROR — {r['stderr'] or r['stdout']}")
                return

            # 7. Fijar web.base.url y configurar SSL/nginx si hay dominio.
            if subdomain:
                _set_stage(container, f'Configurando SSL para {subdomain}...')
                res = configure_domain_ssl(subdomain, port)
                _set_web_base_url(db_name, public_url or f'https://{subdomain}')
                stage_ssl = f'Odoo listo — https://{subdomain}' if res.get('ok') else \
                            f'Odoo listo (SSL pendiente: {(res.get("error") or "")[:60]})'
                _set_stage(container, stage_ssl)
            elif ssl_mode == 'selfsigned' and PORT_MIN <= https_port <= PORT_MAX:
                _set_stage(container, 'Configurando HTTPS autofirmado...')
                res = configure_selfsigned_https(container, port, https_port)
                _set_web_base_url(db_name, public_url)
                _set_stage(container, 'Odoo listo' if res.get('ok') else
                           f'Odoo listo (HTTPS pendiente: {(res.get("error") or "")[:60]})')
            else:
                if public_url:
                    _set_web_base_url(db_name, public_url)
                _set_stage(container, 'Odoo iniciando...')

            # 8. Instalar módulos + paquete fiscal + idioma + correo saliente en
            #    background via XML-RPC. El cliente ve el login en ~30s; todo lo
            #    demás se instala por detrás. Corre SIEMPRE (aunque no haya módulos
            #    ni cambio de idioma) porque también configura el servidor de
            #    correo local — antes se saltaba entero y ningún deploy sin
            #    módulos/idioma personalizado quedaba con correo saliente.
            if fiscal and fiscal not in mod_list:
                mod_list.append(fiscal)
            mail_domain = subdomain or (re.sub(r'^https?://', '', public_url).split('/')[0].split(':')[0] if public_url else '')
            threading.Thread(
                target=_install_modules_rpc,
                args=(container, db_name, mod_list, port, version, lang, mail_domain),
                daemon=True
            ).start()

            log(f"[deploy] {container}: compose OK — módulos en background: {','.join(mod_list) or 'ninguno'} lang={lang} fiscal={fiscal}")

        def _do_deploy_safe():
            # _do_deploy corre en background sin que nadie espere su resultado — si
            # revienta una excepción no controlada (timeout, KeyError, lo que sea) el
            # hilo moría en silencio: sin log, sin _set_stage, el deploy quedaba
            # colgado en la última etapa visible para siempre. Esto lo hace visible.
            try:
                _do_deploy()
            except Exception as e:
                log(f'[deploy] {container}: EXCEPCIÓN no controlada — {e}')
                _set_stage(container, f'ERROR inesperado: {str(e)[:150]}')

        threading.Thread(target=_do_deploy_safe, daemon=True).start()

    # ── Upload módulo ─────────────────────────────────────────────
    def _handle_module_upload(self, body: dict):
        # Chunked upload: cada chunk llega por separado y se ensamblan antes de extraer.
        # Esto evita que un corte de TCP a mitad de un ZIP grande pierda todo el upload.
        if 'chunk_index' in body:
            return self._handle_module_chunk(body)

        # Formato legacy: ZIP completo en base64 (un solo POST — backward compat)
        container = _sanitize_name(body.get('container_name', ''))
        module    = _sanitize_name(body.get('module_name', 'modulo'))
        files     = body.get('files', {})
        zip_b64   = body.get('zip_base64', '')

        if not container:
            return self._send(400, {'error': 'container_name requerido'})

        addons_dir = os.path.join(ODOO_DIR, container, 'addons')
        module_dir = os.path.join(addons_dir, module)
        os.makedirs(module_dir, exist_ok=True)

        if files:
            for rel_path, content in files.items():
                safe = _safe_path(module_dir, rel_path)
                if not safe:
                    log(f"[upload] Path traversal bloqueado: {rel_path}")
                    continue
                os.makedirs(os.path.dirname(safe), exist_ok=True)
                with open(safe, 'w', encoding='utf-8') as f:
                    f.write(content)

        elif zip_b64:
            try:
                zip_data = base64.b64decode(zip_b64)
            except Exception:
                return self._send(400, {'error': 'zip_base64 inválido'})
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp:
                tmp.write(zip_data)
                tmp_path = tmp.name
            with zipfile.ZipFile(tmp_path, 'r') as z:
                for member in z.namelist():
                    safe = _safe_path(addons_dir, member)
                    if safe:
                        z.extract(member, addons_dir)
            os.unlink(tmp_path)

        r = run(['docker', 'restart', container])
        self._send(200 if r['ok'] else 500, {
            'ok':      r['ok'],
            'message': f'Módulo {module} actualizado. Odoo reiniciando...',
        })

    def _handle_module_chunk(self, body: dict):
        upload_id   = str(body.get('upload_id', ''))[:64]
        chunk_index = int(body.get('chunk_index', 0))
        total       = int(body.get('total_chunks', 1))
        container   = _sanitize_name(body.get('container_name', ''))
        module      = _sanitize_name(body.get('module_name', 'modulo'))
        data_b64    = body.get('data_b64', '')

        if not upload_id or not container:
            return self._send(400, {'error': 'upload_id y container_name requeridos'})
        if chunk_index < 0 or chunk_index >= total or total < 1:
            return self._send(400, {'error': 'chunk_index fuera de rango'})

        try:
            chunk_data = base64.b64decode(data_b64)
        except Exception:
            return self._send(400, {'error': 'data_b64 inválido'})

        # Limpiar uploads estancados (>10 min sin completar)
        now = time.time()
        with _chunk_lock:
            stale = [uid for uid, u in _chunk_uploads.items() if now - u['ts'] > 600]
            for uid in stale:
                del _chunk_uploads[uid]
                log(f'[upload] Chunk upload estancado limpiado: {uid}')

            if upload_id not in _chunk_uploads:
                _chunk_uploads[upload_id] = {
                    'chunks': {}, 'total': total,
                    'container': container, 'module': module,
                    'ts': now,
                }
            _chunk_uploads[upload_id]['chunks'][chunk_index] = chunk_data
            received = len(_chunk_uploads[upload_id]['chunks'])

        log(f'[upload] {upload_id}: chunk {chunk_index+1}/{total} recibido ({len(chunk_data)} bytes)')

        if received < total:
            return self._send(200, {'ok': True, 'received': received, 'total': total, 'done': False})

        # Todos los chunks llegaron — ensamblar, extraer y reiniciar
        with _chunk_lock:
            upload = _chunk_uploads.pop(upload_id, None)

        if not upload:
            return self._send(500, {'error': 'Upload perdido (race condition)'})

        full_data  = b''.join(upload['chunks'][i] for i in range(total))
        addons_dir = os.path.join(ODOO_DIR, container, 'addons')
        os.makedirs(addons_dir, exist_ok=True)

        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp:
            tmp.write(full_data)
            tmp_path = tmp.name

        # Carpetas de primer nivel del ZIP = nombres técnicos de los módulos Odoo
        # (convención estándar: cada módulo es una carpeta con __manifest__.py).
        top_level_mods = set()
        try:
            with zipfile.ZipFile(tmp_path, 'r') as zcheck:
                for name in zcheck.namelist():
                    parts = name.split('/')
                    if len(parts) > 1 and parts[0]:
                        safe_mod = _sanitize_name(parts[0])
                        if safe_mod:
                            top_level_mods.add(safe_mod)
        except Exception as e:
            os.unlink(tmp_path)
            return self._send(400, {'error': f'ZIP inválido: {e}'})

        db_name = _derive_db_name(container)
        port    = _get_odoo_port(container)

        # 1) Snapshot ANTES de tocar nada — si el módulo rompe Odoo, se revierte solo.
        snap_dir    = os.path.join(ODOO_DIR, container, '.pre_module_snapshot')
        run(f'rm -rf {snap_dir}')
        os.makedirs(snap_dir, exist_ok=True)
        snap_sql    = os.path.join(snap_dir, 'db.sql')
        snap_addons = os.path.join(snap_dir, 'addons_backup')
        _pg_dump_db(db_name, snap_sql)
        if os.path.isdir(addons_dir):
            run(f'cp -a {addons_dir} {snap_addons}')
        else:
            os.makedirs(snap_addons, exist_ok=True)

        # 2) Extraer el módulo nuevo/actualizado
        try:
            with zipfile.ZipFile(tmp_path, 'r') as z:
                for member in z.namelist():
                    safe = _safe_path(addons_dir, member)
                    if safe:
                        z.extract(member, addons_dir)
        except Exception as e:
            os.unlink(tmp_path)
            return self._send(400, {'error': f'ZIP inválido: {e}'})
        os.unlink(tmp_path)

        # 3) Instalar dependencias Python declaradas (requirements.txt /
        #    external_dependencies del manifest) — antes la UI lo prometía pero
        #    no había ninguna implementación real.
        deps_ok, deps_err = _install_python_requirements(container, addons_dir, list(top_level_mods))
        if not deps_ok:
            log(f'[module] {container}: fallo instalando dependencias Python: {deps_err}')

        run(f'chown -R 100:101 {addons_dir}')
        r = run(['docker', 'restart', container])
        log(f'[upload] {upload_id}: módulo(s) {sorted(top_level_mods)} copiados en {container}, restart ok={r["ok"]}')

        if not r['ok']:
            _rollback_module_snapshot(container, db_name, snap_sql, snap_addons, addons_dir)
            run(f'rm -rf {snap_dir}')
            return self._send(500, {
                'ok': False,
                'error': 'No se pudo reiniciar el contenedor tras copiar el módulo. Se revirtió automáticamente.',
                'rolled_back': True,
            })

        # 4) Esperar a que Odoo vuelva e instalar/actualizar el módulo vía XML-RPC,
        #    con reversión automática si algo falla (ver _install_or_upgrade_module_safe).
        ok, message, rolled_back = _install_or_upgrade_module_safe(
            container, db_name, port, list(top_level_mods), snap_sql, snap_addons, addons_dir
        )
        run(f'rm -rf {snap_dir}')

        if not ok:
            log(f'[module] {container}: instalación falló — {message}')
            return self._send(422, {'ok': False, 'done': True, 'error': message, 'rolled_back': rolled_back})

        if not deps_ok:
            message += f' (aviso: no se pudieron instalar todas las librerías Python — {deps_err[:200]})'

        self._send(200, {'ok': True, 'done': True, 'message': message})

    # ── Configurar dominio + SSL ──────────────────────────────────
    def _handle_configure_domain(self, body: dict):
        container = _sanitize_name(body.get('container_name', ''))
        domain    = _sanitize_domain(body.get('domain', ''))
        port      = int(body.get('odoo_port', 8069))

        if not container or not domain:
            return self._send(400, {'error': 'container_name y domain requeridos'})
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.\-]{1,252}$', domain):
            return self._send(400, {'error': 'Dominio inválido'})
        if not (PORT_MIN <= port <= PORT_MAX):
            return self._send(400, {'error': 'Puerto inválido'})

        result = configure_domain_ssl(domain, port)
        if result.get('ok'):
            return self._send(200, result)
        # 502 si el fallo es de emisión SSL (DNS aún no apunta); 500 si es config nginx.
        code = 502 if 'certificado' in (result.get('error') or '') else 500
        self._send(code, result)


if __name__ == '__main__':
    if not API_KEY:
        print('ERROR: variable NUQLEO_API_KEY no definida. Abortando.')
        exit(1)
    os.makedirs(ODOO_DIR, exist_ok=True)
    log(f'Nuqleo Agent v2 iniciando en {BIND}:{PORT}')
    if MODULES_REPO:
        threading.Thread(target=_sync_custom_modules, daemon=True).start()  # precarga librería custom
    os.makedirs(SNAPSHOT_ROOT, exist_ok=True)
    threading.Thread(target=_snapshot_scheduler_loop, daemon=True).start()  # snapshots diarios (7 días)
    server = HTTPServer((BIND, PORT), NuqleoHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log('Agent detenido.')
