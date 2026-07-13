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
import xmlrpc.client
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

# ── Acceso BI externo (Power BI / Excel) ─────────────────────────
# El Postgres compartido corre sin puerto publicado; para que un cliente conecte
# Power BI se publica vía un proxy socat en BI_PROXY_PORT (ver _ensure_bi_proxy)
# y se le crea un rol de SOLO LECTURA limitado a su propia base.
BI_PROXY_NAME = 'nuqleo_bi_proxy'
BI_PROXY_PORT = 5433

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

# Igual que _chunk_uploads pero para restaurar un backup subido por el cliente
# (ZIP estándar de Odoo: dump.sql + filestore/) — lock/estancamiento separados
# de _chunk_uploads porque son flujos independientes (módulo vs. restore).
_restore_uploads: dict = {}

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
    """Crea el rol 'odoo' si no existe, y SIEMPRE sincroniza su password con
    SHARED_PG_PASS (env NUQLEO_PG_PASS). Sin el ALTER, un re-registro del
    agente (que genera un NUQLEO_PG_PASS nuevo cada vez) contra un Postgres
    compartido que ya existía de una corrida anterior dejaba al rol 'odoo'
    con la contraseña VIEJA — todo Odoo nuevo entraba en crash-loop con
    'password authentication failed for user odoo' aunque postgres estuviera
    perfectamente sano."""
    run(['docker', 'exec', SHARED_PG_NAME, 'psql', '-U', SHARED_PG_ADMIN, '-c',
         f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{SHARED_PG_USER}') "
         f"THEN CREATE ROLE {SHARED_PG_USER} WITH LOGIN CREATEDB PASSWORD '{SHARED_PG_PASS}'; END IF; END $$"])
    run(['docker', 'exec', SHARED_PG_NAME, 'psql', '-U', SHARED_PG_ADMIN, '-c',
         f"ALTER ROLE {SHARED_PG_USER} WITH PASSWORD '{SHARED_PG_PASS}'"])

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

def _pg_exec_db(dbname: str, sql: str) -> dict:
    return run(['docker', 'exec', SHARED_PG_NAME, 'psql', '-U', SHARED_PG_ADMIN, '-d', dbname, '-c', sql])

def _ensure_bi_proxy() -> bool:
    """Publica el Postgres compartido en BI_PROXY_PORT para conexiones externas de
    BI (Power BI/Excel/Tableau). Se usa un contenedor socat en la red nuqleo-net en
    vez de publicar el puerto del propio Postgres porque este ya corre sin -p y no
    puede republicarse sin recrearlo; socat resuelve por NOMBRE de contenedor, así
    que sobrevive a cambios de IP interna tras reinicios. La seguridad real está en
    los roles de solo lectura por cliente (no en ocultar el puerto)."""
    r = run(['docker', 'inspect', '--format', '{{.State.Running}}', BI_PROXY_NAME])
    if r['ok']:
        if r['stdout'].strip() != 'true':
            run(['docker', 'start', BI_PROXY_NAME])
    else:
        ok = run(f'docker run -d --name {BI_PROXY_NAME} --network nuqleo-net '
                 f'--restart unless-stopped -p {BI_PROXY_PORT}:{BI_PROXY_PORT} alpine/socat '
                 f'tcp-listen:{BI_PROXY_PORT},fork,reuseaddr tcp:{SHARED_PG_NAME}:5432', timeout=180)
        if not ok['ok']:
            log(f'[bi] proxy socat no arrancó: {(ok["stderr"] or ok["stdout"])[:200]}')
            return False
    run(f'ufw allow {BI_PROXY_PORT}/tcp comment "Nuqleo BI read-only Postgres"')
    return True

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


def _parse_mem_to_mb(s: str) -> float:
    """Convierte un valor de docker stats (ej. '691MiB', '1.27GiB') a MB numéricos.
    Necesario porque MemUsage solo viene como string 'usado / límite' — sin esto
    no había forma de comparar el uso real de RAM contra la cuota vendida al
    cliente (nuqleo_check_ram_quotas() en el plugin)."""
    s = s.strip()
    m = re.match(r'([\d.]+)\s*(GiB|MiB|KiB|GB|MB|KB|B)', s, re.IGNORECASE)
    if not m:
        return 0.0
    val = float(m.group(1))
    unit = m.group(2).lower()
    if unit in ('gib', 'gb'): return round(val * 1024, 1)
    if unit in ('mib', 'mb'): return round(val, 1)
    if unit in ('kib', 'kb'): return round(val / 1024, 1)
    return round(val / (1024 * 1024), 1)

def _container_resources(cname: str) -> dict:
    """RAM/CPU en vivo (docker stats, una sola muestra) + disco usado por los datos
    de esta instancia + disco total del VPS. Todo con timeouts cortos porque el
    servidor HTTP del agente es single-threaded y esto es una llamada bajo demanda,
    no parte del polling frecuente de /status."""
    cpu_pct = mem_usage = mem_pct = ''
    r = run(['docker', 'stats', '--no-stream', '--format',
             '{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}', cname], timeout=15)
    if r['ok'] and r['stdout'].strip():
        parts = r['stdout'].strip().split('\t')
        if len(parts) >= 3:
            cpu_pct, mem_usage, mem_pct = parts[0], parts[1], parts[2]

    disk_mb = 0.0
    du = run(['du', '-sm', os.path.join(ODOO_DIR, cname)], timeout=20)
    if du['ok'] and du['stdout'].strip():
        try:
            disk_mb = float(du['stdout'].split()[0])
        except (ValueError, IndexError):
            pass

    # Tamaño real de la base de datos de este cliente dentro del Postgres
    # COMPARTIDO — sin esto, disk_mb (solo filestore/addons en disco) subestimaba
    # muchísimo el consumo real de un cliente con muchos registros/adjuntos en BD.
    db_mb = 0.0
    db_name = _derive_db_name(cname)
    db_bytes = _pg_query(f"SELECT pg_database_size('{db_name}')")
    if db_bytes.strip().isdigit():
        db_mb = round(int(db_bytes.strip()) / (1024 * 1024), 1)

    # Snapshots MANUALES (creados a pedido del cliente desde el botón "Backups")
    # cuentan contra su cupo de disco — los automáticos nocturnos NO, son overhead
    # de la plataforma. Por eso se suman aparte y solo se filtran los 'manual-*'.
    manual_snap_mb = 0.0
    snap_root = os.path.join(SNAPSHOT_ROOT, cname)
    if os.path.isdir(snap_root):
        total_bytes = 0
        for d in os.listdir(snap_root):
            if not d.startswith('manual-'):
                continue
            for fn in ('db.sql', 'addons.tar.gz', 'odoo-data.tar.gz'):
                fp = os.path.join(snap_root, d, fn)
                if os.path.exists(fp):
                    total_bytes += os.path.getsize(fp)
        manual_snap_mb = round(total_bytes / (1024 * 1024), 1)

    disk_server = {}
    df = run(['df', '-BM', '--output=used,size,pcent', '/'], timeout=10)
    if df['ok']:
        lines = df['stdout'].splitlines()
        if len(lines) >= 2:
            vals = lines[1].split()
            if len(vals) >= 3:
                disk_server = {
                    'used_mb':  int(vals[0].rstrip('M')),
                    'total_mb': int(vals[1].rstrip('M')),
                    'pct':      vals[2].rstrip('%'),
                }

    mem_used_mb = _parse_mem_to_mb(mem_usage.split('/')[0]) if mem_usage else 0.0

    return {
        'cpu_pct':      cpu_pct,
        'mem_usage':    mem_usage,
        'mem_pct':      mem_pct,
        'mem_used_mb':  mem_used_mb,
        'disk_mb':      round(disk_mb, 1),
        'db_mb':        db_mb,
        'manual_snapshot_mb': manual_snap_mb,
        'client_total_mb': round(disk_mb + db_mb + manual_snap_mb, 1),
        'disk_server':  disk_server,
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
    """Actualiza el repo de módulos custom en MODULES_DIR. Camino rápido: si ya
    hay un clone válido, hace `git pull` (baja solo el diff). Si no existe
    todavía o el pull falla, hace clone completo (swap atómico) como antes."""
    if not MODULES_REPO:
        return False
    run('command -v git >/dev/null 2>&1 || (DEBIAN_FRONTEND=noninteractive apt-get install -y git >/dev/null 2>&1)')
    auth_url = f'https://{MODULES_TOKEN}@{MODULES_REPO}' if MODULES_TOKEN else f'https://{MODULES_REPO}'

    # Camino rápido: git pull en vez de rm -rf + clone completo. Antes CADA
    # sync (wizard abierto, deploy que pide un módulo nuevo, pre-warm al
    # registrar el servidor) volvía a bajar el repo ENTERO aunque solo hubiera
    # cambiado un archivo — eso era lo que hacía sentir los deploys lentos
    # cuando se acababa de publicar un módulo nuevo. git pull trae solo el
    # diff: mucho más rápido y con mucha menos exposición al packet loss.
    if os.path.isdir(os.path.join(MODULES_DIR, '.git')):
        run(f'git -C {MODULES_DIR} remote set-url origin {auth_url}')
        pull_err = ''
        for attempt in range(1, 5):
            r = run(f'timeout 45 git -C {MODULES_DIR} pull --ff-only origin main', timeout=60)
            if r['ok']:
                log(f"[modules] pull OK (intento {attempt})")
                return True
            pull_err = (r.get('stderr') or '')[:150]
            if 'not granted' in pull_err or 'Authentication' in pull_err or '403' in pull_err:
                break
        log(f"[modules] pull falló, cayendo a clone completo: {pull_err}")

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


def _resolve_custom_module_deps(mod_list: list, version: str) -> list:
    """Expande mod_list agregando, para cada módulo propio (repo custom) ya
    presente, sus dependencias declaradas en __manifest__.py que TAMBIÉN sean
    módulos propios (existen como carpeta en el repo). Las dependencias core de
    Odoo (account, sale, l10n_co...) no se tocan — Odoo las resuelve solo."""
    import ast
    src = os.path.join(MODULES_DIR, str(version))
    if not os.path.isdir(src):
        _sync_custom_modules()
    if not os.path.isdir(src):
        return mod_list

    result = list(mod_list)
    seen   = set(result)
    queue  = list(result)
    while queue:
        m = queue.pop(0)
        manifest_path = os.path.join(src, m, '__manifest__.py')
        if not os.path.isfile(manifest_path):
            continue
        try:
            with open(manifest_path, encoding='utf-8') as f:
                manifest = ast.literal_eval(f.read())
        except Exception as e:
            log(f'[modules] no se pudo leer __manifest__.py de {m}: {e}')
            continue
        for dep in manifest.get('depends', []):
            if dep in seen:
                continue
            if os.path.isfile(os.path.join(src, dep, '__manifest__.py')):
                seen.add(dep)
                result.append(dep)
                queue.append(dep)
    return result


OM_ACCOUNT_REPO  = 'https://github.com/odoomates/odooapps.git'
OM_ACCOUNT_CACHE = '/opt/nuqleo-modulos/om_account'  # caché local por versión

# Módulos de contabilidad completa a instalar desde odoomates/odooapps.
# Se hace sparse checkout de todos en un solo clone (eficiente).
# om_account_accountant depende de accounting_pdf_reports, om_account_daily_reports
# y om_recurring_payments (verificado en su __manifest__.py de la rama 18.0) — sin
# copiar también esos 3, Odoo no puede resolver su grafo de dependencias al hacer
# "Update Apps List" y lo excluye en silencio (nunca aparece en Apps para activar).
# om_account_bank_statement_import ya no existe en la rama 18.0 (sí en 17.0) — Odoo
# 18 lo reemplazó con importación de extractos nativa, así que se quita de la lista.
OM_ACCOUNT_MODULES = [
    'om_account_accountant',        # contabilidad completa (reportes, diario, asientos)
    'accounting_pdf_reports',       # dependencia de om_account_accountant
    'om_account_daily_reports',     # dependencia de om_account_accountant
    'om_recurring_payments',        # dependencia de om_account_accountant
    'om_account_asset',             # gestión de activos fijos
    'om_account_budget',            # presupuestos
    'om_account_followup',          # seguimiento de cobros a clientes
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


# ── Soporte/Mesa de ayuda: 'helpdesk' de Odoo también es exclusivo de
#    Enterprise y NO existe en la imagen Community — otro módulo fantasma como
#    'sign'. helpdesk_mgmt (OCA) + sla + rating cubren lo mismo (tickets, SLAs,
#    satisfacción del cliente) en Community, libre. ──
OCA_HELPDESK_REPO    = 'https://github.com/OCA/helpdesk.git'
OCA_HELPDESK_CACHE   = '/opt/nuqleo-modulos/oca_helpdesk'
OCA_HELPDESK_MODULES = ['helpdesk_mgmt', 'helpdesk_mgmt_sla', 'helpdesk_mgmt_rating']

def _fetch_oca_helpdesk(version: str, addons_dir: str) -> list:
    """Descarga helpdesk_mgmt (+ sla, rating) desde OCA/helpdesk. Mismo patrón
    de caché/sparse-checkout que los demás fetchers OCA/odoomates."""
    branch    = f'{version}.0'
    cache_dir = os.path.join(OCA_HELPDESK_CACHE, version)

    need_download = []
    cached = []
    for mod in OCA_HELPDESK_MODULES:
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
        log(f'[oca_helpdesk] {version}: todos los módulos ya en caché/addons')
        return cached

    log(f'[oca_helpdesk] {version}: descargando {len(need_download)} módulos desde GitHub branch {branch}...')
    tmp = f'/tmp/oca_helpdesk_{version}_{int(time.time())}'

    clone_cmd = (
        f'timeout 90 git -c http.lowSpeedLimit=500 -c http.lowSpeedTime=20 '
        f'clone --depth 1 -b {branch} --filter=blob:none --sparse '
        f'{OCA_HELPDESK_REPO} {tmp}'
    )
    cloned = False
    for attempt in range(1, 6):
        run(f'rm -rf {tmp}')
        r = run(clone_cmd, timeout=100)
        if r['ok'] and os.path.isdir(tmp):
            cloned = True
            break
        log(f'[oca_helpdesk] clone intento {attempt} falló: {(r["stderr"] or "")[:100]}')

    if not cloned:
        log(f'[oca_helpdesk] {version}: no se pudo clonar — usando solo módulos en caché')
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
            log(f'[oca_helpdesk] {version}: {mod} instalado OK')
        else:
            log(f'[oca_helpdesk] {version}: {mod} no existe en branch {branch} (skip)')

    run(f'rm -rf {tmp}')
    log(f'[oca_helpdesk] {version}: módulos listos → {cached}')
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
    """Reintenta una llamada XML-RPC que puede chocar con conflictos transitorios
    de Postgres/Odoo mientras button_immediate_install recarga el registro entero:
    - 'SerializationFailure: could not serialize access due to concurrent update'
    - 'LockNotAvailable: could not obtain lock on row in relation "ir_cron"' —
      confirmado en vivo justo después de un deploy fresco: el scheduler interno
      de Odoo (cron) toma el lock de ir_cron casi al mismo tiempo que el install,
      y Odoo lo detecta y lanza "Odoo is currently processing a scheduled action"
      en vez de esperar — hay que reintentar nosotros desde afuera.
    - 'LockNotAvailable: canceling statement due to lock timeout' — Odoo 18 pone
      lock_timeout en sus DDL: si el cliente ya está navegando el login mientras
      corre la instalación (el wizard entrega los accesos a los ~60s pero el
      install tarda 2-4 min), la compilación de asset bundles (requests de 10s+)
      mantiene locks de lectura sobre res_company y el ALTER TABLE del install
      muere en vez de esperar. Confirmado en vivo 2026-07-13.
    - "doesn't have 'read' access to ... (ir.module.module)" — síntoma tardío del
      mismo incidente: tras abortar el graph load por el lock timeout, el reintento
      interno de Odoo corre contra un registry a medio cargar y devuelve AccessError
      aunque el uid sea admin. Con el registry recargado, reintentar desde afuera
      sí funciona.
    Todos son transitorios y esperados bajo carga (Odoo corre con --workers=2,
    hay crons y requests de otros workers tocando las mismas tablas). Confirmado
    en vivo: Odoo YA reintenta internamente unas pocas veces y aun así puede
    agotarlas; sin este reintento externo el módulo/idioma quedaba sin instalar
    en silencio y el fallback (contenedor one-off contra la misma BD que el
    contenedor principal, ya corriendo) tampoco es confiable."""
    RETRYABLE = ('serializ', 'concurrent update', 'ir_cron', 'scheduled action',
                 'locknotavailable', 'could not obtain lock', 'infailedsqltransaction',
                 'lock timeout', 'canceling statement', "have 'read' access",
                 'failed to load registry')
    last_err = None
    for attempt in range(1, tries + 1):
        try:
            return fn()
        except Exception as e:
            last_err = e
            msg = str(e).lower().replace(' ', '')
            if not any(tag.replace(' ', '') in msg for tag in RETRYABLE):
                raise
            log(f'[rpc] intento {attempt}/{tries} chocó con conflicto de concurrencia en Postgres, reintentando...')
            time.sleep(base_delay * attempt)
    raise last_err


class _TimeoutTransport(xmlrpc.client.Transport):
    """Transport de xmlrpc.client con timeout de socket explícito. Sin esto, un
    ServerProxy normal NUNCA expira: confirmado en vivo 2026-07-13 con pg_stat_activity
    mostrando TODAS las conexiones de Postgres en estado idle (nada bloqueado en la
    BD) mientras la llamada button_immediate_install seguía "colgada" varios minutos
    del lado del agente. button_immediate_install reinicia los workers de Odoo matando
    el proceso que atendía el request — si esa muerte no cierra el socket TCP con un
    FIN/RST limpio (pasa bajo carga), el socket.recv() del cliente se queda esperando
    para siempre y nuestro _retry_on_serialization_failure nunca ve la excepción que
    necesita para reintentar. Con este timeout, un socket colgado revienta con
    TimeoutError en vez de bloquear el deploy indefinidamente."""
    def __init__(self, timeout, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._nuqleo_timeout = timeout

    def make_connection(self, host):
        conn = super().make_connection(host)
        conn.timeout = self._nuqleo_timeout
        return conn


def _swap_to_nocron(container: str, port: int) -> str:
    """Detiene el contenedor principal y levanta uno gemelo temporal con
    --max-cron-threads=0, mismo puerto/red/volúmenes, para correr la
    instalación de módulos SIN el cron de Odoo corriendo en paralelo.

    Por qué: confirmado en vivo 2026-07-13 que el cron interno de Odoo
    (WorkerCron, siempre activo con --workers=2) ejecuta
    _check_modules_state() en cada ciclo — un UPDATE sobre ir_module_module
    que choca ("could not serialize access due to concurrent update") con
    CUALQUIER button_immediate_install que mantenga una transacción abierta
    más de unos segundos. Pasaba incluso instalando un solo módulo ('sale'),
    quemando 6 reintentos (~8 min) y a veces fallando igual. Sin cron
    corriendo, no hay con qué chocar.

    El cliente mantiene cron normal en su Odoo final — este contenedor
    temporal solo vive durante la instalación (ver _swap_back).
    Devuelve el nombre del contenedor temporal si el swap funcionó, o ''
    si algo falló (en cuyo caso el caller debe seguir usando `container`
    directo, aceptando el riesgo de choque en vez de bloquear el deploy)."""
    deploy_dir = os.path.join(ODOO_DIR, container)
    addons_dir = os.path.join(deploy_dir, 'addons')
    compose_path = os.path.join(deploy_dir, 'docker-compose.yml')
    try:
        with open(compose_path) as f:
            compose_txt = f.read()
        m = re.search(r'^\s*command:\s*(.+)$', compose_txt, re.MULTILINE)
        if not m:
            log(f'[nocron] {container}: no se encontró "command:" en docker-compose.yml')
            return ''
        # docker-compose escapa '$' como '$$' dentro del YAML (para --db-filter=^x$).
        # Al ejecutar esto nosotros mismos vía subprocess SIN shell (ver más abajo),
        # nadie hace esa des-escapada — hay que deshacerla a mano o Odoo recibe
        # literalmente dos signos de pesos en el regex del filtro de base de datos.
        base_args = m.group(1).strip().replace('$$', '$').split()
        # El puerto puede estar publicado en 127.0.0.1 (modo selfsigned, detrás de
        # nginx) o en 0.0.0.0 (modo IP directa, sin dominio) — replicar EXACTO el
        # binding original o el acceso directo por IP se rompería durante el swap.
        pm = re.search(r'ports:\s*\n\s*-\s*"([^"]+)"', compose_txt)
        port_bind = pm.group(1) if pm else f'{port}:8069'
    except Exception as e:
        log(f'[nocron] {container}: no se pudo leer docker-compose.yml ({e})')
        return ''

    # La versión de Odoo no viaja como parámetro de esta función — se lee de la
    # imagen que ya usa el contenedor original en vez de pedir un argumento más.
    img_r = run(['docker', 'inspect', container, '--format', '{{.Config.Image}}'])
    image = img_r['stdout'].strip() if img_r['ok'] and img_r['stdout'].strip() else 'odoo:18'

    temp_name = f'{container}_nocron'
    run(['docker', 'rm', '-f', temp_name])  # por si quedó uno huérfano de una corrida anterior
    stop_r = run(['docker', 'stop', container], timeout=90)
    if not stop_r['ok']:
        log(f'[nocron] {container}: no se pudo detener el contenedor principal, se aborta el swap')
        return ''

    # Lista, no string+shell=True: evita que bash interprete el '$' del
    # --db-filter (p.ej. como '$$' = PID del shell) o cualquier otro metacarácter.
    docker_args = [
        'docker', 'run', '-d', '--name', temp_name, '--network', 'nuqleo-net',
        '-p', port_bind,
        '-e', f'HOST={SHARED_PG_NAME}', '-e', f'USER={SHARED_PG_USER}', '-e', f'PASSWORD={SHARED_PG_PASS}',
        '-v', f'{deploy_dir}/odoo-data:/var/lib/odoo',
        '-v', f'{addons_dir}:/mnt/extra-addons',
        '--add-host', 'host.docker.internal:host-gateway',
        '--shm-size=256m',
        image,
    ] + base_args + ['--max-cron-threads=0']
    start_r = run(docker_args)
    if not start_r['ok']:
        log(f'[nocron] {container}: no se pudo iniciar el contenedor temporal sin cron ({start_r.get("stderr","")[:150]}), restaurando el original')
        run(['docker', 'rm', '-f', temp_name])
        run(['docker', 'start', container])
        return ''

    # Esperar a que el contenedor temporal responda antes de devolver el control.
    for _ in range(30):
        r = run(f'curl -sf --max-time 3 -o /dev/null -w "%{{http_code}}" http://127.0.0.1:{port}/web/login 2>/dev/null', timeout=6)
        if r['ok'] and r['stdout'].strip() in ('200', '303'):
            log(f'[nocron] {container}: swap a instancia sin cron OK ({temp_name})')
            return temp_name
        time.sleep(2)
    log(f'[nocron] {container}: la instancia sin cron no respondió a tiempo, restaurando el original')
    run(['docker', 'rm', '-f', temp_name])
    run(['docker', 'start', container])
    return ''


def _swap_back(temp_name: str, container: str):
    """Apaga la instancia temporal sin cron y devuelve el contenedor real
    (con cron normal) a su estado corriendo — contraparte de _swap_to_nocron."""
    if not temp_name:
        return
    run(['docker', 'rm', '-f', temp_name])
    run(['docker', 'start', container])
    log(f'[nocron] {container}: instancia sin cron apagada, contenedor original restaurado')


def _install_modules_rpc(container: str, db_name: str, mods_list: list, port: int, version: str, lang: str = 'es_CO', domain: str = '', fiscal: str = '', company_info: dict = None) -> bool:
    """Instala módulos e idioma via XML-RPC mientras Odoo está corriendo.
    Espera hasta que Odoo responda, instala módulos, activa idioma y Odoo se reinicia solo."""
    import xmlrpc.client
    url = f'http://127.0.0.1:{port}'
    # 240s: generoso para que un button_immediate_install del paquete fiscal pesado
    # (el más lento observado) no se corte en medio de una instalación legítima,
    # pero acota el peor caso de un socket colgado tras el reinicio de workers.
    _RPC_TIMEOUT = 240

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
        # Mensaje anterior decía "Odoo listo" incluso cuando Odoo NUNCA respondió
        # — confuso para el cliente y para soporte. Revisamos el estado real del
        # contenedor (docker inspect) para dar una pista accionable en vez de un
        # falso positivo.
        insp = run(['docker', 'inspect', container, '--format',
                    '{{.State.Status}}\t{{.RestartCount}}'])
        docker_state, restarts = 'desconocido', '0'
        if insp['ok'] and insp['stdout'].strip():
            parts = insp['stdout'].strip().split('\t')
            docker_state = parts[0]
            restarts = parts[1] if len(parts) > 1 else '0'
        if restarts.isdigit() and int(restarts) >= 3:
            stage_msg = (f'ERROR: el contenedor se reinicia solo ({restarts}x) — '
                         f'revisa "docker logs {container}" en el VPS (posible fallo de conexión a la BD)')
        else:
            stage_msg = f'Odoo no respondió en 4min (docker: {docker_state}) — revisar logs del contenedor'
        log(f'[rpc] {container}: Odoo no respondió en 4min, módulos pendientes (docker={docker_state}, restarts={restarts})')
        _set_stage(container, stage_msg)
        return False

    _set_stage(container, f'Instalando módulos e idioma {lang}...')
    # Swap a una instancia gemela sin cron para TODA la instalación — ver
    # _swap_to_nocron. Si el swap falla por cualquier motivo, seguimos contra el
    # contenedor original (temp_name queda '') aceptando el riesgo de choque en
    # vez de bloquear el deploy entero por esto.
    temp_name = _swap_to_nocron(container, port)
    try:
        _rpc_transport = _TimeoutTransport(_RPC_TIMEOUT)
        common = xmlrpc.client.ServerProxy(f'{url}/xmlrpc/2/common', allow_none=True, transport=_rpc_transport)
        uid = common.authenticate(db_name, 'admin', 'admin', {})
        if not uid:
            raise RuntimeError('auth falló con admin/admin')

        models = xmlrpc.client.ServerProxy(f'{url}/xmlrpc/2/object', allow_none=True, transport=_rpc_transport)

        # Módulos propios de tema/UX de Nuqleo — livianos y sin datos pesados,
        # se instalan primero para que el cliente vea la marca Nuqleo apenas entra.
        THEME_MODS = {'nuqleo_apps_filter', 'company_welcome_wizard', 'home_theme'}
        # Paquete fiscal/contable — el más pesado y el que más choca con locks de
        # Postgres (carga el plan de cuentas completo, impuestos, etc. — cientos de
        # registros). Confirmado en vivo 2026-07-13: meter esto en el mismo lote que
        # todo lo demás hacía que UN solo conflicto de concurrencia tirara el
        # deploy ENTERO sin entregar nada al cliente en 5-10 minutos. Se instala de
        # último, en su propia etapa, DESPUÉS de que el cliente ya tiene un Odoo
        # usable (idioma + tema + su módulo de negocio elegido).
        HEAVY_FISCAL_MODS = {'account', 'om_account_accountant', 'accounting_pdf_reports',
                              'om_account_daily_reports', 'om_recurring_payments',
                              'om_account_asset', 'om_account_budget', 'om_account_followup',
                              'om_fiscal_year'}
        def _is_heavy(name: str) -> bool:
            return name in HEAVY_FISCAL_MODS or name.startswith('l10n_')

        # 0. Correo saliente vía Postfix local del VPS (best-effort, no aborta el deploy).
        _configure_local_mail_server(models, uid, db_name, domain)

        # 0.5 Fijar el país de la compañía ANTES de instalar el paquete fiscal
        # (ej. l10n_co). La BD del cliente es un clon del template (odoo{v}_template),
        # que trae el país/plan contable por defecto de Odoo (Estados Unidos). Si
        # solo se instala l10n_co como un módulo más SIN cambiar antes el país de
        # la compañía, Odoo nunca carga el plan de cuentas colombiano — el cliente
        # veía siempre la localización de EEUU aunque hubiera elegido Colombia en
        # el wizard. Debe hacerse ANTES de 'account'/'l10n_co' para que Odoo
        # seleccione el chart_template correcto al instalarlos.
        if fiscal.startswith('l10n_') and len(fiscal) == 7:
            country_code = fiscal[5:].upper()
            try:
                country_ids = models.execute_kw(db_name, uid, 'admin', 'res.country', 'search',
                                                 [[['code', '=', country_code]]])
                if country_ids:
                    company_ids = models.execute_kw(db_name, uid, 'admin', 'res.company', 'search', [[]])
                    if company_ids:
                        models.execute_kw(db_name, uid, 'admin', 'res.company', 'write',
                                          [company_ids[:1], {'country_id': country_ids[0]}])
                        log(f'[rpc] {container}: país de la compañía fijado a {country_code} antes de instalar {fiscal}')
                else:
                    log(f'[rpc] {container}: no se encontró res.country con code={country_code}')
            except Exception as ce:
                log(f'[rpc] {container}: no se pudo fijar country_id ({ce}) — continúa con el paquete fiscal igual')

        # 0.6 Precargar datos de la compañía (nombre, NIT/identificación, correo,
        # logo) si el cliente los llenó en el wizard — para que el primer login
        # ya se vea con su marca en vez del "My Company" genérico de Odoo. Todo
        # opcional: si el cliente usó "Omitir", company_info llega vacío/None y
        # este paso simplemente no hace nada.
        if company_info:
            try:
                company_ids = models.execute_kw(db_name, uid, 'admin', 'res.company', 'search', [[]])
                if company_ids:
                    vals = {}
                    if company_info.get('name'):
                        vals['name'] = company_info['name']
                    if company_info.get('vat'):
                        vals['vat'] = company_info['vat']
                    if company_info.get('email'):
                        vals['email'] = company_info['email']
                    if company_info.get('logo_base64'):
                        vals['logo'] = company_info['logo_base64']
                    if vals:
                        models.execute_kw(db_name, uid, 'admin', 'res.company', 'write', [company_ids[:1], vals])
                        log(f'[rpc] {container}: datos de compañía precargados ({list(vals.keys())})')
            except Exception as ci_err:
                log(f'[rpc] {container}: no se pudo precargar datos de compañía ({ci_err}) — continúa igual')

        # Refrescar la lista de módulos ANTES de buscar cuáles instalar. Los
        # módulos custom (ss_enterprise_theme, om_account_*, etc.) se copian
        # a addons justo antes de levantar el container — si Odoo todavía no
        # terminó de escanear el addons_path cuando corre el search de abajo,
        # ese módulo ni siquiera tiene fila en ir.module.module todavía, así
        # que el filtro "name in mods_list" no lo encuentra y se queda sin
        # instalar en silencio (se ve en ir.module.module más tarde como
        # 'uninstalled' — Odoo lo descubrió después, pero ya nadie le pidió
        # instalarlo). update_list() fuerza el escaneo del disco ahora mismo.
        if mods_list:
            try:
                models.execute_kw(db_name, uid, 'admin', 'ir.module.module', 'update_list', [])
            except Exception as ul_err:
                log(f'[rpc] {container}: update_list falló ({ul_err}), continúa igual')

        def _install_group(group_mods: list, label: str):
            """Instala un subconjunto de mods_list y espera a que Odoo vuelva tras
            el reinicio de workers que hace button_immediate_install. Se usa por
            etapas (ver más abajo) en vez de un solo lote gigante: así el cliente
            recibe un Odoo usable (idioma + tema + su módulo elegido) en pocos
            minutos, y el paquete fiscal pesado —el más lento y el más propenso a
            choques de concurrencia— instala de último sin bloquear la entrega."""
            nonlocal uid
            if not group_mods:
                return
            pending = models.execute_kw(
                db_name, uid, 'admin',
                'ir.module.module', 'search',
                [[['name', 'in', group_mods], ['state', 'not in', ['installed', 'to install', 'to upgrade']]]]
            )
            if not pending:
                return
            log(f'[rpc] {container}: instalando etapa "{label}" ({len(pending)} módulos) via XML-RPC')
            _set_stage(container, f'Instalando {label}...')
            try:
                # tries/base_delay más altos que el default: este es el request
                # más largo y propenso a chocar con el tráfico del cliente (ver
                # _retry_on_serialization_failure) — cada reintento arranca la
                # instalación desde donde quedó (los módulos ya commiteados
                # quedan 'installed'), así que insistir es barato y recupera.
                _retry_on_serialization_failure(lambda: models.execute_kw(
                    db_name, uid, 'admin',
                    'ir.module.module', 'button_immediate_install',
                    [pending]
                ), tries=6, base_delay=10.0)
            except Exception as install_err:
                # button_immediate_install reinicia los workers de Odoo COMO PARTE
                # de su funcionamiento normal — el worker que atendía este request
                # muere antes de devolver respuesta, y el cliente XML-RPC ve
                # "Connection refused/reset" aunque la instalación sí haya
                # arrancado bien. Tratar esto como error fatal (antes lo hacía)
                # mandaba el deploy entero al fallback one-off innecesariamente.
                # 'timed out' incluido: confirmado en vivo 2026-07-13 que sin timeout
                # en el transport XML-RPC (ver _TimeoutTransport) esta llamada podía
                # quedarse colgada varios minutos con Postgres 100% idle (nada
                # bloqueado en la BD) — el socket del cliente nunca recibía el cierre
                # de conexión tras el reinicio de workers de Odoo.
                msg = str(install_err).lower()
                CONN_DROP_TAGS = ('connection refused', 'connection reset', 'broken pipe',
                                  'timed out', 'timeout')
                if not any(tag in msg for tag in CONN_DROP_TAGS):
                    raise
                log(f'[rpc] {container}: conexión cortada/expirada durante "{label}" '
                    f'(normal, Odoo reinicia workers) — se continúa esperando que vuelva')
            # button_immediate_install reinicia los workers de Odoo internamente.
            # Hay que esperar a que Odoo vuelva antes de continuar con la siguiente etapa.
            log(f'[rpc] {container}: esperando que Odoo vuelva tras "{label}"...')
            time.sleep(8)
            for _ in range(30):
                try:
                    new_uid = common.authenticate(db_name, 'admin', 'admin', {})
                    if new_uid:
                        uid = new_uid
                        break
                except Exception:
                    pass
                time.sleep(3)

        # 1. Idioma PRIMERO — no depende de ningún módulo custom, es rápido, y le
        #    da al cliente una interfaz en español desde el primer minuto en vez
        #    de esperar a que termine todo lo demás para verla traducida.
        if lang and lang != 'en_US':
            try:
                _set_stage(container, f'Activando idioma {lang}...')
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

        # 2. Tema/UX propio de Nuqleo — liviano, da la marca Nuqleo de una vez.
        theme_mods = [m for m in mods_list if m in THEME_MODS]
        _install_group(theme_mods, 'tema y accesos de Nuqleo')

        # 3. Módulo(s) de negocio que el cliente eligió en el wizard (sale, project,
        #    lo que sea) — el Odoo "tradicional" que el cliente espera ver rápido.
        base_mods = [m for m in mods_list if m not in THEME_MODS and not _is_heavy(m)]
        _install_group(base_mods, 'tus módulos de negocio')

        # 4. Paquete fiscal/contable — de ÚLTIMO porque es el más lento y el más
        #    propenso a chocar con locks (ver comentario en HEAVY_FISCAL_MODS
        #    arriba). Para esta altura el cliente YA tiene un Odoo usable.
        heavy_mods = [m for m in mods_list if _is_heavy(m)]
        _install_group(heavy_mods, 'paquete contable/fiscal (puede tardar más)')

        # Reinicio final tras instalar módulos + idioma: Odoo sirve los bundles de
        # JS/QWeb (web.assets_backend) tal como estaban compilados en el momento de
        # cada button_immediate_install intermedio — con varios módulos instalados
        # en la misma sesión (mail, project, sale, etc.) el navegador del cliente
        # podía recibir un bundle a medio regenerar y tirar errores como
        # "KeyNotFoundError: Cannot find key 'mail.action_discuss' in the actions
        # registry" en el primer login. Un restart limpio al final fuerza a Odoo a
        # sched los assets ya con el registro de módulos completo y estable.
        # Reinicio final: si hicimos swap sin cron, devolver el contenedor real
        # (con cron normal para el cliente) YA es un arranque limpio con el
        # registro de módulos completo — hace lo mismo que el restart de assets
        # de abajo, así que no hace falta repetirlo. Si no hubo swap (falló por
        # algún motivo), seguimos con el restart explícito de siempre.
        if temp_name:
            log(f'[rpc] {container}: instalación terminada, devolviendo el contenedor real (con cron)...')
            _swap_back(temp_name, container)
            temp_name = ''  # ya restaurado — que el finally no lo repita
        else:
            log(f'[rpc] {container}: reinicio final para asegurar assets JS/QWeb limpios...')
            run(['docker', 'restart', container])
        for _ in range(40):
            time.sleep(3)
            r3 = run(f'curl -sf --max-time 3 -o /dev/null -w "%{{http_code}}" {url}/web/login 2>/dev/null', timeout=6)
            if r3['ok'] and r3['stdout'].strip() in ('200', '303'):
                break

        _set_stage(container, 'Listo ✓')
        log(f'[rpc] {container}: módulos e idioma OK via XML-RPC')
        return True

    except Exception as e:
        log(f'[rpc] {container}: XML-RPC falló ({e}), usando one-off como fallback')
        # Fallback: one-off container (método original, más lento pero más robusto)
        addons_dir = os.path.join(ODOO_DIR, container, 'addons')
        mods_csv = ','.join(mods_list)
        lang_flag = f'--load-language {lang}' if lang else ''
        # Parar el contenedor principal mientras corre el one-off: la causa #1 de
        # llegar a este fallback es tráfico web del cliente (login/compilación de
        # assets) tomando locks sobre las mismas tablas que el install necesita
        # ALTERar — con el principal corriendo, el one-off choca con los MISMOS
        # locks y también falla (confirmado en vivo 2026-07-13: one-off ok=False
        # en 28s). Detenido el principal, el one-off tiene la BD para él solo.
        _set_stage(container, 'Finalizando instalación de módulos...')
        if temp_name:
            # El contenedor real ya está detenido (quedó así desde el swap) — solo
            # hay que tumbar la instancia temporal antes del one-off.
            run(['docker', 'rm', '-f', temp_name])
            temp_name = ''
        else:
            run(['docker', 'stop', container], timeout=90)
        inst = run(
            f'docker run --rm --network nuqleo-net '
            f'-v {addons_dir}:/mnt/extra-addons '
            f'-e HOST={SHARED_PG_NAME} -e USER={SHARED_PG_USER} -e PASSWORD={SHARED_PG_PASS} '
            f'odoo:{version} -- --database {db_name} '
            f'{"--init " + mods_csv if mods_csv else ""} {lang_flag} --stop-after-init --no-http',
            timeout=900
        )
        run(['docker', 'start', container], timeout=90)
        ok = inst['ok'] or 'stop' in (inst['stdout'] + inst['stderr']).lower()
        _set_stage(container, 'Listo ✓' if ok else f'Aviso: módulos no instalados ({mods_csv})')
        log(f'[rpc-fallback] {container}: one-off ok={ok}')

        # --load-language deja el idioma INSTALADO pero no cambia el idioma del
        # usuario admin ni el de la compañía (eso solo pasaba en el camino XML-RPC
        # normal, arriba) — por eso un deploy que caía a este fallback quedaba con
        # el paquete de idioma listo pero el login se seguía viendo en inglés.
        if ok and lang and lang != 'en_US':
            try:
                fb_common = xmlrpc.client.ServerProxy(f'{url}/xmlrpc/2/common', allow_none=True,
                                                       transport=_TimeoutTransport(_RPC_TIMEOUT))
                fb_uid = None
                # 40 iteraciones (~2min): el one-off de arriba ahora para/arranca el
                # contenedor principal, así que aquí Odoo SIEMPRE está re-arrancando.
                for _ in range(40):
                    try:
                        fb_uid = fb_common.authenticate(db_name, 'admin', 'admin', {})
                        if fb_uid:
                            break
                    except Exception:
                        pass
                    time.sleep(3)
                if fb_uid:
                    fb_models = xmlrpc.client.ServerProxy(f'{url}/xmlrpc/2/object', allow_none=True,
                                                           transport=_TimeoutTransport(_RPC_TIMEOUT))
                    admin_ids = fb_models.execute_kw(db_name, fb_uid, 'admin', 'res.users', 'search',
                                                      [[['login', '=', 'admin']]])
                    if admin_ids:
                        fb_models.execute_kw(db_name, fb_uid, 'admin', 'res.users', 'write',
                                              [admin_ids, {'lang': lang}])
                    company_ids = fb_models.execute_kw(db_name, fb_uid, 'admin', 'res.company', 'search', [[]])
                    if company_ids:
                        try:
                            fb_models.execute_kw(db_name, fb_uid, 'admin', 'res.company', 'write',
                                                  [company_ids[:1], {'default_lang': lang}])
                        except Exception:
                            pass
                    log(f'[rpc-fallback] {container}: idioma {lang} asignado a admin/compañía OK')
                else:
                    log(f'[rpc-fallback] {container}: Odoo no respondió para asignar idioma a admin/compañía')
            except Exception as le:
                log(f'[rpc-fallback] {container}: no se pudo asignar idioma a admin/compañía: {le}')

        return ok

    finally:
        # Red de seguridad: si algo inesperado no contemplado arriba dejó la
        # instancia temporal sin cron todavía viva a esta altura, nunca dejar el
        # contenedor real del cliente detenido para siempre.
        if temp_name:
            _swap_back(temp_name, container)


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

def _get_odoo_version(container: str) -> str:
    """Versión de Odoo (ej: '18') a partir del tag de la imagen del contenedor
    (odoo:18 → '18') — no se guarda en ningún lado tras el deploy, así que hay
    que leerla de docker cuando se necesita (ej. para instalar módulos del
    repo propio en una instancia ya existente)."""
    r = run(['docker', 'inspect', container, '--format', '{{.Config.Image}}'])
    if r['ok'] and ':' in r['stdout']:
        return r['stdout'].strip().split(':')[-1]
    return ''

def _pg_dump_db(db_name: str, out_path: str) -> bool:
    r = run(f'docker exec {SHARED_PG_NAME} pg_dump -U odoo {db_name} > {out_path}', timeout=180)
    return r['ok'] and os.path.exists(out_path) and os.path.getsize(out_path) > 0


# Módulos/prefijos técnicos de Odoo base que NO aportan nada útil para
# desarrollar un módulo a medida — se excluyen de la introspección para que el
# contexto que recibe la IA se centre en lo que el cliente realmente instaló
# (sale, account, l10n_co, o sus propios módulos custom), no en el andamiaje
# interno de Odoo (auth, bus, mail, portal, etc.) que la IA ya conoce de sobra.
_ODOO_CORE_MODULE_PREFIXES = (
    'base', 'web', 'mail', 'bus', 'portal', 'http_routing', 'web_editor',
    'web_tour', 'base_setup', 'base_import', 'base_automation', 'resource',
    'uom', 'utm', 'digest', 'iap', 'phone_validation', 'onboarding',
    'auth_', 'snailmail', 'privacy', 'partner_autocomplete', 'social_media',
    'html_editor', 'attachment_indexation', 'rating', 'sms', 'website',
)
_ODOO_CORE_MODEL_PREFIXES = (
    'ir.', 'res.', 'mail.', 'bus.', 'base.', 'web_editor.', 'web_tour.',
    'auth_', 'onboarding.', 'resource.', 'utm.', 'digest.', 'iap.',
    'phone.blacklist', 'privacy.', 'rating.', 'sms.', 'report.',
)


def _odoo_introspect(container: str) -> dict:
    """Lee, vía XML-RPC, qué tiene instalado un Odoo YA desplegado del cliente:
    módulos instalados (excluyendo el andamiaje técnico de Odoo) y, para esos
    módulos, sus modelos con los campos principales. Pensado para dar contexto
    real al chat de desarrollo de módulos ('quiero un módulo para mi Odoo') en
    vez de que la IA adivine nombres de modelos/campos que quizás no existen
    en ESA instancia específica."""
    port = _get_odoo_port(container)
    if not port:
        return {'ok': False, 'error': 'contenedor no encontrado o sin puerto publicado'}
    db_name = _derive_db_name(container)
    url = f'http://127.0.0.1:{port}'

    try:
        transport = _TimeoutTransport(30)
        common = xmlrpc.client.ServerProxy(f'{url}/xmlrpc/2/common', allow_none=True, transport=transport)
        uid = common.authenticate(db_name, 'admin', 'admin', {})
        if not uid:
            return {'ok': False, 'error': 'no se pudo autenticar contra la instancia'}
        models = xmlrpc.client.ServerProxy(f'{url}/xmlrpc/2/object', allow_none=True, transport=transport)

        mod_ids = models.execute_kw(db_name, uid, 'admin', 'ir.module.module', 'search',
                                     [[['state', '=', 'installed']]])
        mod_recs = models.execute_kw(db_name, uid, 'admin', 'ir.module.module', 'read',
                                      [mod_ids, ['name', 'shortdesc']])
        custom_mods = [m for m in mod_recs if not m['name'].startswith(_ODOO_CORE_MODULE_PREFIXES)]
        custom_names = {m['name'] for m in custom_mods}

        # Modelos definidos por esos módulos (vía ir.model.data, que registra qué
        # módulo creó cada registro — incluye modelos con nombre ir.model.xxxx).
        model_data_ids = models.execute_kw(
            db_name, uid, 'admin', 'ir.model.data', 'search',
            [[['model', '=', 'ir.model'], ['module', 'in', list(custom_names)]]]
        )
        model_res_ids = [d['res_id'] for d in models.execute_kw(
            db_name, uid, 'admin', 'ir.model.data', 'read', [model_data_ids, ['res_id']])]

        model_recs = []
        if model_res_ids:
            raw_models = models.execute_kw(db_name, uid, 'admin', 'ir.model', 'read',
                                            [model_res_ids, ['model', 'name']])
            raw_models = [m for m in raw_models if not m['model'].startswith(_ODOO_CORE_MODEL_PREFIXES)]
            # Tope de 40 modelos: suficiente contexto sin disparar el tamaño del
            # prompt si el cliente tiene decenas de módulos custom instalados.
            for mrec in raw_models[:40]:
                field_ids = models.execute_kw(
                    db_name, uid, 'admin', 'ir.model.fields', 'search',
                    [[['model', '=', mrec['model']], ['store', '=', True]]]
                )
                fields = models.execute_kw(db_name, uid, 'admin', 'ir.model.fields', 'read',
                                            [field_ids, ['name', 'field_description', 'ttype']])
                model_recs.append({
                    'model': mrec['model'],
                    'name': mrec['name'],
                    'fields': [{'name': f['name'], 'label': f['field_description'], 'type': f['ttype']}
                               for f in fields if not f['name'].startswith('__')][:25],
                })

        return {
            'ok': True,
            'modules': [{'name': m['name'], 'label': m['shortdesc']} for m in custom_mods],
            'models': model_recs,
        }
    except Exception as e:
        return {'ok': False, 'error': str(e)[:200]}

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

        def _tolerate_conn_drop(fn, accion):
            try:
                fn()
            except Exception as e:
                msg = str(e).lower()
                if 'connection refused' not in msg and 'connection reset' not in msg and 'broken pipe' not in msg:
                    raise
                # button_immediate_install/upgrade reinician los workers de Odoo
                # COMO PARTE de su funcionamiento normal — el worker que atendía
                # este request muere antes de responder. Sin esta tolerancia,
                # instalaciones que SÍ funcionaron se revertían igual por error.
                log(f'[module] {container}: conexión cortada durante {accion} (normal, Odoo reinicia workers)')

        if to_install:
            _tolerate_conn_drop(
                lambda: models.execute_kw(db_name, uid, 'admin', 'ir.module.module', 'button_immediate_install', [to_install]),
                'instalación')
        if to_upgrade:
            _tolerate_conn_drop(
                lambda: models.execute_kw(db_name, uid, 'admin', 'ir.module.module', 'button_immediate_upgrade', [to_upgrade]),
                'actualización')

        # Como arriba pudimos haber tolerado una conexión cortada, no podemos
        # asumir que la instalación terminó bien — hay que reconectar y
        # verificar el estado REAL del módulo antes de reportar éxito.
        time.sleep(8)
        reconnected = False
        for _ in range(30):
            try:
                uid2 = common.authenticate(db_name, 'admin', 'admin', {})
                if uid2:
                    uid = uid2
                    reconnected = True
                    break
            except Exception:
                pass
            time.sleep(3)

        if not reconnected:
            _rollback_module_snapshot(container, db_name, snap_sql, snap_addons, addons_dir)
            return False, ('Odoo no volvió a responder después de instalar el módulo. '
                            'Se revirtió automáticamente al estado anterior.'), True

        final_states = models.execute_kw(db_name, uid, 'admin', 'ir.module.module', 'read',
                                          [found], {'fields': ['name', 'state']})
        not_installed = [m['name'] for m in final_states if m['state'] != 'installed']
        if not_installed:
            _rollback_module_snapshot(container, db_name, snap_sql, snap_addons, addons_dir)
            return False, (f"El módulo no quedó instalado correctamente ({', '.join(not_installed)} "
                            f"en estado no instalado). Se revirtió automáticamente."), True

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

def _create_manual_snapshot(container: str):
    """Snapshot manual bajo demanda del cliente (botón 'Crear snapshot ahora' en
    /plataforma). A diferencia del automático nocturno (gratis, no cuenta contra el
    cupo), este SÍ suma a client_total_mb en _container_resources() porque el cliente
    lo pidió explícitamente. Se identifica con prefijo 'manual-' para no pisar el
    snapshot diario del mismo día y se purga solo a los SNAPSHOT_RETENTION_DAYS días
    igual que los automáticos (ver _prune_old_snapshots)."""
    db_name    = _derive_db_name(container)
    deploy_dir = os.path.join(ODOO_DIR, container)
    addons_dir = os.path.join(deploy_dir, 'addons')
    data_dir   = os.path.join(deploy_dir, 'odoo-data')
    if not os.path.isdir(deploy_dir):
        return None, 'Deployment no encontrado'

    import datetime
    snap_id  = 'manual-' + datetime.datetime.utcnow().strftime('%Y-%m-%d-%H%M%S')
    snap_dir = os.path.join(SNAPSHOT_ROOT, container, snap_id)
    os.makedirs(snap_dir, exist_ok=True)

    ok_db = _pg_dump_db(db_name, os.path.join(snap_dir, 'db.sql'))
    if os.path.isdir(addons_dir):
        run(f'tar --exclude=__pycache__ -czf {os.path.join(snap_dir, "addons.tar.gz")} -C {deploy_dir} addons',
            timeout=300)
    if os.path.isdir(data_dir):
        run(f'tar -czf {os.path.join(snap_dir, "odoo-data.tar.gz")} -C {deploy_dir} odoo-data', timeout=300)

    if not ok_db:
        run(f'rm -rf {snap_dir}')
        log(f'[snapshot] {container}: snapshot manual falló (pg_dump)')
        return None, 'No se pudo generar el snapshot (falló el respaldo de la base de datos)'

    log(f'[snapshot] {container}: snapshot manual {snap_id} creado a pedido del cliente')
    return snap_id, None

def _prune_old_snapshots(container: str):
    import datetime
    root = os.path.join(SNAPSHOT_ROOT, container)
    if not os.path.isdir(root):
        return
    cutoff = datetime.datetime.utcnow().date() - datetime.timedelta(days=SNAPSHOT_RETENTION_DAYS)
    for name in os.listdir(root):
        m = re.match(r'^manual-(\d{4}-\d{2}-\d{2})-\d{6}$', name)
        date_part = m.group(1) if m else name
        try:
            d = datetime.datetime.strptime(date_part, '%Y-%m-%d').date()
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
    # Sin esto, un cliente que abre la conexión y no manda una petición completa
    # (bot/scanner con un GET a medio enviar, o un Content-Length más grande que
    # los bytes reales) deja al hilo bloqueado para siempre en recv() — y como
    # el servidor es single-threaded (ver nota más abajo), UN solo cliente lento
    # cuelga el agente entero para TODOS los clientes de este VPS hasta reiniciar
    # el servicio a mano. socketserver ya maneja socket.timeout solo (cierra la
    # conexión y sigue con la siguiente), basta con fijar este atributo.
    timeout = 30

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
                # NO cuenta como fallo de rate-limit: todo el tráfico de todos los
                # clientes de este VPS llega desde la MISMA IP de WordPress. Un
                # timestamp vencido puntual (reloj desincronizado, respuesta lenta
                # de un intento anterior) ya trae la clave correcta — no es un
                # indicio de ataque. Contarlo aquí podía bloquear (_is_rate_limited)
                # TODA la comunicación WordPress→VPS durante 60s por un solo hiccup,
                # afectando a todos los clientes de ese servidor a la vez.
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

        elif self.path.startswith('/odoo-introspect/'):
            # Contexto real para el chat de desarrollo de módulos ('quiero un
            # módulo para mi Odoo') — ver _odoo_introspect. Solo lectura, no
            # toca nada del contenedor ni de la BD del cliente.
            cname = _sanitize_name(self.path[len('/odoo-introspect/'):])
            if not cname:
                return self._send(400, {'error': 'container requerido'})
            result = _odoo_introspect(cname)
            self._send(200 if result.get('ok') else 502, result)

        elif self.path.startswith('/resources/'):
            # Uso de RAM/CPU/disco de una instancia — endpoint aparte y bajo demanda
            # (no metido en /status, que el panel sondea cada 8s): el servidor HTTP del
            # agente es single-threaded (HTTPServer, no ThreadingHTTPServer) y tanto
            # "docker stats" como "du" tardan 1-2s+, así que hacerlo en cada poll
            # bloquearía deploys/otros clientes de este mismo VPS.
            cname = _sanitize_name(self.path[len('/resources/'):])
            if not cname:
                return self._send(400, {'error': 'container requerido'})
            self._send(200, {'ok': True, 'container': cname, **_container_resources(cname)})

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

        elif self.path.startswith('/module/export'):
            # Empaqueta un módulo del repo propio para que el cliente lo DESCARGUE
            # (a diferencia de /module/install-from-repo, que lo instala directo en
            # una instancia) — usado cuando el cliente COMPRA el código en vez de
            # solo rentar el uso mensual en su Odoo.
            qs = parse_qs(urlparse(self.path).query)
            module  = _sanitize_name(qs.get('module_name', [''])[0])
            version = _sanitize_name(qs.get('version', [''])[0])
            if not module or not version:
                return self._send(400, {'error': 'module_name y version requeridos'})
            src = os.path.join(MODULES_DIR, version, module)
            if not os.path.exists(os.path.join(src, '__manifest__.py')):
                _sync_custom_modules()
                if not os.path.exists(os.path.join(src, '__manifest__.py')):
                    return self._send(404, {'error': f'Módulo "{module}" no existe para Odoo {version}'})
            # zipfile de Python en vez de shell out a `zip` — el paquete no viene
            # instalado por defecto en la imagen base de Ubuntu del setup.sh.
            zip_path = f'/tmp/{module}_{version}_export.zip'
            if os.path.exists(zip_path):
                os.remove(zip_path)
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for root, _, files in os.walk(src):
                    for fname in files:
                        full = os.path.join(root, fname)
                        arcname = os.path.join(module, os.path.relpath(full, src))
                        zf.write(full, arcname)
            self._send_file(zip_path, f'{module}.zip')
            os.remove(zip_path)

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
                    m_manual = re.match(r'^manual-(\d{4}-\d{2}-\d{2})-(\d{2})(\d{2})(\d{2})$', d)
                    if re.match(r'^\d{4}-\d{2}-\d{2}$', d):
                        snap_type, date_label = 'auto', d
                    elif m_manual:
                        snap_type = 'manual'
                        date_label = f'{m_manual.group(1)} {m_manual.group(2)}:{m_manual.group(3)}'
                    else:
                        continue
                    size = 0
                    for fn in ('db.sql', 'addons.tar.gz', 'odoo-data.tar.gz'):
                        fp = os.path.join(root, d, fn)
                        if os.path.exists(fp):
                            size += os.path.getsize(fp)
                    items.append({'id': d, 'date': date_label, 'type': snap_type, 'size_mb': round(size / (1024 * 1024), 1)})
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
        elif path == '/module/install-from-repo': self._handle_module_install_from_repo(body)
        elif path == '/module/sync-catalog': self._handle_module_sync_catalog(body)
        elif path == '/configure-domain': self._handle_configure_domain(body)
        elif path == '/reset-password':   self._handle_reset_password(body)
        elif path == '/stop':             self._handle_stop(body)
        elif path == '/restart':          self._handle_restart(body)
        elif path == '/start':            self._handle_start(body)
        elif path == '/setup-postgres':   self._handle_setup_postgres(body)
        elif path == '/backup':           self._handle_backup(body)
        elif path == '/snapshot-restore': self._handle_snapshot_restore(body)
        elif path == '/snapshot-create':  self._handle_snapshot_create(body)
        elif path == '/restore-upload':   self._handle_restore_upload_chunk(body)
        elif path == '/bi-access':        self._handle_bi_access(body)
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

            # Pre-descargar los módulos OCA/odoomates más usados (contabilidad,
            # firma, nómina, soporte) apenas se registra el VPS — así el primer
            # deploy que los necesite los copia de la caché local en vez de
            # esperar el clone de GitHub en caliente durante el deploy real.
            log('[setup] Pre-descargando módulos OCA/odoomates...')
            scratch = '/tmp/nuqleo-prewarm-addons'
            os.makedirs(scratch, exist_ok=True)
            for v in versions:
                v = str(v)
                if v in ('17', '18', '19'):
                    for fetcher, tag in ((_fetch_om_accounting, 'contabilidad'),
                                         (_fetch_oca_sign, 'firma'),
                                         (_fetch_oca_helpdesk, 'soporte')):
                        try:
                            fetcher(v, scratch)
                        except Exception as e:
                            log(f'[setup] pre-warm {tag} {v} falló: {e}')
                if v in ('16', '17', '18', '19'):
                    try:
                        _fetch_oca_payroll(v, scratch)
                    except Exception as e:
                        log(f'[setup] pre-warm nómina {v} falló: {e}')
            run(f'rm -rf {scratch}')

            # Repo privado de módulos propios (NUQLEO_MODULES_REPO/TOKEN) — mismo
            # motivo que el pre-warm de arriba: que el clone ya esté listo en
            # MODULES_DIR antes de que llegue el primer deploy que los pida.
            if MODULES_REPO:
                log('[setup] Pre-descargando repo de módulos propios...')
                try:
                    _sync_custom_modules()
                except Exception as e:
                    log(f'[setup] pre-warm módulos propios falló: {e}')

            _ensure_host_postfix()

            # Re-aplica el proxy BI y su regla de UFW en cada setup/registro del
            # servidor. Sin esto, una reinstalación del agente (que hace
            # `ufw --force reset` + reaplica solo la lista estática de puertos)
            # borraba silenciosamente la regla de BI_PROXY_PORT mientras el
            # contenedor socat seguía corriendo de una corrida anterior —
            # el puerto quedaba "vivo" pero inalcanzable, y nada lo detectaba
            # hasta que un cliente reportara que Power BI no conectaba.
            try:
                _ensure_bi_proxy()
            except Exception as e:
                log(f'[setup] pre-warm proxy BI falló: {e}')

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

        # 2) Tar de addons/filestore + el dump.sql en el mismo archivo (antes solo
        #    se descargaba el tar, sin la BD — un "backup" que no incluía la base
        #    de datos no servía para restaurar nada). Los módulos PROPIOS (repo
        #    privado de Nuqleo) se EXCLUYEN a propósito: el cliente paga por
        #    hospedarlos/usarlos, no por llevarse su código fuente (para eso existe
        #    /store/download-module). Los módulos que el cliente subió con "Módulo"
        #    son su propio código y sí quedan incluidos.
        excludes = '--exclude=__pycache__'
        version  = _get_odoo_version(name)
        if MODULES_REPO and version:
            custom_src = os.path.join(MODULES_DIR, version)
            if os.path.isdir(custom_src):
                for entry in os.listdir(custom_src):
                    if os.path.isfile(os.path.join(custom_src, entry, '__manifest__.py')):
                        excludes += f' --exclude={name}/addons/{entry}'

        tar_cmd = f'tar {excludes} -czf {tar_path} -C {ODOO_DIR} {name}'
        if sql_file and os.path.exists(sql_file):
            tar_cmd += f' -C {bak_dir} {db_name}.sql'
        run(tar_cmd, timeout=300)

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

    # ── Acceso BI de solo lectura (Power BI / Excel) a la BD del cliente ──
    def _handle_bi_access(self, body: dict):
        name   = _sanitize_name(body.get('container_name', ''))
        action = str(body.get('action', 'status'))
        if not name:
            return self._send(400, {'error': 'container_name requerido'})
        db_name = _derive_db_name(name)
        bi_user = f'bi_{db_name}'[:63]  # límite de largo de identificadores en Postgres

        role_exists = _pg_query(f"SELECT 1 FROM pg_roles WHERE rolname='{bi_user}'") == '1'

        if action == 'status':
            return self._send(200, {'ok': True, 'enabled': role_exists, 'user': bi_user,
                                    'db': db_name, 'port': BI_PROXY_PORT})

        if action == 'disable':
            if role_exists:
                # DROP OWNED revoca todos los grants del rol dentro de la BD;
                # el default privilege se revoca aparte porque pertenece a 'odoo'.
                _pg_exec_db(db_name, f'ALTER DEFAULT PRIVILEGES FOR ROLE {SHARED_PG_USER} IN SCHEMA public REVOKE SELECT ON TABLES FROM {bi_user}')
                _pg_exec_db(db_name, f'DROP OWNED BY {bi_user}')
                _pg_exec(f'DROP ROLE IF EXISTS {bi_user}')
            log(f'[bi] {name}: acceso BI desactivado')
            return self._send(200, {'ok': True, 'enabled': False})

        if action not in ('enable', 'rotate'):
            return self._send(400, {'error': 'action inválida (status|enable|rotate|disable)'})

        # enable/rotate — idempotente: crea o rota el password y (re)aplica grants.
        if not _ensure_bi_proxy():
            return self._send(500, {'ok': False, 'error': 'No se pudo iniciar el proxy de conexión BI'})

        password = os.urandom(18).hex()
        if role_exists:
            _pg_exec(f"ALTER ROLE {bi_user} WITH LOGIN PASSWORD '{password}' CONNECTION LIMIT 5")
        else:
            _pg_exec(f"CREATE ROLE {bi_user} WITH LOGIN PASSWORD '{password}' CONNECTION LIMIT 5")

        # Aislar la BD: sin esto cualquier rol (incl. los bi_ de OTROS clientes)
        # puede conectarse por el CONNECT implícito de PUBLIC. El dueño (odoo)
        # conserva su acceso por ser owner de la BD.
        _pg_exec(f'REVOKE CONNECT ON DATABASE {db_name} FROM PUBLIC')
        _pg_exec(f'GRANT CONNECT ON DATABASE {db_name} TO {bi_user}')
        # Solo lectura sobre TODO el esquema, incluyendo tablas que Odoo cree
        # después (módulos instalados más tarde) vía default privileges.
        _pg_exec_db(db_name, f'GRANT USAGE ON SCHEMA public TO {bi_user}')
        _pg_exec_db(db_name, f'GRANT SELECT ON ALL TABLES IN SCHEMA public TO {bi_user}')
        _pg_exec_db(db_name, f'ALTER DEFAULT PRIVILEGES FOR ROLE {SHARED_PG_USER} IN SCHEMA public GRANT SELECT ON TABLES TO {bi_user}')

        log(f'[bi] {name}: acceso BI {"rotado" if role_exists else "activado"} ({bi_user})')
        self._send(200, {'ok': True, 'enabled': True, 'user': bi_user,
                         'password': password, 'db': db_name, 'port': BI_PROXY_PORT})

    # ── Crear snapshot manual bajo demanda ────────────────────────
    def _handle_snapshot_create(self, body: dict):
        name = _sanitize_name(body.get('container_name', ''))
        if not name:
            return self._send(400, {'error': 'container_name requerido'})
        snap_id, err = _create_manual_snapshot(name)
        if err:
            return self._send(500, {'ok': False, 'error': err})
        self._send(200, {'ok': True, 'id': snap_id})

    # ── Restaurar snapshot (diario automático o manual) a un punto concreto ──
    def _handle_snapshot_restore(self, body: dict):
        name     = _sanitize_name(body.get('container_name', ''))
        date_str = re.sub(r'[^0-9a-zA-Z\-]', '', str(body.get('date', '')))[:32]
        if not name or not re.match(r'^(\d{4}-\d{2}-\d{2}|manual-\d{4}-\d{2}-\d{2}-\d{6})$', date_str):
            return self._send(400, {'error': 'container_name y date/id de snapshot inválidos'})

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

    # ── Restaurar backup subido por el cliente (ZIP estándar de Odoo: dump.sql
    #    + filestore/ en la raíz — el mismo que exporta Ajustes > Bases de datos >
    #    Backup). Se sube en chunks igual que un módulo (ver _handle_module_chunk),
    #    solo toca BD + filestore — los addons/módulos custom quedan intactos. ──
    def _handle_restore_upload_chunk(self, body: dict):
        upload_id   = str(body.get('upload_id', ''))[:64]
        chunk_index = int(body.get('chunk_index', 0))
        total       = int(body.get('total_chunks', 1))
        container   = _sanitize_name(body.get('container_name', ''))
        data_b64    = body.get('data_b64', '')

        if not upload_id or not container:
            return self._send(400, {'error': 'upload_id y container_name requeridos'})
        if chunk_index < 0 or chunk_index >= total or total < 1:
            return self._send(400, {'error': 'chunk_index fuera de rango'})

        try:
            chunk_data = base64.b64decode(data_b64)
        except Exception:
            return self._send(400, {'error': 'data_b64 inválido'})

        now = time.time()
        with _chunk_lock:
            stale = [uid for uid, u in _restore_uploads.items() if now - u['ts'] > 600]
            for uid in stale:
                del _restore_uploads[uid]
                log(f'[restore-upload] upload estancado limpiado: {uid}')
            if upload_id not in _restore_uploads:
                _restore_uploads[upload_id] = {'chunks': {}, 'total': total, 'container': container, 'ts': now}
            _restore_uploads[upload_id]['chunks'][chunk_index] = chunk_data
            received = len(_restore_uploads[upload_id]['chunks'])

        log(f'[restore-upload] {upload_id}: chunk {chunk_index+1}/{total} recibido ({len(chunk_data)} bytes)')

        if received < total:
            return self._send(200, {'ok': True, 'received': received, 'total': total, 'done': False})

        with _chunk_lock:
            upload = _restore_uploads.pop(upload_id, None)
        if not upload:
            return self._send(500, {'error': 'Upload perdido (race condition)'})

        full_data = b''.join(upload['chunks'][i] for i in range(total))
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp:
            tmp.write(full_data)
            tmp_path = tmp.name

        deploy_dir = os.path.join(ODOO_DIR, container)
        if not os.path.isdir(deploy_dir):
            os.unlink(tmp_path)
            return self._send(404, {'ok': False, 'done': True, 'error': 'Deployment no encontrado'})

        extract_dir = tempfile.mkdtemp(prefix='nq-restore-')
        try:
            with zipfile.ZipFile(tmp_path, 'r') as z:
                for member in z.namelist():
                    safe = _safe_path(extract_dir, member)
                    if safe:
                        z.extract(member, extract_dir)
        except Exception as e:
            os.unlink(tmp_path)
            run(f'rm -rf {extract_dir}')
            return self._send(400, {'ok': False, 'done': True, 'error': f'ZIP inválido: {e}'})
        os.unlink(tmp_path)

        # dump.sql y filestore/ suelen estar en la raíz del zip, pero si el cliente
        # re-comprimió a mano puede que queden envueltos en una carpeta extra —
        # buscamos en cualquier nivel.
        def _find(name, is_dir=False):
            for root, dirs, files in os.walk(extract_dir):
                entries = dirs if is_dir else files
                if name in entries:
                    return os.path.join(root, name)
            return None

        dump_sql  = _find('dump.sql')
        filestore = _find('filestore', is_dir=True)

        if not dump_sql:
            run(f'rm -rf {extract_dir}')
            return self._send(400, {'ok': False, 'done': True, 'error': 'El ZIP no contiene dump.sql — sube el backup estándar de Odoo (Ajustes > Bases de datos > Backup)'})

        db_name = _derive_db_name(container)
        log(f'[restore-upload] {container}: restaurando desde archivo subido (db={db_name})')

        run(['docker', 'stop', container])
        ok_db = _pg_restore_db(db_name, dump_sql)

        if filestore:
            fs_dest = os.path.join(deploy_dir, 'odoo-data', '.local', 'share', 'Odoo', 'filestore', db_name)
            run(f'rm -rf {fs_dest}')
            os.makedirs(os.path.dirname(fs_dest), exist_ok=True)
            run(f'cp -r {filestore} {fs_dest}')

        run(f'chown -R 100:101 {os.path.join(deploy_dir, "odoo-data")}')
        run(f'rm -rf {extract_dir}')
        r = run(['docker', 'start', container])

        if ok_db and r['ok']:
            log(f'[restore-upload] {container}: restauración completada')
            self._send(200, {'ok': True, 'done': True, 'message': 'Base de datos restaurada desde el archivo subido.'})
        else:
            log(f'[restore-upload] {container}: restauración con errores (db_ok={ok_db}, start_ok={r["ok"]})')
            self._send(500, {'ok': False, 'done': True, 'error': 'La restauración tuvo errores. Revisa el estado de la instancia.'})

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

        # Datos de compañía opcionales del wizard (nombre, NIT/identificación, correo,
        # logo) — todos vacíos si el cliente usó "Omitir". El logo llega como base64
        # puro (el front ya le quitó el prefijo data:image/...;base64,); se limita el
        # tamaño para no aceptar payloads enormes en un campo pensado para un logo.
        company_info = {
            'name':  re.sub(r'[\r\n\t]', '', str(body.get('company_name', '')))[:150].strip(),
            'vat':   re.sub(r'[^A-Za-z0-9.\-\s]', '', str(body.get('company_vat', '')))[:50].strip(),
            'email': re.sub(r'[\r\n\t]', '', str(body.get('company_email', '')))[:150].strip(),
        }
        logo_b64 = str(body.get('company_logo_base64', ''))
        if logo_b64 and len(logo_b64) <= 4_000_000:
            company_info['logo_base64'] = logo_b64
        company_info = {k: v for k, v in company_info.items() if v}

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
        # RAM elástica: mem_reservation 1300m es lo garantizado por instancia (5 Odoos ×
        # 1.3GB = 6.5GB, deja ~1.5GB para sistema+postgres+WP en un VPS 8GB). mem_limit
        # 3000m es el techo de ráfaga — si las otras instancias están libres, esta puede
        # usar hasta 3GB en vez de quedar limitada a 1.3GB fijos. Si TODAS las instancias
        # están cargadas a la vez, el kernel prioriza matar procesos por encima de su
        # reserva, así que ningún cliente se queda sin su 1.3GB garantizado.
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
    mem_reservation: '1300m'
    mem_limit: '3000m'
    memswap_limit: '3000m'
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

            # Módulos propios que van SIEMPRE preinstalados, sin que el cliente tenga
            # que elegirlos en "Tus módulos": asistente de bienvenida y el tema de
            # pantalla de inicio (home_theme — reemplaza a ss_enterprise_theme, que
            # se retiró por un bug y ya no se ofrece en ninguna lista).
            # Solo si el repo de módulos propios está configurado — si no, quedarían en
            # mod_list sin copiarse a addons y la instalación fallaría al no existir.
            if MODULES_REPO:
                # nuqleo_apps_filter: oculta del menú Apps los upsells Enterprise
                # (to_buy) — el cliente solo ve apps Community + módulos propios.
                mod_list.extend(['company_welcome_wizard', 'home_theme', 'nuqleo_apps_filter'])

            # Cualquier módulo propio (repo custom) que dependa de OTRO módulo propio
            # necesita que ese hermano también esté en mod_list: aunque su carpeta se
            # copia igual a addons (ver 5b más abajo), _install_modules_rpc solo llama
            # button_immediate_install sobre los ids que caen dentro de mods_list
            # (name in mods_list) — si el cliente no seleccionó también la dependencia,
            # Odoo nunca recibe la orden de instalarla y el módulo pedido se queda
            # "to install" sin poder resolverla (ej: l10n_co_exogena → l10n_co_edi_community).
            # Las dependencias CORE de Odoo (account, sale, l10n_co...) no necesitan esto:
            # Odoo ya las resuelve solo con button_immediate_install.
            if MODULES_REPO:
                mod_list = _resolve_custom_module_deps(mod_list, version)

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
            # desde Odoo 17 — 'payroll' de OCA es el equivalente libre. Se prefiere
            # la copia en el repo propio (nuqleo_odoos) sobre clonar OCA/payroll en
            # vivo: el clone directo a GitHub sufría por el packet-loss de Contabo
            # y "no salía para instalar" (fallaba en silencio, ver _fetch_oca_payroll).
            if 'payroll' in mod_list and version in ('16', '17', '18', '19'):
                _set_stage(container, 'Preparando módulo de nómina...')
                own_src = os.path.join(MODULES_DIR, str(version))
                has_own_payroll = os.path.isfile(os.path.join(own_src, 'payroll', '__manifest__.py'))
                if has_own_payroll:
                    for m in ('payroll', 'payroll_account'):
                        mod_src = os.path.join(own_src, m)
                        if os.path.isfile(os.path.join(mod_src, '__manifest__.py')) and not os.path.exists(os.path.join(addons_dir, m)):
                            run(f'cp -r {mod_src} {addons_dir}/')
                        if m not in mod_list:
                            mod_list.append(m)
                    log(f'[deploy] {container}: nómina copiada desde repo propio (payroll, payroll_account)')
                else:
                    payroll_mods = _fetch_oca_payroll(version, addons_dir)
                    for m in payroll_mods:
                        if m not in mod_list:
                            mod_list.append(m)
                    log(f'[deploy] {container}: nómina (OCA, fallback) → {payroll_mods}')

            # Si el cliente seleccionó Soporte: 'helpdesk' también es de Enterprise
            # y no existe en Community — helpdesk_mgmt (OCA) es el equivalente libre.
            if 'helpdesk' in mod_list and version in ('16', '17', '18', '19'):
                _set_stage(container, 'Descargando mesa de ayuda (OCA)...')
                mod_list = [m for m in mod_list if m != 'helpdesk']
                helpdesk_mods = _fetch_oca_helpdesk(version, addons_dir)
                for m in helpdesk_mods:
                    if m not in mod_list:
                        mod_list.append(m)
                log(f'[deploy] {container}: soporte (OCA) → {helpdesk_mods}')

            # 5b. Copiar TAMBIÉN el resto de módulos propios del repo que el cliente
            # NO seleccionó, para que aparezcan en el menú Apps de Odoo listos para
            # activar gratis — el cliente ya pagó el hosting; el cobro real por un
            # módulo propio es descargar su código fuente (ver /store/download-module),
            # no instalarlo dentro de su propia instancia.
            if MODULES_REPO:
                # Módulos retirados: siguen en el repo pero NO se copian a ningún
                # deploy nuevo (ss_enterprise_theme se retiró por un bug; su
                # reemplazo home_theme va preinstalado arriba).
                _retired = {'ss_enterprise_theme'}
                repo_src = os.path.join(MODULES_DIR, str(version))
                if not os.path.isdir(repo_src):
                    _sync_custom_modules()
                if os.path.isdir(repo_src):
                    for entry in os.listdir(repo_src):
                        if entry in _retired or entry in mod_list or os.path.exists(os.path.join(addons_dir, entry)):
                            continue
                        if os.path.exists(os.path.join(repo_src, entry, '__manifest__.py')):
                            run(f'cp -r {os.path.join(repo_src, entry)} {addons_dir}/')
                    log(f'[deploy] {container}: resto de módulos propios copiados a addons (disponibles gratis en Apps)')

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
                args=(container, db_name, mod_list, port, version, lang, mail_domain, fiscal, company_info),
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

    # ── Instalar un módulo del repo propio (Tienda de Apps) en una instancia
    #    YA desplegada — a diferencia de /module/upload, el módulo no llega por
    #    zip: ya está clonado en MODULES_DIR (mismo repo privado que alimenta el
    #    wizard de deploy), así que solo hay que copiarlo e instalarlo. Mismo
    #    patrón de snapshot+reversión que _handle_module_chunk. ──
    def _handle_module_install_from_repo(self, body: dict):
        container = _sanitize_name(body.get('container_name', ''))
        module    = _sanitize_name(body.get('module_name', ''))

        if not container or not module:
            return self._send(400, {'error': 'container_name y module_name requeridos'})
        if not MODULES_REPO:
            return self._send(503, {'error': 'Repo de módulos propios no configurado'})

        version = _get_odoo_version(container)
        if not version:
            return self._send(404, {'error': f'No se pudo determinar la versión de Odoo de {container}'})

        src = os.path.join(MODULES_DIR, version, module)
        if not os.path.exists(os.path.join(src, '__manifest__.py')):
            _sync_custom_modules()
            if not os.path.exists(os.path.join(src, '__manifest__.py')):
                return self._send(404, {'error': f'Módulo "{module}" no existe para Odoo {version}'})

        addons_dir = os.path.join(ODOO_DIR, container, 'addons')
        os.makedirs(addons_dir, exist_ok=True)
        db_name = _derive_db_name(container)
        port    = _get_odoo_port(container)

        # 1) Snapshot ANTES de tocar nada.
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

        # 2) Copiar el módulo ya clonado del repo propio.
        run(f'rm -rf {os.path.join(addons_dir, module)}')
        run(f'cp -r {src} {addons_dir}/')

        # 3) Dependencias Python declaradas (requirements.txt / external_dependencies).
        deps_ok, deps_err = _install_python_requirements(container, addons_dir, [module])
        if not deps_ok:
            log(f'[module-repo] {container}: fallo instalando dependencias Python: {deps_err}')

        run(f'chown -R 100:101 {addons_dir}')
        r = run(['docker', 'restart', container])
        log(f'[module-repo] {container}: módulo {module} copiado, restart ok={r["ok"]}')

        if not r['ok']:
            _rollback_module_snapshot(container, db_name, snap_sql, snap_addons, addons_dir)
            run(f'rm -rf {snap_dir}')
            return self._send(500, {
                'ok': False,
                'error': 'No se pudo reiniciar el contenedor tras copiar el módulo. Se revirtió automáticamente.',
                'rolled_back': True,
            })

        ok, message, rolled_back = _install_or_upgrade_module_safe(
            container, db_name, port, [module], snap_sql, snap_addons, addons_dir
        )
        run(f'rm -rf {snap_dir}')

        if not ok:
            log(f'[module-repo] {container}: instalación falló — {message}')
            return self._send(422, {'ok': False, 'done': True, 'error': message, 'rolled_back': rolled_back})

        if not deps_ok:
            message += f' (aviso: no se pudieron instalar todas las librerías Python — {deps_err[:200]})'

        self._send(200, {'ok': True, 'done': True, 'message': message})

    # ── Sincronizar TODOS los módulos propios del catálogo que falten en un
    #    deployment ya existente (creado antes de que _do_deploy copiara el
    #    catálogo completo) — solo copia archivos + update_list(), sin instalar
    #    nada; el cliente los activa él mismo desde el menú Apps de Odoo, gratis.
    def _handle_module_sync_catalog(self, body: dict):
        container = _sanitize_name(body.get('container_name', ''))
        if not container:
            return self._send(400, {'error': 'container_name requerido'})
        if not MODULES_REPO:
            return self._send(503, {'error': 'Repo de módulos propios no configurado'})

        version = _get_odoo_version(container)
        if not version:
            return self._send(404, {'error': f'No se pudo determinar la versión de Odoo de {container}'})

        src = os.path.join(MODULES_DIR, str(version))
        if not os.path.isdir(src):
            _sync_custom_modules()
        if not os.path.isdir(src):
            return self._send(503, {'error': 'No se pudo sincronizar el repositorio de módulos'})

        addons_dir = os.path.join(ODOO_DIR, container, 'addons')
        os.makedirs(addons_dir, exist_ok=True)
        copied = []
        for entry in os.listdir(src):
            if os.path.exists(os.path.join(addons_dir, entry)):
                continue
            if os.path.exists(os.path.join(src, entry, '__manifest__.py')):
                run(f'cp -r {os.path.join(src, entry)} {addons_dir}/')
                copied.append(entry)
        run(f'chown -R 100:101 {addons_dir}')

        if not copied:
            return self._send(200, {'ok': True, 'copied': [], 'message': 'Ya tenías todos los módulos del catálogo disponibles en Apps.'})

        db_name = _derive_db_name(container)
        port    = _get_odoo_port(container)
        try:
            import xmlrpc.client
            url    = f'http://127.0.0.1:{port}'
            common = xmlrpc.client.ServerProxy(f'{url}/xmlrpc/2/common', allow_none=True)
            uid    = common.authenticate(db_name, 'admin', 'admin', {})
            if uid:
                models = xmlrpc.client.ServerProxy(f'{url}/xmlrpc/2/object', allow_none=True)
                models.execute_kw(db_name, uid, 'admin', 'ir.module.module', 'update_list', [])
        except Exception as e:
            log(f'[module-sync] {container}: update_list falló ({e}), los módulos quedan copiados igual')

        self._send(200, {'ok': True, 'copied': copied, 'message': f'{len(copied)} módulo(s) nuevo(s) ya disponibles en el menú Apps de Odoo.'})

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

    def _handle_reset_password(self, body: dict):
        # Resetea la contraseña del usuario admin escribiendo directo en Postgres
        # en vez de vía XML-RPC — si el cliente ya cambió la contraseña y la
        # olvidó, no tenemos con qué autenticar el login RPC. Odoo acepta un
        # password guardado en texto plano en este campo (passlib lo detecta como
        # esquema "plaintext" y lo re-hashea solo en el próximo login exitoso),
        # así que no hace falta replicar su algoritmo de hash aquí.
        container = _sanitize_name(body.get('container_name', ''))
        new_password = str(body.get('new_password', ''))
        if not container:
            return self._send(400, {'error': 'container_name requerido'})
        if len(new_password) < 8:
            return self._send(400, {'error': 'La contraseña debe tener al menos 8 caracteres'})
        db_name = _derive_db_name(container)
        safe_pw = new_password.replace("'", "''")
        r = run(['docker', 'exec', SHARED_PG_NAME, 'psql', '-U', SHARED_PG_ADMIN, '-d', db_name,
                  '-c', f"UPDATE res_users SET password = '{safe_pw}' WHERE login = 'admin'"])
        if not r['ok']:
            log(f'[password] {container}: falló el reset ({r["stderr"][:200]})')
            return self._send(500, {'error': 'No se pudo actualizar la contraseña'})
        log(f'[password] {container}: contraseña de admin reseteada por el cliente')
        self._send(200, {'ok': True})


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
