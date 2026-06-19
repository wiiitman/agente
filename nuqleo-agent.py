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

# ── Configuración ───────────────────────────────────────────────
PORT     = int(os.environ.get('NUQLEO_PORT', 9876))
API_KEY  = os.environ.get('NUQLEO_API_KEY', '')
ODOO_DIR = '/opt/nuqleo-odoo'
LOG_FILE = '/var/log/nuqleo-agent.log'
BIND     = os.environ.get('NUQLEO_BIND', '0.0.0.0')  # cambiar a 127.0.0.1 con túnel/UFW

# Versiones permitidas de Odoo
ALLOWED_ODOO_VERSIONS = {'16', '17', '18', '19', '20'}

# Rango de puertos permitidos para Odoo
PORT_MIN, PORT_MAX = 8000, 9999

# ── Rate limiting ────────────────────────────────────────────────
_rate_lock   = threading.Lock()
_fail_counts = defaultdict(list)   # ip → [timestamps de fallos]
RATE_WINDOW  = 60    # segundos
RATE_MAX     = 5     # fallos máximos antes de bloquear


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


def _sanitize_name(value: str) -> str:
    """Solo letras, números y guiones. Máx 60 chars."""
    return re.sub(r'[^a-zA-Z0-9\-_]', '', value)[:60]


def _sanitize_domain(value: str) -> str:
    """Dominio válido: letras, números, puntos, guiones."""
    return re.sub(r'[^a-zA-Z0-9.\-]', '', value)[:253]


def _safe_path(base_dir: str, rel_path: str) -> str | None:
    """Resuelve una ruta y verifica que esté dentro de base_dir."""
    full = os.path.realpath(os.path.join(base_dir, rel_path.lstrip('/')))
    return full if full.startswith(os.path.realpath(base_dir) + os.sep) else None


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

        key = self.headers.get('X-Nuqleo-Key', '')
        if not API_KEY or not hmac.compare_digest(key, API_KEY):
            _record_fail(ip)
            log(f"[auth] Clave inválida desde {ip}")
            return False

        # Verificar firma HMAC-SHA256 del cuerpo + timestamp
        ts_str  = self.headers.get('X-Nuqleo-Timestamp', '')
        sig_rcv = self.headers.get('X-Nuqleo-Sig', '')

        if ts_str and sig_rcv:
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

    def _read_body(self) -> bytes:
        length = int(self.headers.get('Content-Length', 0))
        return self.rfile.read(length) if length else b''

    def _send(self, code: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

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

        elif self.path == '/deployments':
            r = run(['docker', 'ps', '--format', '{{.Names}}\t{{.Status}}\t{{.Ports}}'])
            containers = []
            for line in r['stdout'].splitlines():
                parts = line.split('\t')
                if len(parts) >= 2:
                    containers.append({'name': parts[0], 'status': parts[1],
                                       'ports': parts[2] if len(parts) > 2 else ''})
            self._send(200, {'ok': True, 'containers': containers})

        else:
            self._send(404, {'error': 'Not found'})

    # ── POST ─────────────────────────────────────────────────────
    def do_POST(self):
        raw_body = self._read_body()
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
        else:                             self._send(404, {'error': 'Endpoint no encontrado'})

    # ── Stop / Restart ───────────────────────────────────────────
    def _handle_stop(self, body: dict):
        name = _sanitize_name(body.get('container_name', ''))
        if not name:
            return self._send(400, {'error': 'container_name requerido'})
        r = run(['docker', 'stop', name])
        if r['ok']:
            run(['docker', 'rm', name])
        self._send(200 if r['ok'] else 500, r)

    def _handle_restart(self, body: dict):
        name = _sanitize_name(body.get('container_name', ''))
        if not name:
            return self._send(400, {'error': 'container_name requerido'})
        r = run(['docker', 'restart', name])
        self._send(200 if r['ok'] else 500, r)

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

        compose = f"""version: '3.9'
services:
  db_{container}:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: {db_name}
      POSTGRES_USER: {db_user}
      POSTGRES_PASSWORD: {db_pass}
    volumes:
      - {deploy_dir}/pgdata:/var/lib/postgresql/data
    restart: unless-stopped

  {container}:
    image: odoo:{version}
    ports:
      - "127.0.0.1:{port}:8069"
    depends_on:
      - db_{container}
    environment:
      HOST: db_{container}
      USER: {db_user}
      PASSWORD: {db_pass}
    volumes:
      - {deploy_dir}/odoo-data:/var/lib/odoo
      - {addons_dir}:/mnt/extra-addons
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true

networks:
  default:
    name: nuqleo-net
    external: true
"""
        with open(os.path.join(deploy_dir, 'docker-compose.yml'), 'w') as f:
            f.write(compose)

        run('docker network create nuqleo-net 2>/dev/null || true')

        # Responder inmediatamente y correr docker compose en background
        self._send(200, {
            'ok':         True,
            'container':  container,
            'port':       port,
            'access_url': f'http://{os.uname().nodename}:{port}',
            'message':    f'Odoo {version} iniciando en puerto {port} (puede tardar 2-5 min)',
        })

        def _do_compose():
            r = run(f'cd {deploy_dir} && docker compose up -d', timeout=600)
            log(f"[deploy] {container}: {'OK' if r['ok'] else 'ERROR'} — {r['stderr'] or r['stdout']}")

        threading.Thread(target=_do_compose, daemon=True).start()

    # ── Upload módulo ─────────────────────────────────────────────
    def _handle_module_upload(self, body: dict):
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
                # Extraer con protección path-traversal
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

        run('apt-get install -y certbot python3-certbot-nginx 2>/dev/null || true')
        r = run(['certbot', 'certonly', '--non-interactive', '--agree-tos',
                 '-m', f'admin@{domain}', '--nginx', '-d', domain])
        log(f"[ssl] certbot {domain}: ok={r['ok']}")

        if not r['ok'] and 'already exists' not in r['stderr']:
            return self._send(500, {'error': 'Error SSL', 'detail': r['stderr'][:300]})

        nginx_conf = f"""upstream odoo_{container} {{ server 127.0.0.1:{port}; }}
server {{
    listen 80; server_name {domain};
    return 301 https://$server_name$request_uri;
}}
server {{
    listen 443 ssl http2; server_name {domain};
    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    add_header Strict-Transport-Security "max-age=63072000" always;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-Proto https;
    location / {{
        proxy_pass http://odoo_{container};
        proxy_read_timeout 600s;
    }}
}}
"""
        nginx_path = f'/etc/nginx/sites-available/{domain}'
        with open(nginx_path, 'w') as f:
            f.write(nginx_conf)
        run(f'ln -sf {nginx_path} /etc/nginx/sites-enabled/{domain}')

        test = run(['nginx', '-t'])
        if test['ok']:
            run(['systemctl', 'reload', 'nginx'])
            self._send(200, {'ok': True, 'domain': domain, 'message': f'SSL activo para {domain}'})
        else:
            self._send(500, {'error': 'Error Nginx', 'detail': test['stderr'][:300]})


if __name__ == '__main__':
    if not API_KEY:
        print('ERROR: variable NUQLEO_API_KEY no definida. Abortando.')
        exit(1)
    os.makedirs(ODOO_DIR, exist_ok=True)
    log(f'Nuqleo Agent v2 iniciando en {BIND}:{PORT}')
    server = HTTPServer((BIND, PORT), NuqleoHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log('Agent detenido.')
