#!/bin/bash
# === NUQLEO VPS SETUP ===
# Uso: bash nuqleo-setup.sh TOKEN_AQUI

TOKEN="${1:-}"
if [ -z "$TOKEN" ]; then
  echo "❌ Falta el token. Uso: bash nuqleo-setup.sh TOKEN_AQUI"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
echo "▶ Instalando dependencias..."
apt-get update -qq && apt-get install -y python3 docker.io docker-compose-v2 curl openssl nginx certbot > /dev/null 2>&1
systemctl enable --now docker
# docker-compose-v2 trae el plugin `docker compose` (el docker.io de Ubuntu NO lo incluye).
# Sin él, el agente falla al levantar el contenedor: "unknown shorthand flag: 'd' in -d".
# nginx + certbot para dominios con SSL automático por cliente (reverse proxy).
# Quitamos el sitio default para que no capture los server_name de los clientes.
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
mkdir -p /var/www/certbot
systemctl enable --now nginx 2>/dev/null || true
# Abrir 80/443 si hay ufw activo (necesario para el challenge ACME y el tráfico).
if command -v ufw >/dev/null 2>&1; then ufw allow 80/tcp >/dev/null 2>&1 || true; ufw allow 443/tcp >/dev/null 2>&1 || true; fi

echo "▶ Instalando agente..."
mkdir -p /opt/nuqleo-agent
curl -fsSL "https://raw.githubusercontent.com/wiiitman/agente/main/nuqleo-agent.py" \
    -o /opt/nuqleo-agent/nuqleo-agent.py
chmod 755 /opt/nuqleo-agent/nuqleo-agent.py

API=$(openssl rand -hex 32)
printf "NUQLEO_API_KEY=%s\nNUQLEO_PORT=9876\nNUQLEO_BIND=0.0.0.0\nNUQLEO_WORDPRESS_URL=https://nuqleo.app\nNUQLEO_PG_PASS=nuqleo_pg_2024\n" "$API" > /etc/nuqleo-agent.env
# Librería de módulos custom (repo privado). NO se hardcodea el token aquí (este
# script es público en GitHub): se pasa por variables de entorno al ejecutar, ej:
#   NUQLEO_MODULES_REPO=github.com/wiiitman/nuqleo_odoos.git \
#   NUQLEO_MODULES_TOKEN=ghp_xxx  bash nuqleo-setup.sh TOKEN
if [ -n "${NUQLEO_MODULES_REPO:-}" ]; then
  printf "NUQLEO_MODULES_REPO=%s\nNUQLEO_MODULES_TOKEN=%s\n" \
    "$NUQLEO_MODULES_REPO" "${NUQLEO_MODULES_TOKEN:-}" >> /etc/nuqleo-agent.env
fi
chmod 600 /etc/nuqleo-agent.env

cat > /etc/systemd/system/nuqleo-agent.service << 'SVCEOF'
[Unit]
Description=Nuqleo Agent
After=docker.service network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/nuqleo-agent
EnvironmentFile=/etc/nuqleo-agent.env
ExecStart=/usr/bin/python3 /opt/nuqleo-agent/nuqleo-agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload && systemctl enable nuqleo-agent && systemctl start nuqleo-agent
sleep 2

echo "▶ Registrando VPS..."
API_KEY=$(grep NUQLEO_API_KEY /etc/nuqleo-agent.env | cut -d= -f2)
MY_IP=$(hostname -I | awk '{print $1}')
MY_HOST=$(hostname)
curl -s -X POST "https://nuqleo.app/wp-json/nuqleo/v1/agent/register" \
  -H "Content-Type: application/json" \
  -d "{\"hostname\":\"$MY_HOST\",\"ip_address\":\"$MY_IP\",\"api_key\":\"$API_KEY\",\"agent_port\":9876,\"registration_key\":\"$TOKEN\"}"
echo ""

echo "▶ Levantando postgres compartido..."
docker network create nuqleo-net 2>/dev/null || true
docker run -d \
  --name nuqleo_postgres_shared \
  --network nuqleo-net \
  -e POSTGRES_PASSWORD=nuqleo_pg_2024 \
  -e POSTGRES_USER=postgres \
  -v /opt/nuqleo-pgdata:/var/lib/postgresql/data \
  --restart unless-stopped \
  postgres:15-alpine
sleep 6

docker exec nuqleo_postgres_shared psql -U postgres -c \
  "DO \$\$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='odoo') THEN CREATE ROLE odoo WITH LOGIN CREATEDB PASSWORD 'nuqleo_pg_2024'; END IF; END \$\$"

echo "▶ Descargando imágenes Docker (para cachear en el VPS)..."
# Los deploys de clientes solo usan Odoo 18 y 19 (17 quedó solo para desarrollo
# local, no se despliega). Así el VPS se aprovisiona más rápido y usa menos disco.
docker pull odoo:18
docker pull odoo:19
echo "✅ Imágenes descargadas"

# Inicializa un template Odoo y verifica que NO quede vacío.
# IMPORTANTE: la BD debe ser OWNER 'odoo' (no 'postgres'), si no el --init base
# falla silenciosamente por permisos y el template queda vacío → todo deploy que
# copie ese template arranca con "Database not initialized" → HTTP 500.
init_odoo_template() {
  local ver="$1"; local db="odoo${ver}_template"
  echo "▶ Creando template Odoo ${ver} (~3 min)..."
  docker exec nuqleo_postgres_shared psql -U postgres -c "CREATE DATABASE ${db} OWNER odoo" 2>/dev/null || true
  # Garantizar dueño correcto aunque la BD ya existiera de un intento previo
  docker exec nuqleo_postgres_shared psql -U postgres -c \
    "UPDATE pg_database SET datistemplate=false, datallowconn=true WHERE datname='${db}'"
  docker exec nuqleo_postgres_shared psql -U postgres -c "ALTER DATABASE ${db} OWNER TO odoo"
  docker run --rm --network nuqleo-net \
    -e HOST=nuqleo_postgres_shared -e USER=odoo -e PASSWORD=nuqleo_pg_2024 \
    odoo:${ver} -- -d ${db} -i base --stop-after-init --no-http
  # Verificar que se inicializó de verdad
  local mods
  mods=$(docker exec nuqleo_postgres_shared psql -U postgres -d ${db} -tAc "SELECT count(*) FROM ir_module_module" 2>/dev/null || echo 0)
  if [ "${mods:-0}" -lt 1 ]; then
    echo "❌ ERROR: template ${db} quedó vacío (init falló). Revisa el rol 'odoo' y permisos."
    exit 1
  fi
  docker exec nuqleo_postgres_shared psql -U postgres -c \
    "UPDATE pg_database SET datistemplate=true, datallowconn=false WHERE datname='${db}'"
  echo "✅ Template Odoo ${ver} listo (${mods} módulos)"
}

init_odoo_template 18
init_odoo_template 19

echo ""
echo "✅ VPS listo. Verifica en nuqleo.app/wp-admin"
