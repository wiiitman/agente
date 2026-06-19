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
apt-get update -qq && apt-get install -y python3 docker.io curl openssl > /dev/null 2>&1
systemctl enable --now docker

echo "▶ Instalando agente..."
mkdir -p /opt/nuqleo-agent
curl -fsSL "https://raw.githubusercontent.com/wiiitman/agente/main/nuqleo-agent.py" \
    -o /opt/nuqleo-agent/nuqleo-agent.py
chmod 755 /opt/nuqleo-agent/nuqleo-agent.py

API=$(openssl rand -hex 32)
printf "NUQLEO_API_KEY=%s\nNUQLEO_PORT=9876\nNUQLEO_BIND=0.0.0.0\nNUQLEO_WORDPRESS_URL=https://nuqleo.app\nNUQLEO_PG_PASS=nuqleo_pg_2024\n" "$API" > /etc/nuqleo-agent.env
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

echo "▶ Creando template Odoo 17 (~3 min)..."
docker exec nuqleo_postgres_shared psql -U postgres -c "CREATE DATABASE odoo17_template OWNER odoo"
docker run --rm --network nuqleo-net \
  -e HOST=nuqleo_postgres_shared -e USER=odoo -e PASSWORD=nuqleo_pg_2024 \
  odoo:17 -- --database odoo17_template --init base --stop-after-init
docker exec nuqleo_postgres_shared psql -U postgres -c \
  "UPDATE pg_database SET datistemplate=true, datallowconn=false WHERE datname='odoo17_template'"
echo "✅ Template Odoo 17 listo"

echo "▶ Creando template Odoo 18 (~3 min)..."
docker exec nuqleo_postgres_shared psql -U postgres -c "CREATE DATABASE odoo18_template OWNER odoo"
docker run --rm --network nuqleo-net \
  -e HOST=nuqleo_postgres_shared -e USER=odoo -e PASSWORD=nuqleo_pg_2024 \
  odoo:18 -- --database odoo18_template --init base --stop-after-init
docker exec nuqleo_postgres_shared psql -U postgres -c \
  "UPDATE pg_database SET datistemplate=true, datallowconn=false WHERE datname='odoo18_template'"
echo "✅ Template Odoo 18 listo"

echo ""
echo "✅ VPS listo. Verifica en nuqleo.app/wp-admin"
