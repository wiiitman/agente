#!/bin/bash
# =============================================================
#  Nuqleo Agent — Instalación manual
#  1. Descarga este archivo al VPS (FileZilla o wget)
#  2. Ve a WordPress Admin → Nuqleo AI → Servidores → "Generar token"
#  3. Pega el token en REGISTRATION_KEY abajo
#  4. Ejecuta: bash install.sh
# =============================================================

REGISTRATION_KEY="PEGA_AQUI_EL_TOKEN"   # <── obtenerlo en WP Admin → Nuqleo AI → Servidores
WORDPRESS_URL="https://nuqleo.app"

# ─────────────────────────────────────────────────────────────
# NO MODIFICAR NADA DEBAJO DE ESTA LÍNEA
# ─────────────────────────────────────────────────────────────

AGENT_DIR="/opt/nuqleo-agent"
AGENT_PORT=9876
API_KEY=$(openssl rand -hex 32)
PG_PASS=$(openssl rand -hex 24)

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║       Nuqleo Agent — Instalación         ║"
echo "╚══════════════════════════════════════════╝"
echo "  Servidor : $(hostname) / $(hostname -I | awk '{print $1}')"
echo "  WordPress: $WORDPRESS_URL"
echo ""

if [ "$REGISTRATION_KEY" = "PEGA_AQUI_EL_TOKEN" ]; then
    echo "❌ ERROR: Debes pegar el token de registro en REGISTRATION_KEY"
    echo "   Ve a WordPress Admin → Nuqleo AI → Servidores → 'Generar token'"
    exit 1
fi

# ── 1. Dependencias ───────────────────────────────────────────
echo "[1/6] Instalando dependencias..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y python3 docker.io curl openssl 2>&1 | tail -3
systemctl enable --now docker 2>/dev/null || true
echo "      OK"

# ── 2. Descargar agente desde WordPress ──────────────────────
echo "[2/6] Descargando nuqleo-agent.py..."
mkdir -p "$AGENT_DIR"
curl -fsSL "${WORDPRESS_URL}/wp-content/plugins/plugin-nuqleo/agent/nuqleo-agent.py" \
    -o "${AGENT_DIR}/nuqleo-agent.py" || {
    echo "❌ No se pudo descargar el agente desde WordPress."
    echo "   Verifica que el plugin esté activo en WordPress."
    exit 1
}
chmod 755 "${AGENT_DIR}/nuqleo-agent.py"
echo "      OK — $(wc -l < ${AGENT_DIR}/nuqleo-agent.py) líneas"

# ── 3. Archivo de entorno ─────────────────────────────────────
echo "[3/6] Creando archivo de entorno..."
printf 'NUQLEO_API_KEY=%s\nNUQLEO_PORT=%s\nNUQLEO_BIND=0.0.0.0\nNUQLEO_WORDPRESS_URL=%s\nNUQLEO_PG_PASS=%s\n' \
    "$API_KEY" "$AGENT_PORT" "$WORDPRESS_URL" "$PG_PASS" > /etc/nuqleo-agent.env
chmod 600 /etc/nuqleo-agent.env
echo "      OK — API key guardada en /etc/nuqleo-agent.env"

# ── 4. Servicio systemd ───────────────────────────────────────
echo "[4/6] Configurando servicio systemd..."
cat > /etc/systemd/system/nuqleo-agent.service <<EOF
[Unit]
Description=Nuqleo VPS Agent
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=${AGENT_DIR}
EnvironmentFile=/etc/nuqleo-agent.env
ExecStart=/usr/bin/python3 ${AGENT_DIR}/nuqleo-agent.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable nuqleo-agent
systemctl restart nuqleo-agent
echo "      OK — servicio iniciado"

# ── 5. Verificar que el agente responde ───────────────────────
echo "[5/6] Verificando agente (espera 8s)..."
sleep 8

if curl -s --max-time 3 "http://localhost:${AGENT_PORT}/ping" > /dev/null 2>&1; then
    echo "      ✅ Agente responde en localhost:${AGENT_PORT}"
else
    echo "      ⚠  Agente no responde. Logs:"
    journalctl -u nuqleo-agent -n 25 --no-pager
    echo ""
    echo "  Continuando con el registro de todas formas..."
fi

# ── 6. Registrar en WordPress ─────────────────────────────────
echo "[6/6] Registrando en WordPress..."
MY_IP=$(hostname -I | awk '{print $1}')
MY_HOST=$(hostname)

RESPONSE=$(curl -s -w '\n%{http_code}' -X POST \
    "${WORDPRESS_URL}/wp-json/nuqleo/v1/agent/register" \
    -H 'Content-Type: application/json' \
    -d "{\"hostname\":\"${MY_HOST}\",\"ip_address\":\"${MY_IP}\",\"api_key\":\"${API_KEY}\",\"agent_port\":${AGENT_PORT},\"registration_key\":\"${REGISTRATION_KEY}\"}")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -1)

echo ""
echo "  HTTP $HTTP_CODE"
echo "  Respuesta: $BODY"
echo ""

if echo "$BODY" | grep -q '"success":true'; then
    echo "╔══════════════════════════════════════════╗"
    echo "║  ✅  INSTALACIÓN COMPLETADA              ║"
    echo "╚══════════════════════════════════════════╝"
    echo ""
    echo "  El servidor ya aparece en:"
    echo "  · ${WORDPRESS_URL}/wp-admin → Nuqleo AI → Servidores"
    echo "  · /plataforma → Nuevo Deploy → Selector de servidor"
    echo ""
    echo "  Ver logs: journalctl -u nuqleo-agent -f"
else
    echo "╔══════════════════════════════════════════╗"
    echo "║  ⚠   Agente instalado — fallo registro  ║"
    echo "╚══════════════════════════════════════════╝"
    echo ""
    echo "  Causa más probable: token expirado (válido 1 hora)."
    echo "  Genera uno nuevo en WP Admin → Nuqleo AI → Servidores"
    echo "  y corre este curl directamente en el VPS:"
    echo ""
    echo "  curl -X POST '${WORDPRESS_URL}/wp-json/nuqleo/v1/agent/register' \\"
    echo "    -H 'Content-Type: application/json' \\"
    echo "    -d '{\"hostname\":\"${MY_HOST}\",\"ip_address\":\"${MY_IP}\",\"api_key\":\"${API_KEY}\",\"agent_port\":${AGENT_PORT},\"registration_key\":\"NUEVO_TOKEN\"}'"
    echo ""
    echo "  API_KEY de este servidor (guárdala):"
    echo "  ${API_KEY}"
fi
echo ""
