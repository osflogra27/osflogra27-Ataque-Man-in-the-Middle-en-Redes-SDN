#!/usr/bin/env bash
#
# setup_env.sh - Instala las dependencias del laboratorio segun el rol de la VM.
#
# Fase 1. Ejecutar como root en cada VM (Ubuntu Server 22.04) dentro de GNS3:
#     sudo ./scripts/setup_env.sh controller   # VM con Ryu
#     sudo ./scripts/setup_env.sh ovs          # VM con Open vSwitch
#     sudo ./scripts/setup_env.sh host         # VMs host (incluye atacante)
#     sudo ./scripts/setup_env.sh all          # instala todo (PC de pruebas)
#
set -euo pipefail

ROLE="${1:-all}"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Ejecuta como root: sudo $0 ${ROLE}" >&2
    exit 1
fi

echo "==> Actualizando indices de paquetes"
apt-get update

base_tools() {
    apt-get install -y python3 python3-pip iproute2 iputils-ping tcpdump
}

install_controller() {
    echo "==> [controller] Instalando Ryu"
    base_tools
    pip3 install --upgrade pip
    pip3 install ryu==4.34 eventlet==0.30.2 requests
}

install_ovs() {
    echo "==> [ovs] Instalando Open vSwitch"
    base_tools
    apt-get install -y openvswitch-switch openvswitch-common
    systemctl enable --now openvswitch-switch || service openvswitch-switch start || true
}

install_host() {
    echo "==> [host] Instalando Scapy y utilidades de captura"
    base_tools
    apt-get install -y tshark
    pip3 install --upgrade pip
    pip3 install "scapy>=2.5.0"
}

case "${ROLE}" in
    controller) install_controller ;;
    ovs)        install_ovs ;;
    host)       install_host ;;
    all)        install_controller; install_ovs; install_host ;;
    *) echo "Rol invalido: ${ROLE} (usa: controller|ovs|host|all)" >&2; exit 1 ;;
esac

echo ""
echo "==> Comprobacion:"
command -v ryu-manager >/dev/null 2>&1 && echo "    ryu-manager: OK" || true
command -v ovs-vsctl   >/dev/null 2>&1 && echo "    ovs-vsctl:   OK" || true
python3 -c "import scapy; print('    scapy:', scapy.__version__)" 2>/dev/null || true

echo "==> Listo (rol: ${ROLE})."
