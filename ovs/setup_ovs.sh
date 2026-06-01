#!/usr/bin/env bash
#
# setup_ovs.sh - Configura Open vSwitch en su VM y lo conecta al controlador Ryu.
#
# Fase 1. Ejecutar como root en la VM de Open vSwitch dentro de GNS3:
#     sudo ./ovs/setup_ovs.sh
#
# Crea un puente OVS (br0), fuerza OpenFlow 1.3, agrega las interfaces de datos
# como puertos y apunta el controlador a la VM de Ryu.
#
set -euo pipefail

# ---- Parametros (ajusta segun tu topologia GNS3) ----
BRIDGE="br0"
CONTROLLER_IP="192.168.100.10"     # IP de la VM con Ryu
CONTROLLER_PORT="6653"
# Interfaces de datos del OVS conectadas a los hosts/enlaces en GNS3.
# Edita esta lista segun los adaptadores que tenga la VM (ip link show).
DATA_IFACES=("eth1" "eth2" "eth3")

if [[ "${EUID}" -ne 0 ]]; then
    echo "Ejecuta como root: sudo $0" >&2
    exit 1
fi

if ! command -v ovs-vsctl >/dev/null 2>&1; then
    echo "Open vSwitch no encontrado. Ejecuta primero: sudo ./scripts/setup_env.sh" >&2
    exit 1
fi

echo "==> Asegurando que el servicio de Open vSwitch este activo"
systemctl enable --now openvswitch-switch 2>/dev/null || service openvswitch-switch start || true

echo "==> Creando el puente ${BRIDGE} (si no existe)"
ovs-vsctl --may-exist add-br "${BRIDGE}"

echo "==> Forzando OpenFlow 1.3 en ${BRIDGE}"
ovs-vsctl set bridge "${BRIDGE}" protocols=OpenFlow13

echo "==> Agregando interfaces de datos como puertos del puente"
for ifc in "${DATA_IFACES[@]}"; do
    if ip link show "${ifc}" >/dev/null 2>&1; then
        ovs-vsctl --may-exist add-port "${BRIDGE}" "${ifc}"
        ip link set dev "${ifc}" up
        echo "    + ${ifc}"
    else
        echo "    ! ${ifc} no existe en esta VM, se omite"
    fi
done

echo "==> Apuntando el controlador a tcp:${CONTROLLER_IP}:${CONTROLLER_PORT}"
ovs-vsctl set-controller "${BRIDGE}" "tcp:${CONTROLLER_IP}:${CONTROLLER_PORT}"
# fail-mode secure: sin controlador, el switch NO reenvia (util para el lab)
ovs-vsctl set-fail-mode "${BRIDGE}" secure

echo ""
echo "==> Estado actual del OVS:"
ovs-vsctl show
echo ""
echo "==> Verifica la conexion con el controlador:"
echo "    ovs-vsctl get-controller ${BRIDGE}"
echo "    ovs-ofctl -O OpenFlow13 dump-flows ${BRIDGE}"
