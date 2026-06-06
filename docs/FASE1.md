# Fase 1 — Preparación del entorno

> Semana 1 del proyecto. Metodología, sección 9 — "Fase 1: Preparación del Entorno".

## 1. Objetivo

Montar un laboratorio SDN **reproducible y aislado** en **GNS3 + VirtualBox** que sirva de base para las
fases siguientes (ataque, evidencias y mitigación). El entorno combina:

- **SDN**: un **Open vSwitch (OVS)** controlado por **Ryu** vía OpenFlow 1.3.
- **Hosts reales**: VMs Ubuntu Server 22.04 con direccionamiento IPv4 estático.
- **Tres topologías**: estrella, árbol y malla (ver `docs/TOPOLOGIAS.md`).
- **Línea base**: snapshot de GNS3 + captura de tráfico legítimo (`.pcap`).

## 2. Arquitectura

```
   Plano de datos (10.0.0.0/24)              Plano de control (192.168.100.0/24)
   h1 10.0.0.11 (víctima A)
   h2 10.0.0.12 (víctima B)   ── [ Open vSwitch br0 ] ──OpenFlow 1.3──→ [ Ryu 192.168.100.10 ]
   h3 10.0.0.66 (atacante)
```

- El **OVS** no tiene lógica propia: depende del controlador (fail-mode `secure`).
- **Ryu** ejecuta un *learning switch* (`controller/simple_switch_13.py`) y, opcionalmente, la API REST
  (`ofctl_rest`) que se usará en la Fase 2.
- Los hosts se comunican por IPv4; el tráfico **ARP** que circula es la superficie de ataque de la Fase 2.

## 3. Componentes entregados

| Archivo | Rol / VM | Descripción |
|---------|----------|-------------|
| `controller/simple_switch_13.py` | Ryu | Learning switch L2 (OpenFlow 1.3). |
| `ovs/setup_ovs.sh` | OVS | Crea `br0`, fuerza OF1.3, agrega puertos y apunta a Ryu. |
| `hosts/config_host.sh` | Hosts | Asigna IPv4 estática según el rol (h1/h2/h3). |
| `scripts/setup_env.sh` | Todas | Instala dependencias según rol (controller/ovs/host). |
| `scripts/run_controller.sh` | Ryu | Arranca Ryu (con `REST=1` añade la API REST). |
| `scripts/baseline_capture.sh` | Host/OVS | Captura la línea base de tráfico legítimo (`.pcap`). |
| `docs/TOPOLOGIAS.md` | — | Topologías estrella/árbol/malla + direccionamiento. |

## 4. Requisitos previos

- PC con virtualización: 4+ núcleos, 16 GB RAM, 100 GB disco (según el anteproyecto).
- **GNS3** + **VirtualBox** instalados en el equipo anfitrión.
- Imagen base **Ubuntu Server 22.04** para las VMs (host, OVS y controlador).

## 5. Pasos

### 5.1 Crear el proyecto en GNS3
1. Instalar GNS3 y VirtualBox; configurar VirtualBox como motor de VMs en GNS3.
2. Importar/clonar la imagen Ubuntu Server 22.04 para: 3 hosts (h1, h2, h3), 1 VM OVS y 1 VM Ryu.
3. Cablear el **escenario estrella** (base): los 3 hosts al OVS; el OVS al Ryu por el segmento de control.

### 5.2 Instalar dependencias (en cada VM, según su rol)
```bash
sudo ./scripts/setup_env.sh ovs          # VM Open vSwitch
sudo ./scripts/setup_env.sh host         # cada VM host (incluye el atacante)
```

> **VM Ryu — nota importante.** Ryu 4.34 no funciona con Python 3.10 (Ubuntu 22.04) ni con
> setuptools/eventlet modernos (errores típicos: `get_script_args` al compilar, o
> `cannot set 'is_timeout' attribute of immutable type 'TimeoutError'` al arrancar).
> Instálalo en un **entorno virtual con Python 3.9**:
> ```bash
> sudo apt-get install -y software-properties-common
> sudo add-apt-repository -y ppa:deadsnakes/ppa
> sudo apt-get update
> sudo apt-get install -y python3.9 python3.9-venv python3.9-dev
> python3.9 -m venv ~/ryu-venv
> source ~/ryu-venv/bin/activate
> pip install --upgrade "pip<21" "setuptools==58.2.0" wheel
> pip install "eventlet==0.30.2" "ryu==4.34" requests
> ryu-manager --version
> ```

### 5.3 Arrancar el controlador (VM Ryu)
```bash
source ~/ryu-venv/bin/activate       # activar el venv en cada sesión
./scripts/run_controller.sh          # learning switch
# o, dejando lista la API REST para la Fase 2:
REST=1 ./scripts/run_controller.sh
```

### 5.4 Configurar el Open vSwitch (VM OVS)
Edita `DATA_IFACES` y `CONTROLLER_IP` en `ovs/setup_ovs.sh` según tu topología, luego:
```bash
sudo ./ovs/setup_ovs.sh
```

### 5.5 Configurar los hosts (cada VM host)
```bash
sudo ./hosts/config_host.sh h1     # 10.0.0.11
sudo ./hosts/config_host.sh h2     # 10.0.0.12
sudo ./hosts/config_host.sh h3     # 10.0.0.66 (atacante)
```

### 5.6 Línea base
1. Tomar una **snapshot** del proyecto en GNS3 (estado limpio reproducible).
2. Capturar tráfico legítimo (genera ping/curl entre h1 y h2 en paralelo):
```bash
sudo ./scripts/baseline_capture.sh eth0 60
```

## 6. Verificación / criterio de cierre

La Fase 1 está **completa al 100%** cuando:

1. El OVS aparece conectado a Ryu:
   - en la VM OVS: `ovs-vsctl get-controller br0` → `tcp:192.168.100.10:6653`
   - en el log de Ryu aparece `Switch conectado: dpid=...`
2. Hay conectividad IPv4 entre hosts: `h1$ ping -c 3 10.0.0.12` con 0% de pérdida.
3. Se ven flujos instalados por el controlador:
   `sudo ovs-ofctl -O OpenFlow13 dump-flows br0`
4. Existe la captura de línea base en `captures/baseline_*.pcap`.
5. Está tomada la snapshot de GNS3 de los tres escenarios (al menos el de estrella).

## 7. Notas

- Red `10.0.0.0/24` para datos y `192.168.100.0/24` para control (planos separados).
- El reenvío IPv4 (`ip_forward=1`) solo se activa en el atacante (h3); se usará en la Fase 2 para no
  romper la conectividad durante el MITM.
- Las capturas `.pcap` quedan en `captures/` y están **excluidas de git** (`.gitignore`).

## 8. Próximo paso

**Fase 2 — Implementación del ataque:** módulo de **ARP Spoofing** con Scapy desde h3, más **inyección de
flujos OpenFlow maliciosos** vía la API REST de Ryu, e interceptación/modificación de tráfico HTTP/ICMP/TCP.
