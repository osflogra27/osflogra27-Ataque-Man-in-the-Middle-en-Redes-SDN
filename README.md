# Ataque Man-in-the-Middle en Redes SDN (GNS3 + Ryu)

**Implementación y Análisis de un Ataque Man-in-the-Middle en Entornos de Redes Definidas por Software (SDN): Interceptación, Modificación de Paquetes y Estrategias de Mitigación.**

Proyecto de la Especialización en Ciberseguridad. Implementa, analiza y mitiga un ataque MITM
(mediante **ARP Spoofing** e inyección de flujos OpenFlow maliciosos) en una red **SDN emulada con
GNS3**, controlada por **Ryu** y conmutada por **Open vSwitch**, usando **Scapy** y **Wireshark**.
El trabajo extiende el repositorio académico **SdnShare** (que ya incorpora módulos de ataque DDoS)
con una nueva capa orientada a ataques de intermediario.

> ⚠️ **Uso responsable.** Todo el material es exclusivamente para fines educativos y de investigación,
> dentro de un laboratorio virtualizado y aislado (GNS3 + VirtualBox). No debe utilizarse contra redes o
> sistemas sobre los que no se tenga autorización explícita.

---

## Plan del proyecto (4 semanas / 4 fases)

El proyecto se divide en cuatro fases (metodología experimental-cuantitativa), una **fase por semana**.
La meta es completar **una fase al 100% cada semana**.

| Fase | Semana | Objetivo | Estado |
|------|--------|----------|--------|
| **Fase 1** | Semana 1 | Preparación del entorno: GNS3 + VirtualBox, OVS, Ryu, topologías y línea base de tráfico | ✅ Completada |
| **Fase 2** | Semana 2 | Implementación del ataque MITM (ARP Spoofing con Scapy + inyección de flujos vía API REST de Ryu + interceptación/modificación) | ✅ Completada |
| **Fase 3** | Semana 3 | Recolección y análisis de evidencias (pcap, estadísticas de flujo, logs, IoC) | ⬜ Pendiente |
| **Fase 4** | Semana 4 | Simulación completa en GNS3 y evaluación de mecanismos de mitigación | ⬜ Pendiente |

Detalle completo en [`docs/PLAN_GENERAL.md`](docs/PLAN_GENERAL.md).

---

## Fase 1 — Preparación del entorno (esta entrega)

Esta fase deja listo un laboratorio SDN reproducible en GNS3:

- **Controlador Ryu** (learning switch OpenFlow 1.3) para la VM de control.
- **Open vSwitch (OVS)** configurado para conectarse al controlador por el canal OpenFlow.
- **Hosts Ubuntu Server** con direccionamiento IPv4 estático.
- **Tres escenarios de topología**: estrella, árbol y malla (ver [`docs/TOPOLOGIAS.md`](docs/TOPOLOGIAS.md)).
- **Scripts** para configurar cada componente y para capturar la **línea base de tráfico legítimo**.

Guía paso a paso y checklist de cierre en [`docs/FASE1.md`](docs/FASE1.md).

### Arquitectura (resumen)

```
   Plano de datos (10.0.0.0/24)              Plano de control (192.168.100.0/24)
   ───────────────────────────              ──────────────────────────────────
   h1  10.0.0.11  (víctima A)
   h2  10.0.0.12  (víctima B/servidor)  ── [ Open vSwitch ] ──OpenFlow 1.3── [ Ryu  192.168.100.10 ]
   h3  10.0.0.66  (atacante, Fase 2)
```

## Montaje paso a paso (5 VMs en GNS3 + VirtualBox)

El laboratorio usa **5 VMs Ubuntu Server 22.04**: `ryu`, `ovs`, `h1`, `h2`, `h3`.
Lo más práctico es instalar Ubuntu Server **una vez** (ISO de
[ubuntu.com/download/server](https://ubuntu.com/download/server) — **no** la "cloud image"),
crear tu usuario/contraseña durante la instalación, y luego **clonar** la VM 5 veces en VirtualBox
(marcando "Generar nuevas direcciones MAC para todos los adaptadores").

### Paso 0 — Traer el proyecto a cada VM
En cada VM, clona el repositorio y entra en la carpeta:
```bash
git clone <URL-del-repo> ~/proyecto-mitm
cd ~/proyecto-mitm
chmod +x scripts/*.sh ovs/*.sh hosts/*.sh attack/*.sh attack/*.py controller/*.py
```

### Paso 1 — Instalar dependencias por rol

**VM `ryu` (controlador).** Ryu 4.34 NO compila/corre con Python 3.10 (Ubuntu 22.04) ni con
setuptools/eventlet modernos. La forma fiable es un **entorno virtual con Python 3.9**:
```bash
sudo apt-get update
sudo apt-get install -y software-properties-common
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt-get update
sudo apt-get install -y python3.9 python3.9-venv python3.9-dev

python3.9 -m venv ~/ryu-venv
source ~/ryu-venv/bin/activate
pip install --upgrade "pip<21" "setuptools==58.2.0" wheel
pip install "eventlet==0.30.2" "ryu==4.34" requests
ryu-manager --version        # debe imprimir "ryu-manager 4.34"
```
> Recuerda: en la VM `ryu`, **activa el venv antes de arrancar el controlador** en cada sesión:
> `source ~/ryu-venv/bin/activate`

**VM `ovs` (switch):**
```bash
sudo ./scripts/setup_env.sh ovs
```

**VMs `h1` y `h2` (víctimas):**
```bash
sudo ./scripts/setup_env.sh host
```

**VM `h3` (atacante).** `netfilterqueue` se compila desde C y necesita las cabeceras de
netfilter; instálalas ANTES o el `pip install` falla con
`fatal error: libnfnetlink/linux_nfnetlink.h: No such file or directory`:
```bash
sudo ./scripts/setup_env.sh host
sudo apt-get install -y build-essential python3-dev libnetfilter-queue-dev libnfnetlink-dev curl netcat
pip3 install netfilterqueue requests
python3 -c "import netfilterqueue; print('netfilterqueue OK')"   # verificar
```

Qué instala cada rol:

| VM | Comando | Instala |
|----|---------|---------|
| `ryu` | venv Python 3.9 + `pip install ryu==4.34 ...` | Ryu, eventlet, requests |
| `ovs` | `setup_env.sh ovs` | Open vSwitch |
| `h1`, `h2` | `setup_env.sh host` | Scapy, tshark, tcpdump |
| `h3` | `setup_env.sh host` + extras | + netfilterqueue, requests, curl, netcat |

### Paso 2 — Arrancar y configurar (orden recomendado)
```bash
# VM ryu  (¡activa el venv primero!)
source ~/ryu-venv/bin/activate
REST=1 ./scripts/run_controller.sh        # OpenFlow 1.3 :6653 + API REST :8080

# VM ovs  (edita CONTROLLER_IP y DATA_IFACES en ovs/setup_ovs.sh si hace falta)
sudo ./ovs/setup_ovs.sh

# VMs host: asignar IPv4 según el rol
sudo ./hosts/config_host.sh h1            # 10.0.0.11
sudo ./hosts/config_host.sh h2            # 10.0.0.12
sudo ./hosts/config_host.sh h3            # 10.0.0.66 (activa ip_forward)

# Línea base de tráfico legítimo (en un host o en la VM ovs)
sudo ./scripts/baseline_capture.sh eth0 60
```

### Paso 3 — Validar la Fase 1
```bash
# en h1: conectividad con h2
ping -c 3 10.0.0.12
# en la VM ovs: flujos instalados por el controlador
sudo ovs-ofctl -O OpenFlow13 dump-flows br0
```
Toma una **snapshot** en GNS3. Con esto la Fase 1 queda montada.
(El detalle del ataque MITM — Fase 2 — está en [`docs/FASE2.md`](docs/FASE2.md).)

---

## Estructura del repositorio

```
.
├── README.md
├── LICENSE
├── requirements.txt
├── .gitignore
├── controller/
│   └── simple_switch_13.py      # Controlador Ryu (learning switch OpenFlow 1.3)
├── ovs/
│   └── setup_ovs.sh             # Configura Open vSwitch y lo conecta a Ryu
├── hosts/
│   └── config_host.sh           # Direccionamiento IPv4 estático de los hosts
├── attack/                      # Fase 2: módulo de ataque MITM
│   ├── arp_spoof.py             # ARP Spoofing (Scapy) desde el atacante
│   ├── flow_inject.py           # Inyección de flujos OpenFlow vía API REST de Ryu
│   ├── mitm_intercept.py        # Interceptación/modificación de paquetes
│   ├── demo_traffic.sh          # Genera tráfico de prueba (ICMP/TCP/HTTP)
│   └── verify_mitm.sh           # Verifica que el MITM esté activo
├── scripts/
│   ├── setup_env.sh             # Instala dependencias según el rol de la VM
│   ├── run_controller.sh        # Arranca el controlador Ryu
│   └── baseline_capture.sh      # Captura la línea base de tráfico (pcap)
├── captures/                    # Capturas .pcap (ignoradas por git)
└── docs/
    ├── PLAN_GENERAL.md          # Plan de las 4 fases (OE1–OE5)
    ├── FASE1.md                 # Documentación detallada de la Fase 1
    ├── FASE2.md                 # Documentación detallada de la Fase 2
    ├── TOPOLOGIAS.md            # Topologías estrella / árbol / malla + direccionamiento
    └── Anteproyecto_MITM_SDN.pdf
```

---

## Herramientas

- **[GNS3](https://www.gns3.com/)** + **VirtualBox** — emulación de red con VMs reales.
- **[Ryu](https://ryu-sdn.org/)** — controlador SDN en Python (API REST en Fase 2).
- **[Open vSwitch](https://www.openvswitch.org/)** — switch OpenFlow.
- **[Scapy](https://scapy.net/)** — construcción/inyección de paquetes (Fase 2).
- **[Wireshark](https://www.wireshark.org/) / tcpdump** — captura y análisis de tráfico.

---

## Bitácora de avance

- **Fase 1 — Semana 1:** entorno GNS3 + SDN configurado y línea base capturada. ✅
- **Fase 2 — Semana 2:** ataque MITM implementado — ARP Spoofing, inyección de flujos e interceptación/modificación. ✅
- Fase 3 — Semana 3: _pendiente._
- Fase 4 — Semana 4: _pendiente._

> Este README se irá actualizando a medida que avancemos en cada fase.
