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
| **Fase 1** | Semana 1 | Preparación del entorno: GNS3 + VirtualBox, OVS, Ryu, topologías y línea base de tráfico | ✅ En curso |
| **Fase 2** | Semana 2 | Implementación del ataque MITM (ARP Spoofing con Scapy + inyección de flujos vía API REST de Ryu) | ⬜ Pendiente |
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

### Puesta en marcha (dentro de las VMs de GNS3)

```bash
# En todas las VMs (según rol): instalar dependencias
sudo ./scripts/setup_env.sh

# VM Controlador (Ryu)
./scripts/run_controller.sh

# VM Open vSwitch
sudo ./ovs/setup_ovs.sh

# En cada VM host (ajustando el rol)
sudo ./hosts/config_host.sh h1

# Capturar la línea base de tráfico legítimo (1 min)
sudo ./scripts/baseline_capture.sh h1-eth0 60
```

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
├── scripts/
│   ├── setup_env.sh             # Instala dependencias según el rol de la VM
│   ├── run_controller.sh        # Arranca el controlador Ryu
│   └── baseline_capture.sh      # Captura la línea base de tráfico (pcap)
├── captures/                    # Capturas .pcap (ignoradas por git)
└── docs/
    ├── PLAN_GENERAL.md          # Plan de las 4 fases (OE1–OE5)
    ├── FASE1.md                 # Documentación detallada de la Fase 1
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

- **Fase 1 — Semana 1:** entorno GNS3 + SDN configurado y línea base capturada. _(esta entrega)_
- Fase 2 — Semana 2: _pendiente._
- Fase 3 — Semana 3: _pendiente._
- Fase 4 — Semana 4: _pendiente._

> Este README se irá actualizando a medida que avancemos en cada fase.
