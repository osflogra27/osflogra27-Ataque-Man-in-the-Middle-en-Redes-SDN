# Plan general del proyecto

**Título:** Implementación y Análisis de un Ataque Man-in-the-Middle en Entornos de Redes Definidas por
Software (SDN): Interceptación, Modificación de Paquetes y Estrategias de Mitigación.

**Objetivo general:** Implementar, analizar y mitigar un ataque Man-in-the-Middle en una red SDN emulada
con **GNS3** y controlada por **Ryu**, generando un framework reproducible de simulación, recolección de
evidencias y contramedidas activas.

**Herramientas:** GNS3, VirtualBox, Ryu, Open vSwitch, Scapy, Wireshark/tcpdump. Base: repositorio
académico **SdnShare** (extiende sus módulos de DDoS con una capa MITM).

El proyecto se ejecuta en **4 semanas**, una **fase por semana** (metodología experimental-cuantitativa).

---

## Objetivos específicos (del anteproyecto)

- **OE1.** Diseñar e implementar el módulo de ataque MITM (ARP Spoofing + inyección de flujos OpenFlow maliciosos mediante Scapy y la API REST de Ryu).
- **OE2.** Definir y ejecutar un protocolo de recolección de evidencias (pcap, estadísticas de flujo vía API del controlador, logs estructurados).
- **OE3.** Implementar al menos dos mecanismos de mitigación activa: (a) detección de ARP Spoofing por inspección de tablas ARP en el controlador y (b) detección de anomalías estadísticas en contadores de flujo OpenFlow.
- **OE4.** Evaluar la eficacia de la mitigación con métricas (TP, FP, tiempo de detección y de respuesta).
- **OE5.** Documentar vulnerabilidades, IoC y buenas prácticas de aseguramiento para SDN en producción.

---

## Fase 1 — Semana 1
### Preparación del entorno

Instalar y configurar GNS3 sobre VirtualBox. Diseñar la topología con VMs Linux (Ubuntu Server 22.04)
como hosts, un **Open vSwitch (OVS)** en una VM dedicada y el controlador **Ryu** en otra VM, conectados
por el canal de control OpenFlow. Definir los escenarios de topología (**estrella, árbol y malla**), tomar una
**snapshot** como línea base del proyecto GNS3 y capturar **métricas de tráfico legítimo** con Wireshark.

**Entregables:** controlador Ryu, configuración de OVS, configuración de hosts, scripts de instalación y de
captura de línea base, documentación de topologías y checklist de validación (`docs/FASE1.md`).

**Criterio de cierre:** OVS conectado a Ryu, conectividad IPv4 entre hosts y `baseline.pcap` capturado.

---

## Fase 2 — Semana 2
### Implementación del ataque

Desarrollar en Python (**Scapy**) el módulo de **ARP Spoofing** ejecutado desde la VM atacante,
posicionándose entre dos hosts. Complementariamente, implementar la **inyección de entradas de flujo
maliciosas** en la tabla OpenFlow del OVS mediante la **API REST de Ryu**. Validar la interceptación y
modificación de paquetes HTTP, ICMP y TCP antes de su reenvío.

**Entregables previstos:** módulo de ataque (ARP Spoofing + inyección de flujos), evidencia de
interceptación/modificación de tráfico.

---

## Fase 3 — Semana 3
### Recolección y análisis de evidencias

Ejecutar el protocolo de recolección: captura con tcpdump/Wireshark en la VM atacante, extracción
periódica de estadísticas de flujo vía API REST de Ryu y correlación de eventos en un log unificado.
Identificar los **indicadores de compromiso (IoC)** más discriminantes del MITM frente al tráfico legítimo.

**Entregables previstos:** capturas `.pcap` anotadas, logs de flujo, catálogo de IoC, informe de análisis.

---

## Fase 4 — Semana 4
### Simulación completa y evaluación de mitigación

Ejecutar el escenario completo en GNS3 con todas las VMs activas, integrando ataque, recolección y
mitigación. Implementar en Ryu los módulos de **detección (inspección de tablas ARP y análisis estadístico
de contadores de flujo)** y evaluar métricas de eficacia: tasa de verdaderos positivos, falsos positivos,
tiempo de detección y tiempo de respuesta.

**Entregables previstos:** módulos de mitigación, métricas de eficacia, informe técnico final.

---

## Calendario (cronograma del anteproyecto)

| Semana | Fase | Resultado esperado |
|--------|------|--------------------|
| 1 | Fase 1 | Entorno GNS3 + SDN funcional y línea base de tráfico |
| 2 | Fase 2 | Ataque MITM reproducible (ARP Spoofing + inyección de flujos) |
| 3 | Fase 3 | Evidencias y catálogo de IoC documentados |
| 4 | Fase 4 | Mitigación implementada, métricas e informe final |
