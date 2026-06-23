# Fase 3 — Recolección y análisis de evidencias

> Semana 3 del proyecto. Cubre el objetivo específico **OE2**.

## 1. Objetivo

Ejecutar el protocolo de recolección de evidencias sobre el ataque MITM de la Fase 2:

1. **Captura PCAP** del tráfico interceptado en la VM atacante (h3).
2. **Extracción de estadísticas de flujo** via API REST del controlador Ryu.
3. **Análisis automatizado de IoC** (Indicadores de Compromiso) sobre las capturas.
4. **Informe estructurado** que correlaciona evidencias y documenta los IoC del MITM.

---

## 2. Componentes entregados

| Archivo | Descripción |
|---------|-------------|
| `scripts/collect_evidence.sh` | Captura PCAP + log ARP en tiempo real desde h3 |
| `scripts/flow_stats.py` | Extrae estadísticas de flujo de Ryu vía REST API |
| `scripts/analyze_ioc.py` | Analiza PCAP buscando IoC del MITM (ARP Spoofing, floods, MAC changes) |
| `captures/` | Directorio donde se guardan todos los artefactos |

---

## 3. Protocolo de recolección

### Requisitos previos

- Fase 1 activa: OVS conectado a Ryu (`is_connected: true`)
- Fase 2 activa: ARP Spoofing corriendo en h3 (`attack/arp_spoof.py`)
- Ryu iniciado con API REST (`--wsapi-port 8080`)
- `scapy` y `requests` instalados en las VMs que los necesiten

---

### 3.1 Captura de tráfico MITM (en h3)

Mientras el ARP Spoofing está activo, capturar el tráfico que fluye por h3:

```bash
# En h3 (atacante) — como root:
cd ~/proyecto-mitm
sudo bash scripts/collect_evidence.sh enp0s3 120
```

El script captura durante 120 segundos y genera en `captures/`:
- `mitm_capture_<ts>.pcap` — captura completa
- `arp_events_<ts>.log` — log ARP con timestamps
- `evidence_summary_<ts>.txt` — resumen del evento

**Generar tráfico durante la captura** (en h1 y h2 en paralelo):
```bash
# En h2:
python3 -m http.server 8000

# En h1:
for i in $(seq 1 10); do
    ping -c5 10.0.0.12
    curl -s http://10.0.0.12:8000 -o /dev/null
    sleep 2
done
```

---

### 3.2 Extracción de estadísticas de flujo OpenFlow (en ryu o en ovs)

```bash
cd ~/proyecto-mitm

# Consulta única (snapshot):
python3 scripts/flow_stats.py --controller 192.168.100.10 --once

# Monitoreo continuo durante 2 minutos:
python3 scripts/flow_stats.py --controller 192.168.100.10 --interval 5 --duration 120
```

Genera en `captures/`:
- `flow_stats_<ts>.json` — estadísticas de flujo y IoC detectados

**IoC detectados automáticamente por `flow_stats.py`:**

| IoC | Descripción |
|-----|-------------|
| `FLUJO_MALICIOSO` | Cookie `0x6d69746d` — flujo inyectado por `flow_inject.py` |
| `DUPLICACION_TRAFICO` | Flujo con OUTPUT a múltiples puertos (intercepción) |
| `ALTA_TASA_PACKET_IN` | Flujo default con >500 paquetes (ARP flood hacia controlador) |

---

### 3.3 Análisis de IoC sobre PCAP (en cualquier VM con scapy)

```bash
cd ~/proyecto-mitm

# Análisis básico con reporte en consola:
python3 scripts/analyze_ioc.py captures/mitm_capture_<ts>.pcap

# Con exportación a JSON:
python3 scripts/analyze_ioc.py captures/mitm_capture_<ts>.pcap --report
```

**IoC detectados automáticamente por `analyze_ioc.py`:**

| IoC | Severidad | Descripción |
|-----|-----------|-------------|
| `ARP_SPOOFING` | ALTA | IP con múltiples MACs distintas en la misma captura |
| `MAC_CHANGE` | ALTA | Una IP cambia de MAC a lo largo del tiempo |
| `GRATUITOUS_ARP` | MEDIA | Respuesta ARP no solicitada (src_ip == dst_ip) |
| `ARP_FLOODING` | MEDIA | Tasa ARP > 3 pkt/s (normal < 1 pkt/s) |

---

## 4. Catálogo de IoC del MITM

### 4.1 Plano de datos (ARP / L2)

| # | IoC | Valor normal | Valor bajo ataque | Herramienta |
|---|-----|-------------|-------------------|-------------|
| 1 | Entradas ARP con MAC duplicada | Una MAC por IP | Misma MAC para varias IPs | `ip neigh`, analyze_ioc.py |
| 2 | Tasa de paquetes ARP | < 1 pkt/s | > 3 pkt/s durante ataque | analyze_ioc.py |
| 3 | Gratuitous ARP | Ausentes o mínimos | Periódicos (cada 2 s) | Wireshark / tcpdump |
| 4 | Cambio de MAC para una IP | Constante | Cambia con el ataque | analyze_ioc.py |

### 4.2 Plano de control (OpenFlow / Ryu)

| # | IoC | Valor normal | Valor bajo ataque | Herramienta |
|---|-----|-------------|-------------------|-------------|
| 5 | Tasa de packet_in | Baja (nuevos flujos) | Alta y sostenida (ARP loops) | flow_stats.py |
| 6 | Cookie de flujo | 0x0 (learning switch) | 0x6d69746d (inyección maliciosa) | flow_stats.py |
| 7 | Flujos con OUTPUT múltiple | Ausentes | Presentes (duplicación) | `ovs-ofctl dump-flows` |
| 8 | Entradas MAC en Ryu | Una MAC por IP | Múltiples MACs por IP (flap) | Logs de Ryu |

---

## 5. Verificación / criterio de cierre

La Fase 3 está **completa al 100%** cuando:

1. `captures/mitm_capture_<ts>.pcap` existe y contiene tráfico ARP anómalo.
2. `analyze_ioc.py` reporta al menos 1 IoC de severidad **ALTA** (`ARP_SPOOFING` o `MAC_CHANGE`).
3. `flow_stats.py` muestra el flujo default con `n_packets > 0` y detecta tasa elevada.
4. Los archivos `arp_events_<ts>.log` y `evidence_summary_<ts>.txt` están en `captures/`.
5. El informe JSON (`ioc_report_<ts>.json`) documenta todos los IoC encontrados.

---

## 6. Verificación rápida de IoC desde CLI

```bash
# Ver tabla ARP de h1 (debe mostrar MAC de h3 para la IP de h2):
ip neigh show

# Ver tráfico ARP en tiempo real (en h3 durante el ataque):
sudo tcpdump -i enp0s3 -n arp

# Ver flujos en OVS (buscar cookies maliciosas o múltiples outputs):
sudo ovs-ofctl -O OpenFlow13 dump-flows br0

# Consultar API REST de Ryu directamente:
curl -s http://192.168.100.10:8080/stats/flow/1 | python3 -m json.tool
```

---

## 7. Próximo paso

**Fase 4 — Mitigación:** implementar en Ryu detección activa de ARP Spoofing
(inspección de tablas ARP) y análisis estadístico de contadores de flujo para
bloquear el ataque y medir métricas de eficacia (TP, FP, tiempo de detección).
