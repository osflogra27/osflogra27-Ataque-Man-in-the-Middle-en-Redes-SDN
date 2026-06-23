# Fase 4 — Simulación completa y evaluación de mitigación

> Semana 4 del proyecto. Cubre los objetivos específicos **OE3** y **OE4**.
> **Estado: 🧪 En pruebas**

## 1. Objetivo

Integrar el módulo de mitigación activa con el entorno completo, ejecutar el escenario
end-to-end (ataque + detección + bloqueo) y medir la eficacia mediante métricas cuantitativas:

- **OE3:** Implementar detección de ARP Spoofing en el controlador Ryu y detección estadística de anomalías en contadores de flujo.
- **OE4:** Evaluar eficacia con métricas: True Positives (TP), False Positives (FP), tiempo de detección y tiempo de respuesta.

---

## 2. Componentes entregados

| Archivo | Descripción |
|---------|-------------|
| `mitigation/arp_monitor.py` | Controlador Ryu con detección y bloqueo activo de ARP Spoofing |
| `mitigation/flow_anomaly.py` | Detector estadístico de anomalías en flujos OpenFlow |
| `mitigation/run_mitigation.sh` | Script para iniciar Ryu en modo mitigación |
| `scripts/evaluate_mitigation.py` | Calcula TP, FP, tiempos y genera informe |

---

## 3. Arquitectura de mitigación

```
         ┌─────────────────────────────────────────────┐
         │  ryu  (arp_monitor.py)                      │
         │  ┌──────────────────────────────────────┐   │
         │  │ Tabla ARP confiable: {IP -> MAC}     │   │
         │  │ Si IP ya conocida y MAC cambia:      │   │
         │  │   -> ARP_SPOOFING_DETECTED            │   │
         │  │   -> Flujo DROP en OVS (prioridad 100)│   │
         │  │   -> Log en captures/mitigation_*.log│   │
         │  └──────────────────────────────────────┘   │
         │  API REST: /mitigation/stats              │   │
         └─────────────────────────────────────────────┘
                          │ OpenFlow 1.3
         ┌─────────────────────────────────────────────┐
         │  ovs  (br0)                                 │
         │  Puerto enp0s8 → h1, h2, h3                │
         │  Flujos DROP para MAC atacante              │
         └─────────────────────────────────────────────┘
```

---

## 4. Procedimiento

### Requisito previo

La Fase 1 debe estar operativa (OVS + conectividad). Ryu debe iniciarse con `arp_monitor.py`
en lugar de `simple_switch_13`.

---

### 4.1 Iniciar Ryu en modo mitigación (en ryu)

```bash
cd ~/proyecto-mitm
bash mitigation/run_mitigation.sh
```

O manualmente:
```bash
source ~/ryu-venv/bin/activate
ryu-manager --wsapi-port 8080 mitigation/arp_monitor.py ryu.app.ofctl_rest
```

Verificar que la API de mitigación responde:
```bash
curl -s http://192.168.100.10:8080/mitigation/stats | python3 -m json.tool
```

---

### 4.2 Configurar OVS (en ovs)

```bash
sudo systemctl start openvswitch-switch
sudo ovs-vsctl add-br br0 2>/dev/null || true
sudo ovs-vsctl add-port br0 enp0s8 2>/dev/null || true
sudo ovs-vsctl set-controller br0 tcp:192.168.100.10:6653
sudo ovs-vsctl show   # verificar is_connected: true
```

---

### 4.3 Lanzar el ataque MITM (en h3)

```bash
cd ~/proyecto-mitm
sudo sysctl -w net.ipv4.ip_forward=1
sudo python3 attack/arp_spoof.py --target 10.0.0.11 --gateway 10.0.0.12 --iface enp0s3
```

---

### 4.4 Observar la detección y bloqueo

En Ryu verás mensajes como:
```
WARNING:arp_monitor:ARP_SPOOFING_DETECTED — IP 10.0.0.12 cambio de MAC ...
WARNING:arp_monitor:*** BLOQUEO ACTIVO: MAC 08:00:27:xx:xx:xx bloqueada ***
```

Verificar flujos de bloqueo en OVS:
```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows br0
# Buscar: priority=100, actions=drop
```

Verificar tabla ARP en h1 (debe recuperarse):
```bash
ip neigh flush dev enp0s3
ping -c3 10.0.0.12
ip neigh show
# La MAC de 10.0.0.12 debe ser la MAC real de h2 otra vez
```

---

### 4.5 Detector de anomalías en flujos (en ryu o en ovs)

Mientras el ataque está activo:
```bash
python3 mitigation/flow_anomaly.py --controller 192.168.100.10 --interval 5 --duration 120 --report
```

---

### 4.6 Evaluación de métricas

```bash
# Desde log (post-ataque):
python3 scripts/evaluate_mitigation.py --log captures/mitigation_events.log --save

# En vivo (durante el ataque):
python3 scripts/evaluate_mitigation.py --live --controller 192.168.100.10 --save
```

---

## 5. Métricas objetivo

| Métrica | Valor esperado |
|---------|---------------|
| TP (ataques bloqueados) | ≥ 1 por sesión de ataque |
| FP (falsos positivos) | 0 (tráfico legítimo no debe bloquearse) |
| Tiempo de detección | < 5 s desde inicio del ARP Spoofing |
| Tiempo de respuesta | < 1 s desde detección hasta flujo DROP |
| Conectividad durante ataque | No se interrumpe (MITM transparente) |
| Conectividad después del bloqueo | h1 ↔ h2 se restaura automáticamente |

---

## 6. API REST de mitigación

Con `arp_monitor.py` corriendo, los siguientes endpoints están disponibles:

```bash
# Ver todas las métricas y eventos recientes:
curl http://192.168.100.10:8080/mitigation/stats

# Ver tabla ARP de confianza:
curl http://192.168.100.10:8080/mitigation/trusted_arp

# Ver MACs bloqueadas:
curl http://192.168.100.10:8080/mitigation/blocked

# Desbloquear una MAC manualmente:
curl -X DELETE http://192.168.100.10:8080/mitigation/unblock/08:00:27:xx:xx:xx

# Ver flujos OpenFlow actuales:
curl http://192.168.100.10:8080/stats/flow/1 | python3 -m json.tool
```

---

## 7. Criterio de cierre

La Fase 4 está **completa al 100%** cuando:

1. `arp_monitor.py` detecta el ARP Spoofing en < 5 s y genera evento `ARP_SPOOFING_DETECTED`.
2. OVS instala flujo DROP para la MAC atacante (visible en `dump-flows`).
3. `evaluate_mitigation.py` reporta TP ≥ 1 y FP = 0.
4. `captures/mitigation_events.log` documenta todos los eventos.
5. `captures/mitigation_evaluation_<ts>.json` contiene el informe de métricas.

---

## 8. Notas de implementación

- `arp_monitor.py` aprende MACs legítimas en los primeros paquetes ARP de cada sesión.
  Por esto, el ataque debe lanzarse **después** de que h1 y h2 hayan intercambiado al menos
  un ARP (basta con hacer `ping` una vez antes del ataque).
- El flujo DROP tiene `hard_timeout=300s` (5 minutos). Pasado ese tiempo, se puede volver
  a lanzar el ataque para nuevas pruebas, o eliminarlo manualmente con el endpoint `/mitigation/unblock`.
- `flow_anomaly.py` requiere que Ryu esté corriendo con `--wsapi-port 8080`. No modifica
  flujos por sí solo; solo detecta y alerta.

---

## 9. Vulnerabilidades identificadas y buenas prácticas (OE5)

| Vulnerabilidad | Descripción | Mitigación |
|---|---|---|
| ARP Spoofing | Protocolo ARP sin autenticación en L2 | Tabla ARP estática + detección en controlador SDN |
| Inyección de flujos | API REST de Ryu sin autenticación por defecto | Configurar TLS + autenticación en la API REST |
| Acceso al plano de control | Canal OpenFlow sin cifrar (TCP) | Usar TLS/DTLS en el canal OpenFlow |
| Packet flooding al controlador | Default flow envía todo al controlador | Rate limiting en OVS + flow aging |
| MITM en la interfaz de gestión | Misma red para control y datos | Separar plano de control en VLAN/red dedicada |
