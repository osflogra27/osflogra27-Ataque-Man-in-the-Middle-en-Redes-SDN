#!/usr/bin/env python3
"""
flow_anomaly.py - Detector de anomalias estadisticas en contadores de flujo OpenFlow (Fase 4).

Consulta periodicamente la API REST de Ryu y aplica deteccion estadistica:
  - Tasa de packet_in anormalmente alta (posible ARP flood o ataque)
  - Flujos con cookies maliciosas (inyeccion de flujos)
  - Desviacion estandar alta en contadores de paquetes por puerto
  - Flujos duplicados (mismo match, acciones diferentes)

Puede correr standalone o ser importado por arp_monitor.py.

Uso:
    python3 mitigation/flow_anomaly.py --controller 192.168.100.10 --interval 5 --duration 120
"""

import argparse
import json
import math
import os
import sys
import time
from datetime import datetime

try:
    import requests
except ImportError:
    print("[!] pip3 install requests")
    sys.exit(1)

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAPTURES_DIR = os.path.join(ROOT_DIR, "captures")
os.makedirs(CAPTURES_DIR, exist_ok=True)

# Umbrales configurables
PACKET_IN_RATE_THRESHOLD = 10.0   # pkt/s en flujo default -> alerta
PORT_STDDEV_THRESHOLD    = 500.0  # desviacion estandar en rx_packets entre puertos
MALICIOUS_COOKIE         = 0x6d69746d


class FlowAnomalyDetector:
    def __init__(self, base_url):
        self.base_url = base_url
        self.history  = []     # historial de snapshots
        self.alerts   = []     # alertas emitidas
        self.prev_snapshot = None

    def snapshot(self):
        """Toma un snapshot de todos los switches."""
        snap = {"ts": time.time(), "switches": {}}
        try:
            switches = requests.get(f"{self.base_url}/stats/switches", timeout=5).json()
        except Exception as e:
            print(f"[!] No se pudo conectar a Ryu: {e}")
            return None

        for dpid in switches:
            try:
                flows = requests.get(f"{self.base_url}/stats/flow/{dpid}", timeout=5).json().get(str(dpid), [])
                ports = requests.get(f"{self.base_url}/stats/port/{dpid}", timeout=5).json().get(str(dpid), [])
                snap["switches"][str(dpid)] = {"flows": flows, "ports": ports}
            except Exception:
                pass

        self.history.append(snap)
        if len(self.history) > 100:
            self.history.pop(0)
        return snap

    def analyze(self, snap):
        """Analiza un snapshot en busca de anomalias."""
        alerts = []
        ts = snap["ts"]

        for dpid, data in snap["switches"].items():
            flows = data.get("flows", [])
            ports = data.get("ports", [])

            # --- Anomalia 1: Tasa packet_in alta ---
            if self.prev_snapshot:
                prev_flows = self.prev_snapshot["switches"].get(dpid, {}).get("flows", [])
                dt = ts - self.prev_snapshot["ts"]
                if dt > 0:
                    for flow in flows:
                        if flow.get("priority", 0) == 0:  # flujo default
                            pkt_now = flow.get("packet_count", 0)
                            # buscar mismo flujo en snapshot anterior
                            for pf in prev_flows:
                                if pf.get("priority", 0) == 0:
                                    pkt_prev = pf.get("packet_count", 0)
                                    rate = (pkt_now - pkt_prev) / dt
                                    if rate > PACKET_IN_RATE_THRESHOLD:
                                        alerts.append({
                                            "tipo": "HIGH_PACKET_IN_RATE",
                                            "severidad": "ALTA",
                                            "dpid": dpid,
                                            "rate_pps": round(rate, 2),
                                            "descripcion": f"Tasa packet_in={rate:.1f} pkt/s > umbral {PACKET_IN_RATE_THRESHOLD}",
                                            "ts": datetime.fromtimestamp(ts).isoformat()
                                        })

            # --- Anomalia 2: Cookie maliciosa ---
            for flow in flows:
                if flow.get("cookie", 0) == MALICIOUS_COOKIE:
                    alerts.append({
                        "tipo": "MALICIOUS_COOKIE",
                        "severidad": "ALTA",
                        "dpid": dpid,
                        "cookie": hex(MALICIOUS_COOKIE),
                        "flow": flow,
                        "descripcion": "Cookie 0x6d69746d detectada — flujo inyectado por atacante",
                        "ts": datetime.fromtimestamp(ts).isoformat()
                    })

            # --- Anomalia 3: Desviacion estandar alta entre puertos ---
            rx_vals = [p.get("rx_packets", 0) for p in ports if p.get("port_no", 0) != 0xfffffffe]
            if len(rx_vals) >= 2:
                mean = sum(rx_vals) / len(rx_vals)
                variance = sum((x - mean) ** 2 for x in rx_vals) / len(rx_vals)
                stddev = math.sqrt(variance)
                if stddev > PORT_STDDEV_THRESHOLD:
                    alerts.append({
                        "tipo": "PORT_IMBALANCE",
                        "severidad": "MEDIA",
                        "dpid": dpid,
                        "stddev": round(stddev, 1),
                        "rx_per_port": rx_vals,
                        "descripcion": f"Desbalance de trafico entre puertos (stddev={stddev:.0f} pkt)",
                        "ts": datetime.fromtimestamp(ts).isoformat()
                    })

            # --- Anomalia 4: Flujos con OUTPUT a multiples puertos ---
            for flow in flows:
                actions = str(flow.get("actions", ""))
                if actions.count("OUTPUT") > 1:
                    alerts.append({
                        "tipo": "MULTI_OUTPUT_FLOW",
                        "severidad": "ALTA",
                        "dpid": dpid,
                        "actions": actions,
                        "descripcion": "Flujo con salida a multiples puertos (posible duplicacion/intercepcion)",
                        "ts": datetime.fromtimestamp(ts).isoformat()
                    })

        self.prev_snapshot = snap
        self.alerts.extend(alerts)
        return alerts

    def print_alerts(self, alerts):
        if not alerts:
            return
        print(f"\n{'='*60}")
        print(f"  [{datetime.now().strftime('%H:%M:%S')}] {len(alerts)} ALERTA(S) DETECTADA(S)")
        print(f"{'='*60}")
        for a in alerts:
            sev = a.get("severidad", "?")
            tipo = a.get("tipo", "?")
            desc = a.get("descripcion", "")
            marker = "!!!!" if sev == "ALTA" else " !! "
            print(f"  [{marker}] [{sev}] {tipo}")
            print(f"         {desc}")
        print(f"{'='*60}\n")

    def save_report(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = os.path.join(CAPTURES_DIR, f"flow_anomaly_report_{ts}.json")
        with open(out, "w") as f:
            json.dump({
                "generated": datetime.now().isoformat(),
                "total_alerts": len(self.alerts),
                "alerts": self.alerts
            }, f, indent=2, default=str)
        print(f"[+] Reporte guardado: {out}")
        return out


def main():
    parser = argparse.ArgumentParser(description="Deteccion de anomalias en flujos OpenFlow (Fase 4)")
    parser.add_argument("--controller", default="192.168.100.10")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument("--report", action="store_true")
    args = parser.parse_args()

    base_url = f"http://{args.controller}:{args.port}"
    detector = FlowAnomalyDetector(base_url)

    print(f"[*] Detector de anomalias iniciado — {base_url}")
    print(f"[*] Intervalo: {args.interval}s | Duracion: {args.duration}s")
    print(f"[*] Umbrales: packet_in > {PACKET_IN_RATE_THRESHOLD} pkt/s | stddev > {PORT_STDDEV_THRESHOLD}")
    print()

    deadline = time.time() + args.duration
    try:
        while time.time() < deadline:
            snap = detector.snapshot()
            if snap:
                alerts = detector.analyze(snap)
                detector.print_alerts(alerts)
                n_flows = sum(len(d["flows"]) for d in snap["switches"].values())
                print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                      f"switches={len(snap['switches'])}  flujos={n_flows}  "
                      f"alertas_total={len(detector.alerts)}", end="\r")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] Interrumpido.")

    print(f"\n[+] Total alertas: {len(detector.alerts)}")
    if args.report or detector.alerts:
        detector.save_report()


if __name__ == "__main__":
    main()
