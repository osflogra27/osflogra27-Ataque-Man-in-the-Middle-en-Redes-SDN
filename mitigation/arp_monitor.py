#!/usr/bin/env python3
"""
arp_monitor.py - Controlador Ryu con deteccion y mitigacion activa de ARP Spoofing (Fase 4).

Extiende SimpleSwitch13 con deteccion de ARP Spoofing:
  1. Mantiene tabla ARP de confianza {IP -> MAC}.
  2. Detecta cuando una IP cambia de MAC (ARP Spoofing).
  3. Instala flujo DROP en OVS para la MAC atacante (prioridad 100).
  4. Registra eventos en captures/mitigation_events.log.

Uso (en la VM ryu):
    source ~/ryu-venv/bin/activate
    ryu-manager mitigation/arp_monitor.py
"""

import json
import logging
import os
import time
from collections import defaultdict
from datetime import datetime

from ryu.app.simple_switch_13 import SimpleSwitch13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, arp

LOG = logging.getLogger("arp_monitor")

# ── Configuracion ──────────────────────────────────────────────────
BLOCK_THRESHOLD = 1    # cambios de MAC para activar bloqueo
BLOCK_DURATION  = 300  # segundos (hard_timeout del flujo DROP)
BLOCK_PRIORITY  = 100  # mayor que el learning switch (10)

# Archivo de log de eventos
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(ROOT_DIR, "captures", "mitigation_events.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


def log_event(event_type, detail, extra=None):
    ts = datetime.now().isoformat(timespec="seconds")
    entry = {"ts": ts, "event": event_type, "detail": detail}
    if extra:
        entry.update(extra)
    LOG.warning("[%s] %s | %s", event_type, detail, extra or "")
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        LOG.error("Error escribiendo log: %s", e)
    return entry


class ArpMonitor(SimpleSwitch13):
    """Learning switch OpenFlow 1.3 con deteccion y bloqueo de ARP Spoofing."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.trusted_arp  = {}               # {ip: mac_legitima}
        self.spoof_count  = defaultdict(int) # {ip: n_cambios}
        self.blocked_macs = {}               # {mac: timestamp_bloqueo}
        self.metrics = {
            "attacks_detected": 0,
            "attacks_blocked":  0,
            "first_detection_ts": None,
            "first_block_ts":     None,
        }
        LOG.warning("=== ArpMonitor iniciado — monitoreando ARP Spoofing ===")
        log_event("STARTUP", "arp_monitor iniciado")

    # ── Packet-in: hereda de SimpleSwitch13 y agrega inspeccion ARP ──
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # Primero deja que simple_switch_13 haga su trabajo (aprendizaje + forwarding)
        super()._packet_in_handler(ev)

        # Luego inspeccionamos el paquete ARP
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        arp_pkt = pkt.get_protocol(arp.arp)

        if arp_pkt is None:
            return

        src_ip  = arp_pkt.src_ip
        src_mac = arp_pkt.src_mac

        if not src_ip or src_ip == "0.0.0.0":
            return

        dp = msg.datapath

        if src_ip in self.trusted_arp:
            trusted_mac = self.trusted_arp[src_ip]
            if trusted_mac != src_mac:
                # *** ARP SPOOFING DETECTADO ***
                self.spoof_count[src_ip] += 1
                self.metrics["attacks_detected"] += 1
                if self.metrics["first_detection_ts"] is None:
                    self.metrics["first_detection_ts"] = time.time()

                log_event("ARP_SPOOFING_DETECTED",
                          f"IP {src_ip} cambio MAC {trusted_mac} -> {src_mac}",
                          {"attacker_mac": src_mac, "victim_ip": src_ip,
                           "trusted_mac": trusted_mac,
                           "spoof_count": self.spoof_count[src_ip]})

                if self.spoof_count[src_ip] >= BLOCK_THRESHOLD:
                    self._block_mac(dp, src_mac, src_ip, trusted_mac)
        else:
            # Primera vez que vemos esta IP: registrar como confiable
            self.trusted_arp[src_ip] = src_mac
            LOG.info("ARP aprendido: %s -> %s", src_ip, src_mac)

    # ── Instalar flujo DROP para la MAC atacante ──────────────────────
    def _block_mac(self, dp, attacker_mac, victim_ip, legitimate_mac):
        if attacker_mac in self.blocked_macs:
            return  # ya bloqueada

        parser = dp.ofproto_parser
        ofp    = dp.ofproto

        # DROP de todo trafico desde la MAC atacante
        match = parser.OFPMatch(eth_src=attacker_mac)
        self._add_flow_drop(dp, BLOCK_PRIORITY, match)

        # DROP especifico de ARP desde la MAC atacante
        match_arp = parser.OFPMatch(eth_type=0x0806, eth_src=attacker_mac)
        self._add_flow_drop(dp, BLOCK_PRIORITY + 1, match_arp)

        self.blocked_macs[attacker_mac] = time.time()
        self.metrics["attacks_blocked"] += 1
        if self.metrics["first_block_ts"] is None:
            self.metrics["first_block_ts"] = time.time()

        det_ts = self.metrics["first_detection_ts"]
        resp_t = round(time.time() - det_ts, 3) if det_ts else None

        log_event("MAC_BLOCKED",
                  f"MAC {attacker_mac} bloqueada (victima: {victim_ip})",
                  {"attacker_mac": attacker_mac,
                   "legitimate_mac": legitimate_mac,
                   "victim_ip": victim_ip,
                   "response_time_s": resp_t})

        LOG.warning("*** BLOQUEO ACTIVO: MAC %s bloqueada por %ds ***",
                    attacker_mac, BLOCK_DURATION)

    # ── Helper: flujo DROP ────────────────────────────────────────────
    def _add_flow_drop(self, dp, priority, match):
        parser = dp.ofproto_parser
        ofp    = dp.ofproto
        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            match=match,
            instructions=[],          # sin acciones = DROP
            hard_timeout=BLOCK_DURATION,
            command=ofp.OFPFC_ADD)
        dp.send_msg(mod)
