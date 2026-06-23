#!/usr/bin/env python3
"""
arp_monitor.py - Controlador Ryu con deteccion y mitigacion activa de ARP Spoofing (Fase 4).

Extiende simple_switch_13 con un modulo de seguridad que:
  1. Mantiene una tabla ARP de confianza (IP -> MAC aprendida).
  2. Detecta cuando una IP cambia de MAC (indicador de ARP Spoofing).
  3. Instala flujos de bloqueo en OVS para la MAC del atacante.
  4. Registra cada evento en un log estructurado con timestamps.
  5. Expone metricas via API REST (/mitigation/stats).

Uso (en la VM ryu):
    source ~/ryu-venv/bin/activate
    ryu-manager --wsapi-port 8080 mitigation/arp_monitor.py ryu.app.ofctl_rest
"""

import json
import logging
import os
import time
from collections import defaultdict
from datetime import datetime

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import arp, ethernet, packet
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3

LOG = logging.getLogger("arp_monitor")
LOG.setLevel(logging.INFO)

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(ROOT_DIR, "captures", "mitigation_events.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# Umbral: si una IP cambia de MAC mas de N veces en la sesion -> bloqueo permanente
BLOCK_THRESHOLD = 1
# Duracion del flujo de bloqueo en segundos (0 = permanente)
BLOCK_DURATION = 300
# Prioridad del flujo de bloqueo (mayor que learning switch = 10)
BLOCK_PRIORITY = 100


def log_event(event_type, detail, extra=None):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {"ts": ts, "event": event_type, "detail": detail}
    if extra:
        entry.update(extra)
    line = json.dumps(entry)
    LOG.warning("[%s] %s — %s", event_type, detail, extra or "")
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")
    return entry


class ArpMonitorApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Tabla ARP de confianza: {ip: mac}
        self.trusted_arp = {}
        # Conteo de cambios por IP: {ip: count}
        self.spoof_count = defaultdict(int)
        # MACs bloqueadas: {mac: ts_bloqueo}
        self.blocked_macs = {}
        # Registro de eventos de mitigacion
        self.events = []
        # Metricas
        self.metrics = {
            "attacks_detected": 0,
            "attacks_blocked": 0,
            "false_positives": 0,
            "first_detection_ts": None,
            "first_block_ts": None,
        }
        # MAC table del learning switch: {dpid: {mac: port}}
        self.mac_to_port = {}
        # datapath registry
        self.datapaths = {}

        wsgi = kwargs["wsgi"]
        wsgi.register(MitigationController,
                      {"arp_monitor_app": self})

        log_event("STARTUP", "arp_monitor iniciado — monitoreando ARP Spoofing")

    # ------------------------------------------------------------------
    # OpenFlow: handshake inicial
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        self.datapaths[dp.id] = dp
        self.mac_to_port.setdefault(dp.id, {})

        # Flujo default: mandar todo al controlador (tabla miss)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, 0, match, actions)
        LOG.info("Switch conectado: dpid=%016x", dp.id)

    # ------------------------------------------------------------------
    # OpenFlow: paquetes entrantes
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        dst_mac = eth.dst
        src_mac = eth.src
        dpid = dp.id

        # --- Inspeccion ARP ---
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self._inspect_arp(dp, in_port, arp_pkt, src_mac)

        # --- Bloquear si la MAC de origen esta bloqueada ---
        if src_mac in self.blocked_macs:
            LOG.debug("Paquete de MAC bloqueada %s — descartado", src_mac)
            return

        # --- Learning switch ---
        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac)
            self._add_flow(dp, 10, match, actions)

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)

    # ------------------------------------------------------------------
    # Deteccion ARP Spoofing
    # ------------------------------------------------------------------
    def _inspect_arp(self, dp, in_port, arp_pkt, src_mac):
        src_ip = arp_pkt.src_ip
        if not src_ip or src_ip == "0.0.0.0":
            return

        if src_ip in self.trusted_arp:
            trusted_mac = self.trusted_arp[src_ip]
            if trusted_mac != src_mac:
                # *** ARP SPOOFING DETECTADO ***
                self.spoof_count[src_ip] += 1
                self.metrics["attacks_detected"] += 1

                if self.metrics["first_detection_ts"] is None:
                    self.metrics["first_detection_ts"] = time.time()

                event = log_event("ARP_SPOOFING_DETECTED",
                    f"IP {src_ip} cambio de MAC {trusted_mac} -> {src_mac}",
                    {"attacker_mac": src_mac, "victim_ip": src_ip,
                     "trusted_mac": trusted_mac, "dpid": dp.id, "port": in_port,
                     "spoof_count": self.spoof_count[src_ip]})
                self.events.append(event)

                if self.spoof_count[src_ip] >= BLOCK_THRESHOLD:
                    self._block_mac(dp, src_mac, src_ip, trusted_mac)
        else:
            # Primera vez que vemos esta IP: registrar como confiable
            self.trusted_arp[src_ip] = src_mac
            LOG.info("ARP aprendido: %s -> %s", src_ip, src_mac)

    # ------------------------------------------------------------------
    # Bloqueo activo: instalar flujo DROP para la MAC atacante
    # ------------------------------------------------------------------
    def _block_mac(self, dp, attacker_mac, victim_ip, legitimate_mac):
        if attacker_mac in self.blocked_macs:
            return  # ya bloqueada

        parser = dp.ofproto_parser
        ofp = dp.ofproto

        # Flujo 1: DROP de todo lo que salga de la MAC atacante
        match = parser.OFPMatch(eth_src=attacker_mac)
        self._add_flow(dp, BLOCK_PRIORITY, match, [], hard_timeout=BLOCK_DURATION)

        # Flujo 2: DROP de ARP replies con IP de la victima desde MAC atacante
        match_arp = parser.OFPMatch(eth_type=0x0806, eth_src=attacker_mac)
        self._add_flow(dp, BLOCK_PRIORITY + 1, match_arp, [], hard_timeout=BLOCK_DURATION)

        self.blocked_macs[attacker_mac] = time.time()
        self.metrics["attacks_blocked"] += 1

        if self.metrics["first_block_ts"] is None:
            self.metrics["first_block_ts"] = time.time()

        det_ts = self.metrics.get("first_detection_ts")
        response_time = round(time.time() - det_ts, 3) if det_ts else None

        event = log_event("MAC_BLOCKED",
            f"MAC {attacker_mac} bloqueada por {BLOCK_DURATION}s (IP victima: {victim_ip})",
            {"attacker_mac": attacker_mac, "legitimate_mac": legitimate_mac,
             "victim_ip": victim_ip, "dpid": dp.id,
             "response_time_s": response_time})
        self.events.append(event)

        LOG.warning("*** BLOQUEO ACTIVO: MAC %s bloqueada ***", attacker_mac)

    # ------------------------------------------------------------------
    # Helper: agregar flujo OpenFlow
    # ------------------------------------------------------------------
    def _add_flow(self, dp, priority, match, actions, idle_timeout=0, hard_timeout=0):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        inst = ([parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                if actions else [])
        mod = parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match,
            instructions=inst, idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            command=ofp.OFPFC_ADD)
        dp.send_msg(mod)

    # ------------------------------------------------------------------
    # Metodo para desbloquear una MAC (usado via REST)
    # ------------------------------------------------------------------
    def unblock_mac(self, mac):
        if mac in self.blocked_macs:
            del self.blocked_macs[mac]
            # Eliminar de trusted_arp para re-aprender
            for ip, m in list(self.trusted_arp.items()):
                if m == mac:
                    del self.trusted_arp[ip]
            log_event("MAC_UNBLOCKED", f"MAC {mac} desbloqueada manualmente")
            return True
        return False


# ------------------------------------------------------------------
# API REST de mitigacion
# ------------------------------------------------------------------
class MitigationController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app = data["arp_monitor_app"]

    @route("mitigation", "/mitigation/stats", methods=["GET"])
    def get_stats(self, req, **kwargs):
        app = self.app
        det_ts = app.metrics.get("first_detection_ts")
        blk_ts = app.metrics.get("first_block_ts")
        detection_time = round(blk_ts - det_ts, 3) if (det_ts and blk_ts) else None

        body = {
            "trusted_arp": app.trusted_arp,
            "blocked_macs": {k: datetime.fromtimestamp(v).isoformat()
                             for k, v in app.blocked_macs.items()},
            "metrics": {
                **app.metrics,
                "detection_time_s": detection_time,
                "first_detection_ts": datetime.fromtimestamp(det_ts).isoformat() if det_ts else None,
                "first_block_ts": datetime.fromtimestamp(blk_ts).isoformat() if blk_ts else None,
            },
            "recent_events": app.events[-20:],
        }
        return self._json_response(body)

    @route("mitigation", "/mitigation/trusted_arp", methods=["GET"])
    def get_trusted_arp(self, req, **kwargs):
        return self._json_response(self.app.trusted_arp)

    @route("mitigation", "/mitigation/blocked", methods=["GET"])
    def get_blocked(self, req, **kwargs):
        return self._json_response(list(self.app.blocked_macs.keys()))

    @route("mitigation", "/mitigation/unblock/{mac}", methods=["DELETE"])
    def unblock(self, req, mac, **kwargs):
        ok = self.app.unblock_mac(mac)
        return self._json_response({"unblocked": ok, "mac": mac})

    def _json_response(self, data):
        from webob import Response
        body = json.dumps(data, indent=2, default=str)
        return Response(content_type="application/json", body=body.encode())
