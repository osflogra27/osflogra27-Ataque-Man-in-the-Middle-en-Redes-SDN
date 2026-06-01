# Topologías del laboratorio (Fase 1)

El anteproyecto define tres escenarios de topología para GNS3: **estrella, árbol y malla**. Todos comparten
el mismo direccionamiento del plano de datos y el mismo plano de control (Ryu).

## Direccionamiento

**Plano de datos — `10.0.0.0/24`**

| Host | Rol | IPv4 | Notas |
|------|-----|------|-------|
| h1 | Víctima A | `10.0.0.11/24` | cliente |
| h2 | Víctima B / Servidor | `10.0.0.12/24` | servicio objetivo |
| h3 | Atacante | `10.0.0.66/24` | se activa en Fase 2 (ARP Spoofing) |

**Plano de control — `192.168.100.0/24`**

| Nodo | IPv4 | Notas |
|------|------|-------|
| Ryu (controlador) | `192.168.100.10` | OpenFlow 1.3 :6653, API REST :8080 |
| OVS (gestión) | `192.168.100.20` | canal de control hacia Ryu |

> El plano de control va por una red separada del plano de datos (buena práctica SDN). En GNS3 esto se
> modela con un segundo adaptador/segmento que une la VM OVS con la VM Ryu.

## Escenario 1 — Estrella (base)

Todos los hosts cuelgan de un único OVS. Es la topología base para las Fases 1 y 2.

```
        h1 ─┐
        h2 ─┼─ [ OVS br0 ] ──OpenFlow─→ [ Ryu ]
        h3 ─┘
```

## Escenario 2 — Árbol

Un OVS raíz y OVS de borde; los hosts cuelgan de las hojas. Útil para observar cómo se propaga el MITM
entre segmentos.

```
                 [ OVS raíz ] ──OpenFlow─→ [ Ryu ]
                 /          \
          [ OVS-A ]        [ OVS-B ]
           /    \            /    \
          h1    h2          h3    (libre)
```

## Escenario 3 — Malla

Varios OVS interconectados con enlaces redundantes (el controlador resuelve los bucles). Permite estudiar
el impacto del MITM y de la mitigación cuando existen rutas alternativas.

```
        [ OVS-1 ]───[ OVS-2 ]
            │   \   /   │
            │    \ /    │
        [ OVS-3 ]───[ OVS-4 ]
        (hosts repartidos entre los OVS; todos apuntan a Ryu)
```

## Notas de implementación en GNS3

- Cada VM Ubuntu Server usa un adaptador para el plano de datos (`eth0`) y, donde aplique, otro para gestión.
- En la VM OVS, los adaptadores que van a los hosts/enlaces (`eth1`, `eth2`, …) se agregan como puertos del puente `br0` (ver `ovs/setup_ovs.sh`).
- Tras montar cada escenario, tomar una **snapshot** en GNS3 como línea base reproducible.
- Capturar tráfico legítimo con Wireshark/`baseline_capture.sh` antes de pasar a la Fase 2.
