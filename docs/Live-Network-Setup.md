# Live Network Monitoring - Setup

Real-time packet observation for AUTHORIZED hosts and networks only. Capture runs
on the machine where the monitoring service has permission to observe the
interface. A browser cannot capture packets; the dashboard is only a viewer.

## Modes

| Mode | Data source | How to enter |
|------|-------------|--------------|
| DEMO / REPLAY | Scripted multi-stage attack replay | Default. Play / Next Step / Reset in the navbar. |
| LIVE NETWORK | Real captured packets | Live Network page then Start Monitoring (privileged role). |

Provenance is tagged at ingestion (`is_simulated`) and labelled in the footer and
on the Live Network page. The two sources are never merged unlabelled.

## Windows setup

1. Install Npcap from https://npcap.com and enable WinPcap-compatible mode.
2. Install dependencies: `pip install -r requirements.txt`
3. Start the backend AS ADMINISTRATOR - raw capture requires elevation.

Without Npcap the API stays fully functional and `/api/network/status` reports
`capability.reason = npcap_missing` with remediation text. No packets are faked.

## Linux setup

Grant capture capability to the interpreter instead of running everything as root:

    sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))
    ip link      # confirm the interface name

Then start the backend normally as an unprivileged user.

## Configuration

Copy `.env.example` to `.env` and set:

    NETWORK_MONITOR_ENABLED=true    # false keeps DEMO-only operation
    NETWORK_INTERFACE=auto          # or e.g. eth0 / Wi-Fi
    PACKET_CAPTURE_FILTER=          # optional BPF filter
    PACKET_RETENTION_MINUTES=60     # metadata retention (no payloads stored)
    THREAT_THRESHOLD=70             # escalation score
    AUTO_BLOCK=false                # sandboxed by default

Detection thresholds (PORT_SCAN_UNIQUE_PORTS, DOS_PACKETS_PER_SECOND,
TRAFFIC_BURST_MULTIPLIER, ...) are all environment-tunable. Never commit `.env`.

To correlate network evidence with an existing endpoint/identity incident:

    NETWORK_LOCAL_ENTITY=user:alice / host:WKS-042

## API

Read endpoints: `/api/network/status`, `/packets`, `/stats`, `/ips`,
`/connections`, `/threats`, `/interfaces`

Control endpoints require an `X-Sentinel-Role` header with an authorized role:
`POST /api/network/start`, `POST /api/network/stop`, `POST /api/network/reset`

Unauthorized callers receive 401/403. When capture is impossible the start call
returns 409 with the precise reason instead of a false success.

## Authorized local testing

Run these only against your own machine or an isolated lab you own.

1. Normal traffic - browse locally. Expect statistics to populate and NO
   incident to be raised.
2. Port scan - scan your own host, e.g. `nmap -p 1-200 127.0.0.1`.
   Expect port fan-out above PORT_SCAN_UNIQUE_PORTS, a `Probe / Reconnaissance`
   detection mapped to T1046, a rising threat score, and an incident created or
   enriched.
3. Traffic burst - generate sustained self-directed traffic, e.g.
   `ping -n 1000 -l 1400 127.0.0.1`. Expect baseline deviation and an anomaly
   detection once the burst multiplier is exceeded.
4. Cross-layer - while monitoring, POST identity/endpoint events to
   `/api/telemetry/ingest` using the same entity as NETWORK_LOCAL_ENTITY.
   Expect ONE correlated incident with attack graph, timeline and MITRE mapping.

## Privacy

Only header metadata is collected: timestamp, source/destination IP and port,
protocol, packet size, TCP flags, interface, direction, and a 5-tuple hash.
Payload bytes are never captured or stored. Metadata is deleted after
PACKET_RETENTION_MINUTES.

## Performance

Capture runs on a background thread and hands packets to a bounded queue.
ML inference runs once per aggregation window, never per packet. Queue overflow
drops packets and REPORTS the count in `/api/network/status` rather than hiding
loss. Database writes are batched and retention is swept periodically.

## Database note

Persistence is best-effort at startup. If the configured database is
unreachable the API still serves and `/api/health` reports
`database.connected = false` with a sanitized error code. Supabase direct
connection hostnames resolve to IPv6 only; on IPv4-only hosts use the Supabase
session/transaction pooler connection string instead.
