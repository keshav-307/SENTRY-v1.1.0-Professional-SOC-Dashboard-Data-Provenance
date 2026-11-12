# Detection Rules

Thresholds are editable in `config/detection_rules.json`. Defaults below match
the code defaults; invalid or missing settings fall back to these values.

| Rule ID | Name | Severity | Default condition | MITRE ATT&CK |
|---|---|---|---|---|
| `SSH-BRUTE-001` | SSH Brute Force | HIGH | ≥ 5 failed authentications from one IP in 120 s | T1110 Brute Force |
| `WEB-SQLI-001` | SQL Injection Attempt | CRITICAL | SQL signature in request path/query | T1190 Exploit Public-Facing Application |
| `WEB-TRAVERSAL-001` | Path Traversal Attempt | HIGH | Parent-directory sequence in request | T1083 File and Directory Discovery |
| `AUTH-COMPROMISE-001` | Successful Login After Brute Force | CRITICAL | Success after ≥ 5 failures in 120 s | T1078 Valid Accounts |
| `NET-RECON-001` | Network Reconnaissance | HIGH | ≥ 10 unique destination ports from one IP in 120 s, counting connection initiations only | T1046 Network Service Discovery |
| `DNS-SUSPICIOUS-001` | Suspicious DNS Activity | HIGH | ≥ 20 unique domains from one IP in 60 s | T1071.004 DNS |
| `ML-ANOMALY-001` | Statistical Anomaly (optional) | MEDIUM | Feature z-score ≥ 4.0 vs stored baseline | — |

## Alert deduplication

SSH brute force, SQL injection, path traversal and authentication compromise
share a persistent fingerprint table (`alert_dedup`). The fingerprint is a
SHA-256 of the rule, source IP and detection context:

| Rule | Context | Cooldown |
|---|---|---|
| `SSH-BRUTE-001` | targeted usernames | 300 s |
| `WEB-SQLI-001` | matched signature + endpoint + method | 300 s |
| `WEB-TRAVERSAL-001` | matched signature + decoded target | 300 s |
| `AUTH-COMPROMISE-001` | account that logged in | 900 s |

A matching detection inside the cooldown is suppressed without creating an
alert; its events are still stored, the suppression counter and last-seen time
are updated, and the existing alert's status is left alone. The cooldown is
measured from the last emitted alert, so a campaign alerts again once it
expires. Different sources, accounts, endpoints, signatures or targets use
different fingerprints and are not merged. `NET-RECON-001` keeps its existing
120-second per-source suppression in `detection_state`.

## Evidence

Every rule alert stores:

- rule identity, description and severity
- MITRE technique
- source IP, threshold, observed values
- correlation window (start, end, seconds)
- conditions with expected/observed/result
- the exact triggering events (up to 50; total count always recorded)
- a generated explanation
- confidence value with an explicit "not a probability" basis
- recommended actions

Rule-specific extras include matched signature, request path/method, targeted
usernames, failure counts, unique destination ports, unique domains and
NXDOMAIN counts.

## Direction awareness

Live capture sees both directions of every flow. Each captured event therefore
records:

- `direction` relative to this host: `outbound`, `inbound`, `local` or
  `unknown` (derived from the capture interface's IPv4 and IPv6 addresses)
- `initiated`: `True` for a TCP SYN without ACK or the first packet of a UDP
  flow, `False` for replies and mid-stream packets, `NULL` when the producer
  supplied no information (legacy or synthetic events)

`NET-RECON-001` counts a destination port only when the event is not marked
`initiated = False`. Reply packets from a CDN, gateway or server carry the
local host's ephemeral port as their destination port, so without this filter
ordinary HTTPS traffic could look like the remote host scanning local ports.
Events with `initiated = NULL` keep the historical behaviour. No ephemeral
port range heuristic is used, and the 10-port threshold, 120-second window,
persistent deduplication, severity, confidence and T1046 mapping are unchanged.

## Suppression

- `NET-RECON-001` and `DNS-SUSPICIOUS-001` suppress repeat alerts for the same
  source inside their window, using `detection_state` in SQLite.
- `SSH-BRUTE-001`, `WEB-SQLI-001`, `WEB-TRAVERSAL-001` and
  `AUTH-COMPROMISE-001` keep their original behaviour: they alert per
  processing call. Raising those thresholds or adding suppression is an
  operator decision, not a silent default.

## Tuning guidance

- Raise `NET-RECON-001` thresholds in environments with legitimate port
  sweeping (vulnerability scanners, monitoring).
- DNS thresholds depend on normal resolver chatter; baseline first.
- The anomaly layer should be enabled only after enough normal activity has
  been observed; it never replaces rule detection.
