# Security and Privacy

## Responsible use

SENTRY captures network metadata. Only monitor networks and systems you own or
are explicitly authorized to monitor. Capturing traffic on networks you do not
control may be illegal in your jurisdiction.

The synthetic event generator exists so SENTRY can be evaluated without
capturing anyone's traffic. Generated events are clearly labelled as synthetic
in the dashboard.

## What SENTRY stores

- Normalized event metadata: timestamps, source/destination IP addresses,
  ports, protocols, HTTP methods/paths/status, usernames, and DNS query names
  when captured.
- Alerts, detection evidence, threat-intelligence results, analyst notes and
  audit entries.

SENTRY does **not** store packet payloads. The network sensor extracts packet
headers and DNS query names only.

Data is stored locally in `sentry.db` (SQLite). That file is excluded from
version control. Delete it to remove collected data.

## Secrets

- No API keys are stored in the repository.
- `ABUSEIPDB_API_KEY` (optional reputation provider), `SENTRY_WEBHOOK_URL`
  (optional notifications) and `SENTRY_ANOMALY_ENABLED` are read from the
  environment. See `.env.example`.
- `.env` and `.dev.vars` are git-ignored.

## Privileges

Live capture requires packet-capture privileges: Npcap on Windows, or
`CAP_NET_RAW`/`CAP_NET_ADMIN` on Linux. Do not run the whole dashboard as
administrator when only capture needs elevation.

## Reporting a vulnerability

Open a private security advisory on the repository, or contact the maintainer.
Please do not file public issues for vulnerabilities.
