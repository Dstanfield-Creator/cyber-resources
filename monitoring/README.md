# Monitoring & Observability

> Prometheus and Grafana stacks, exporters, and a lab health dashboard whose alerts come from real incidents rather than defaults. Part of the Security Operations repo.

**Status:** Active · **Updated:** 2026-10-08

## Structure

```
├── mydashboard/                 # MyDashboard: the "is the lab healthy?" screen - data sources, panels, alert rules
├── compose/
│   ├── monitoring-stack/        # Reference stack: Prometheus, Alertmanager, Grafana, node_exporter, cAdvisor, blackbox
│   └── lab-monitoring/          # The stack as deployed in the lab
├── docs/
│   └── prometheus-node-exporter-setup.md   # Sandboxed node_exporter, textfile collector, scrape config, PromQL
└── (sanitisation rules: ../CONTRIBUTING.md)
```

## Contents

| Item | Summary | Status |
|---|---|---|
| [MyDashboard](./mydashboard/) | Design for a Prometheus + Grafana lab health dashboard: Proxmox, backup, container and host data sources, panel layout, and alert rules derived from the incidents in the write-ups | Design complete, build in progress |
| [Monitoring Stack (Compose)](./compose/monitoring-stack/) | Prometheus, Alertmanager, Grafana with provisioned datasources and dashboards, node_exporter, cAdvisor and blackbox_exporter with SSH probes, starter alert rules | Reference |
| [Lab Monitoring (Compose)](./compose/lab-monitoring/) | The trimmed stack actually running in the lab, pinned image tags, `.env.example` only | Active |
| [Prometheus node_exporter Setup](./docs/prometheus-node-exporter-setup.md) | Sandboxed systemd unit bound to the management interface, textfile collector for custom metrics, scrape config and useful PromQL | Active |

## MyDashboard build

The MyDashboard build lands in this repo as it is completed:

```
compose/lab-monitoring/   # the running stack
prometheus/               # alert rules per failure mode (from mydashboard/)
grafana/                  # provisioned dashboards (JSON) and datasources
docs/runbooks/            # one runbook per alert
```

**Stack:** Prometheus · Alertmanager · Grafana · prometheus-pve-exporter · node_exporter · cAdvisor · blackbox_exporter · n8n (alert to notification)

## Related

- Grafana and n8n run on the [Docker Services Host](https://github.com/Dstanfield-Creator/lab-ops/tree/main/docs/docker-services-host/) (lab-ops)
- The incident that produced the first alert rules: [A backup job that failed silently for a month](https://dstanfield-creator.github.io/writeups/silent-backup-failure.html) and the [Proxmox Backup Server](https://github.com/Dstanfield-Creator/lab-ops/tree/main/docs/proxmox-backup-server/) build
- Host-side reachability checks that feed the dashboard: [lab-ssh-check](https://github.com/Dstanfield-Creator/lab-ops/tree/main/scripts/lab-ssh-check) (lab-ops)

## Conventions

- Only RFC 5737 documentation addresses (`192.0.2.0/24`) and `example.com` appear in committed files; every stack ships a `.env.example` and the real `.env` is never committed.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full sanitisation rules.

---

**Author:** Danny Stanfield · Perth, WA  
**License:** MIT
