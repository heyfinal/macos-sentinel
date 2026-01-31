# McGuardian

McGuardian is a comprehensive macOS security analyzer that audits system integrity, network exposure, persistence mechanisms, and forensic indicators in a single run.

## Why McGuardian
- Unified security posture scan for macOS 12+ (Monterey and newer)
- Combines system, network, persistence, malware, and forensics checks
- Outputs clear, actionable findings with MITRE ATT&CK mapping
- Optional Python analysis for YARA + ML anomaly detection

## Features
- System integrity checks (SIP, Gatekeeper, TCC, SSH, Screen Sharing)
- Network exposure analysis (firewall, listeners, connections)
- Persistence discovery (LaunchAgents/Daemons, cron, login items, kexts)
- Malware indicators (hash matching + filename heuristics)
- Forensics (shell history, keychain changes, unified logs)
- Reports in text, JSON, and HTML

## Quick Start

```bash
cd /Users/daniel/macos-sentinel
swift build -c release
sudo .build/release/mcguardian scan
```

## Usage

```bash
mcguardian scan --quick
mcguardian scan --format json --output /tmp/findings.json
mcguardian scan --format html --output /tmp/report.html
```

### Run specific modules

```bash
mcguardian scan --module system --module network
mcguardian scan --module forensics --format json --output /tmp/forensics.json
```

## Python Analysis (Optional)

```bash
cd /Users/daniel/macos-sentinel/analysis
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python analyzer.py -i /tmp/findings.json -o /tmp/enhanced_findings.json
```

## Reports
- JSON: easy to integrate with SIEM and automation pipelines
- HTML: shareable audit report for teams and stakeholders

## Security Notes
- Some checks require elevated privileges to inspect system configuration.
- Realtime monitoring is stubbed (EndpointSecurity entitlement required).

## Project Structure
```
macos-sentinel/
├── Package.swift
├── Sources/
│   ├── Sentinel/
│   └── SentinelCLI/
├── analysis/
│   ├── analyzer.py
│   └── yara_rules/
└── Tests/
```

## License
MIT
