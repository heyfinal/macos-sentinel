#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
from dataclasses import dataclass, asdict
from typing import List, Dict

try:
    import yara_x
    YARA_AVAILABLE = True
except Exception:
    YARA_AVAILABLE = False

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False


@dataclass
class Finding:
    id: str
    title: str
    description: str
    evidence: str
    remediation: str
    risk_level: str
    mitre_attack_id: str | None


def load_rules(rule_dir: str) -> str:
    sources = []
    for root, _, files in os.walk(rule_dir):
        for file in files:
            if file.endswith('.yar') or file.endswith('.yara'):
                with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                    sources.append(f.read())
    return '\n'.join(sources)


class YARAScanner:
    def __init__(self, rule_dir: str):
        if YARA_AVAILABLE:
            compiler = yara_x.Compiler()
            source = load_rules(rule_dir)
            if source.strip():
                compiler.add_source(source)
                self.rules = compiler.build()
            else:
                self.rules = None
        else:
            self.rules = None

    def scan_file(self, filepath: str) -> List[Finding]:
        if not self.rules:
            return []
        findings = []
        try:
            with open(filepath, 'rb') as f:
                data = f.read(10 * 1024 * 1024)
            matches = self.rules.scan(data)
            for match in matches.matching_rules:
                findings.append(Finding(
                    id=f"YARA-{match.identifier}",
                    title=f"YARA Match: {match.identifier}",
                    description=match.metadata.get('description', 'Matched YARA rule'),
                    evidence=f"File: {filepath}",
                    remediation="Investigate and remove if malicious",
                    risk_level=match.metadata.get('severity', 'high'),
                    mitre_attack_id="T1059"
                ))
        except Exception:
            pass
        return findings


class AnomalyDetector:
    def __init__(self):
        if ML_AVAILABLE:
            self.model = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
        else:
            self.model = None

    def analyze_process_behavior(self) -> List[Finding]:
        if not self.model:
            return []
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        features = []
        processes = []
        for line in result.stdout.strip().split('\n')[1:]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                try:
                    cpu = float(parts[2])
                    mem = float(parts[3])
                    vsz = int(parts[4])
                    rss = int(parts[5])
                    features.append([cpu, mem, vsz, rss])
                    processes.append({
                        'user': parts[0],
                        'pid': parts[1],
                        'cpu': cpu,
                        'mem': mem,
                        'command': parts[10]
                    })
                except Exception:
                    continue
        if len(features) < 10:
            return []
        X = np.array(features)
        predictions = self.model.fit_predict(X)
        findings = []
        for i, pred in enumerate(predictions):
            if pred == -1:
                proc = processes[i]
                findings.append(Finding(
                    id=f"ML-PROC-{proc['pid']}",
                    title=f"Anomalous Process Behavior: PID {proc['pid']}",
                    description="Process exhibits unusual resource usage patterns",
                    evidence=f"User: {proc['user']} CPU: {proc['cpu']}% MEM: {proc['mem']}% Command: {proc['command']}",
                    remediation="Investigate process activity",
                    risk_level="medium",
                    mitre_attack_id="T1071"
                ))
        return findings


class CorrelationEngine:
    ATTACK_CHAINS = [
        {
            'name': 'Persistence + C2',
            'required': ['PERSIST-', 'NET-CONN-'],
            'risk_level': 'critical',
            'description': 'Persistence indicators with network connections'
        },
        {
            'name': 'Credential Theft Chain',
            'required': ['KEY-', 'HIST-'],
            'risk_level': 'critical',
            'description': 'Potential credential access activity detected'
        },
        {
            'name': 'Remote Access Compromise',
            'required': ['SSH-', 'VNC-'],
            'risk_level': 'critical',
            'description': 'Multiple remote access vectors are enabled'
        },
        {
            'name': 'Defense Evasion',
            'required': ['SYS-001', 'SYS-002'],
            'risk_level': 'critical',
            'description': 'Security protections have been disabled'
        }
    ]

    def correlate(self, findings: List[Dict]) -> List[Finding]:
        correlated = []
        ids = [f['id'] for f in findings if 'id' in f]

        for chain in self.ATTACK_CHAINS:
            matches = []
            for required in chain['required']:
                for fid in ids:
                    if fid.startswith(required) or fid == required:
                        matches.append(fid)
                        break
            if len(matches) == len(chain['required']):
                correlated.append(Finding(
                    id=f"CHAIN-{chain['name'].replace(' ', '-')}",
                    title=f"Attack Chain Detected: {chain['name']}",
                    description=chain['description'],
                    evidence=f"Correlated findings: {', '.join(matches)}",
                    remediation="Immediate investigation required",
                    risk_level=chain['risk_level'],
                    mitre_attack_id="T1078"
                ))
        return correlated


def main() -> None:
    parser = argparse.ArgumentParser(description='macOS Sentinel Analysis Engine')
    parser.add_argument('--input', '-i', required=True, help='Input findings JSON')
    parser.add_argument('--output', '-o', required=True, help='Output enhanced findings JSON')
    parser.add_argument('--scan-paths', nargs='+', help='Additional paths to YARA scan')
    args = parser.parse_args()

    with open(args.input, 'r', encoding='utf-8') as f:
        base_findings = json.load(f)

    all_findings = base_findings.copy()

    print('[*] Running YARA analysis...')
    scanner = YARAScanner(rule_dir=os.path.join(os.path.dirname(__file__), 'yara_rules'))
    scan_paths = args.scan_paths or ['/tmp', '/var/tmp', os.path.expanduser('~/Downloads')]

    allowlist_prefixes = [
        "/System/",
        "/usr/bin/",
        "/usr/sbin/",
        "/bin/",
        "/sbin/",
        "/Library/Apple/"
    ]
    allowlist_names = [
        "nmap",
        "wireshark",
        "tcpdump",
        "openssl",
        "iterm",
        "terminal"
    ]

    for path in scan_paths:
        if not os.path.exists(path):
            continue
        for root, _, files in os.walk(path):
            for file in files[:100]:
                filepath = os.path.join(root, file)
                if any(filepath.startswith(prefix) for prefix in allowlist_prefixes):
                    continue
                lower = file.lower()
                if any(name in lower for name in allowlist_names):
                    continue
                all_findings.extend([asdict(f) for f in scanner.scan_file(filepath)])

    print('[*] Running anomaly detection...')
    detector = AnomalyDetector()
    all_findings.extend([asdict(f) for f in detector.analyze_process_behavior()])

    print('[*] Running correlation analysis...')
    correlator = CorrelationEngine()
    all_findings.extend([asdict(f) for f in correlator.correlate(all_findings)])

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(all_findings, f, indent=2)

    print(f"[+] Analysis complete. {len(all_findings)} findings written to {args.output}")


if __name__ == '__main__':
    main()
