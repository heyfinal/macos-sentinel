import Foundation

actor NetworkAnalyzer: AnalyzerModule {
    let name = "Network Security"

    func run(quick: Bool) async throws -> [Finding] {
        var findings: [Finding] = []

        findings.append(contentsOf: checkFirewallStatus())
        findings.append(contentsOf: checkListeningPorts(quick: quick))
        findings.append(contentsOf: checkEstablishedConnections(quick: quick))

        return findings
    }

    private func checkFirewallStatus() -> [Finding] {
        var findings: [Finding] = []
        let result = Shell.run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"])
        if result.output.lowercased().contains("disabled") {
            findings.append(Finding(
                id: "NET-001",
                title: "Application Firewall Disabled",
                description: "macOS Application Firewall is disabled.",
                evidence: result.output.trimmingCharacters(in: .whitespacesAndNewlines),
                remediation: "Enable firewall in System Settings > Network > Firewall",
                riskLevel: .high,
                mitreAttackID: "T1562.004"
            ))
        }

        let stealth = Shell.run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getstealthmode"])
        if stealth.output.lowercased().contains("disabled") {
            findings.append(Finding(
                id: "NET-002",
                title: "Stealth Mode Disabled",
                description: "Stealth mode is disabled, system responds to ICMP probes.",
                evidence: stealth.output.trimmingCharacters(in: .whitespacesAndNewlines),
                remediation: "Enable stealth mode in firewall settings",
                riskLevel: .low,
                mitreAttackID: nil
            ))
        }

        return findings
    }

    private func checkListeningPorts(quick: Bool) -> [Finding] {
        var findings: [Finding] = []
        let result = Shell.run("/usr/sbin/lsof", ["-iTCP", "-sTCP:LISTEN", "-n", "-P"])
        guard !result.output.isEmpty else { return findings }

        let commonPorts: Set<Int> = [
            22, 53, 80, 443, 445, 548, 631, 5353, 5900, 5000, 7000
        ]

        for line in result.output.split(separator: "\n").dropFirst() {
            let parts = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard parts.count >= 9 else { continue }

            let process = parts[0]
            let nameField = parts.last ?? ""
            let port = parsePort(from: nameField)

            guard let portValue = port else { continue }
            if commonPorts.contains(portValue) && quick { continue }

            let risk: RiskLevel = portValue < 1024 ? .medium : .low
            findings.append(Finding(
                id: "NET-LISTEN-\(portValue)",
                title: "Listening Port Detected: \(portValue)",
                description: "A process is listening on a network port.",
                evidence: "Process: \(process) | Listener: \(nameField)",
                remediation: "Verify the service is expected; disable if unnecessary.",
                riskLevel: risk,
                mitreAttackID: "T1571"
            ))
        }

        return findings
    }

    private func checkEstablishedConnections(quick: Bool) -> [Finding] {
        var findings: [Finding] = []
        let result = Shell.run("/usr/sbin/lsof", ["-iTCP", "-sTCP:ESTABLISHED", "-n", "-P"])
        guard !result.output.isEmpty else { return findings }

        let suspiciousPorts: Set<Int> = [4444, 1337, 31337, 9001]

        for line in result.output.split(separator: "\n").dropFirst() {
            let parts = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard parts.count >= 9 else { continue }

            let process = parts[0]
            let nameField = parts.last ?? ""
            let (localPort, remotePort, remoteHost) = parseConnection(from: nameField)

            guard let rPort = remotePort else { continue }
            if quick && suspiciousPorts.isEmpty { continue }

            let risk: RiskLevel = suspiciousPorts.contains(rPort) ? .high : .low
            let description = suspiciousPorts.contains(rPort)
                ? "Established connection to a suspicious remote port."
                : "Established outbound connection detected."

            findings.append(Finding(
                id: "NET-CONN-\(localPort ?? 0)-\(rPort)",
                title: "Outbound Connection to Port \(rPort)",
                description: description,
                evidence: "Process: \(process) | Connection: \(nameField) | Remote: \(remoteHost ?? "unknown")",
                remediation: "Investigate remote endpoint and process behavior.",
                riskLevel: risk,
                mitreAttackID: "T1071"
            ))
        }

        return findings
    }

    private func parsePort(from nameField: String) -> Int? {
        guard let colon = nameField.lastIndex(of: ":") else { return nil }
        let portString = nameField[nameField.index(after: colon)...]
        return Int(portString)
    }

    private func parseConnection(from nameField: String) -> (Int?, Int?, String?) {
        // Example: 127.0.0.1:55362->93.184.216.34:443
        let parts = nameField.components(separatedBy: "->")
        guard parts.count == 2 else { return (nil, nil, nil) }

        let local = parts[0]
        let remote = parts[1]

        let localPort = parsePort(from: local)
        let remotePort = parsePort(from: remote)
        let remoteHost = remote.split(separator: ":").first.map(String.init)

        return (localPort, remotePort, remoteHost)
    }
}
