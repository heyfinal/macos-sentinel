import Foundation

actor SystemAnalyzer: AnalyzerModule {
    let name = "System Security"

    func run(quick: Bool) async throws -> [Finding] {
        var findings: [Finding] = []

        if let sip = checkSIPStatus() { findings.append(sip) }
        if let gk = checkGatekeeperStatus() { findings.append(gk) }
        findings.append(contentsOf: analyzeTCCDatabase(quick: quick))
        findings.append(contentsOf: auditSSHConfiguration())
        findings.append(contentsOf: auditRemoteAccess())

        return findings
    }

    private func checkSIPStatus() -> Finding? {
        let result = Shell.run("/usr/bin/csrutil", ["status"])
        guard result.exitCode == 0 else { return nil }

        if result.output.lowercased().contains("disabled") {
            return Finding(
                id: "SYS-001",
                title: "System Integrity Protection Disabled",
                description: "SIP is disabled, allowing modification of protected system files.",
                evidence: result.output.trimmingCharacters(in: .whitespacesAndNewlines),
                remediation: "Enable SIP in Recovery Mode: csrutil enable",
                riskLevel: .high,
                mitreAttackID: "T1562.001"
            )
        }
        return nil
    }

    private func checkGatekeeperStatus() -> Finding? {
        let result = Shell.run("/usr/sbin/spctl", ["--status"])
        guard result.exitCode == 0 else { return nil }

        if result.output.lowercased().contains("disabled") {
            return Finding(
                id: "SYS-002",
                title: "Gatekeeper Disabled",
                description: "Gatekeeper is disabled, allowing unsigned apps to run.",
                evidence: result.output.trimmingCharacters(in: .whitespacesAndNewlines),
                remediation: "Enable Gatekeeper: sudo spctl --master-enable",
                riskLevel: .high,
                mitreAttackID: "T1553.001"
            )
        }
        return nil
    }

    private func analyzeTCCDatabase(quick: Bool) -> [Finding] {
        var findings: [Finding] = []
        let tccPaths = [
            "/Library/Application Support/com.apple.TCC/TCC.db",
            NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db"
        ]

        for path in tccPaths {
            guard FileManager.default.fileExists(atPath: path) else { continue }
            let query = "SELECT client, service, auth_value, auth_reason FROM access WHERE auth_value = 2;"
            let result = Shell.run("/usr/bin/sqlite3", [path, query])
            guard result.exitCode == 0 else { continue }

            let suspiciousPatterns = [
                "com.unknown",
                "nc", "ncat", "netcat",
                "socat", "python", "ruby", "perl",
                "terminal", "iterm", "bash", "zsh", "sh"
            ]

            for line in result.output.split(separator: "\n") {
                let entry = String(line)
                if !entry.contains("kTCCServiceSystemPolicyAllFiles") { continue }

                let lowered = entry.lowercased()
                if suspiciousPatterns.contains(where: { lowered.contains($0) }) {
                    findings.append(Finding(
                        id: "TCC-001",
                        title: "Suspicious Full Disk Access Grant",
                        description: "A potentially dangerous application has Full Disk Access.",
                        evidence: entry,
                        remediation: "Review and revoke in System Settings > Privacy & Security.",
                        riskLevel: .high,
                        mitreAttackID: "T1548"
                    ))
                } else if !quick {
                    findings.append(Finding(
                        id: "TCC-INFO",
                        title: "Full Disk Access Grant",
                        description: "An application has Full Disk Access.",
                        evidence: entry,
                        remediation: "Review to confirm it is expected.",
                        riskLevel: .info,
                        mitreAttackID: "T1548"
                    ))
                }
            }
        }

        return findings
    }

    private func auditSSHConfiguration() -> [Finding] {
        var findings: [Finding] = []

        let sharingPrefs = "/Library/Preferences/SystemConfiguration/com.apple.RemoteAccessServers.plist"
        if FileManager.default.fileExists(atPath: sharingPrefs) {
            let result = Shell.run("/usr/sbin/systemsetup", ["-getremotelogin"])
            if result.output.lowercased().contains("on") {
                findings.append(Finding(
                    id: "SSH-001",
                    title: "Remote Login (SSH) Enabled",
                    description: "SSH access is enabled, allowing remote shell access.",
                    evidence: result.output.trimmingCharacters(in: .whitespacesAndNewlines),
                    remediation: "Disable: sudo systemsetup -setremotelogin off",
                    riskLevel: .medium,
                    mitreAttackID: "T1021.004"
                ))
            }
        }

        let authorizedKeysPath = NSHomeDirectory() + "/.ssh/authorized_keys"
        if FileManager.default.fileExists(atPath: authorizedKeysPath) {
            if let content = try? String(contentsOfFile: authorizedKeysPath, encoding: .utf8), !content.isEmpty {
                findings.append(Finding(
                    id: "SSH-002",
                    title: "SSH Authorized Keys Present",
                    description: "Public keys found that allow passwordless SSH access.",
                    evidence: "File: \(authorizedKeysPath)\nKeys: \(content.split(separator: "\n").count)",
                    remediation: "Review and remove unauthorized keys from ~/.ssh/authorized_keys",
                    riskLevel: .high,
                    mitreAttackID: "T1098.004"
                ))
            }
        }

        let sshdConfig = "/etc/ssh/sshd_config"
        if let config = try? String(contentsOfFile: sshdConfig, encoding: .utf8) {
            if config.contains("PermitRootLogin yes") {
                findings.append(Finding(
                    id: "SSH-003",
                    title: "Root SSH Login Permitted",
                    description: "SSH configuration allows direct root login.",
                    evidence: "PermitRootLogin yes in /etc/ssh/sshd_config",
                    remediation: "Set PermitRootLogin to 'no' in sshd_config",
                    riskLevel: .critical,
                    mitreAttackID: "T1078.003"
                ))
            }

            if config.contains("PasswordAuthentication yes") {
                findings.append(Finding(
                    id: "SSH-004",
                    title: "SSH Password Authentication Enabled",
                    description: "SSH allows password-based authentication (brute-force risk).",
                    evidence: "PasswordAuthentication yes",
                    remediation: "Set PasswordAuthentication to 'no', use key-based auth",
                    riskLevel: .medium,
                    mitreAttackID: "T1110"
                ))
            }
        }

        return findings
    }

    private func auditRemoteAccess() -> [Finding] {
        var findings: [Finding] = []

        let result = Shell.run("/usr/bin/defaults", ["read", "/Library/Preferences/com.apple.RemoteManagement", "ARD_AllLocalUsers"])
        if result.exitCode == 0 {
            findings.append(Finding(
                id: "VNC-001",
                title: "Apple Remote Desktop Enabled",
                description: "Remote Desktop/Screen Sharing may be active.",
                evidence: "com.apple.RemoteManagement preferences exist",
                remediation: "Disable in System Settings > Sharing > Screen Sharing",
                riskLevel: .high,
                mitreAttackID: "T1021.005"
            ))
        }

        let vncPorts = [5900, 5901, 5902]
        for port in vncPorts {
            if isPortListening(port: port) {
                findings.append(Finding(
                    id: "VNC-002",
                    title: "VNC Server Listening on Port \(port)",
                    description: "A VNC server is actively listening for connections.",
                    evidence: "Port \(port) is open and listening",
                    remediation: "Identify and stop the VNC server process",
                    riskLevel: .critical,
                    mitreAttackID: "T1021.005"
                ))
            }
        }

        return findings
    }

    private func isPortListening(port: Int) -> Bool {
        let result = Shell.run("/usr/sbin/lsof", ["-i", ":\(port)", "-sTCP:LISTEN"])
        return !result.output.isEmpty
    }
}
