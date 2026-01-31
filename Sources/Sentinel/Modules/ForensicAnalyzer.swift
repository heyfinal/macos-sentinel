import Foundation

actor ForensicAnalyzer: AnalyzerModule {
    let name = "Forensics"

    func run(quick: Bool) async throws -> [Finding] {
        var findings: [Finding] = []
        findings.append(contentsOf: scanShellHistory())
        findings.append(contentsOf: checkKeychainModifications())
        if !quick {
            findings.append(contentsOf: scanRecentBinaries())
            findings.append(contentsOf: scanUnifiedLogs())
        }
        return findings
    }

    private func scanShellHistory() -> [Finding] {
        var findings: [Finding] = []
        let historyFiles = [
            NSHomeDirectory() + "/.zsh_history",
            NSHomeDirectory() + "/.bash_history"
        ]

        // Malicious patterns - NOT just common tools
        // These detect actual attack patterns, not legitimate usage
        let maliciousPatterns: [(pattern: String, description: String, severity: RiskLevel)] = [
            // Remote code execution
            ("curl.*\\|.*sh", "curl pipe to shell (remote code exec)", .critical),
            ("wget.*\\|.*sh", "wget pipe to shell (remote code exec)", .critical),
            ("curl.*\\|.*bash", "curl pipe to bash (remote code exec)", .critical),

            // Reverse shells
            ("bash -i >& /dev/tcp", "bash reverse shell", .critical),
            ("/dev/tcp/", "bash /dev/tcp network connection", .high),
            ("nc -e /bin", "netcat reverse shell", .critical),
            ("nc.*-e.*sh", "netcat with shell execution", .critical),
            ("ncat.*--exec", "ncat with command execution", .critical),
            ("mkfifo.*nc", "named pipe netcat backdoor", .critical),

            // Python/Ruby shells
            ("python.*socket.*connect.*exec", "python reverse shell", .critical),
            ("python.*pty.spawn", "python PTY shell spawn", .high),
            ("ruby.*TCPSocket.*exec", "ruby reverse shell", .critical),

            // Credential theft
            ("security dump-keychain", "keychain credential dump", .critical),
            ("security find.*-w", "keychain password extraction", .high),
            ("sqlite3.*TCC.db", "TCC database manipulation", .critical),

            // Persistence installation
            ("launchctl.*load.*tmp", "launchctl loading from /tmp", .high),
            ("launchctl.*load.*hidden", "launchctl loading hidden file", .high),
            ("crontab.*curl", "cron with remote download", .high),

            // Privilege escalation
            ("sudo.*NOPASSWD", "sudo NOPASSWD configuration", .high),
            ("chmod.*4755", "setuid bit modification", .high),
            ("chmod.*u\\+s", "setuid bit modification", .high),

            // Enumeration (may indicate recon)
            ("base64 -d.*\\|.*sh", "base64 decode to shell", .critical),
            ("base64 --decode.*\\|.*sh", "base64 decode to shell", .critical),
            ("echo.*\\|.*base64.*-d.*\\|.*sh", "encoded payload execution", .critical),
        ]

        for file in historyFiles {
            guard let content = try? String(contentsOfFile: file, encoding: .utf8) else { continue }
            let contentLower = content.lowercased()

            for (pattern, desc, severity) in maliciousPatterns {
                if let regex = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive) {
                    let range = NSRange(contentLower.startIndex..., in: contentLower)
                    if regex.firstMatch(in: contentLower, range: range) != nil {
                        findings.append(Finding(
                            id: "HIST-\(severity == .critical ? "CRIT" : "HIGH")",
                            title: "Malicious Command Pattern Detected",
                            description: "Shell history contains pattern indicative of attack: \(desc)",
                            evidence: "File: \(file) | Pattern: \(pattern)",
                            remediation: "Investigate immediately. This pattern is rarely used legitimately.",
                            riskLevel: severity,
                            mitreAttackID: "T1059"
                        ))
                    }
                }
            }
        }

        return findings
    }

    private func checkKeychainModifications() -> [Finding] {
        var findings: [Finding] = []
        let keychainPaths = [
            NSHomeDirectory() + "/Library/Keychains/login.keychain-db",
            NSHomeDirectory() + "/Library/Keychains/" + (NSUserName() + ".keychain-db"),
            "/Library/Keychains/System.keychain"
        ]

        for path in keychainPaths {
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
                  let modDate = attrs[.modificationDate] as? Date else { continue }
            let days = Calendar.current.dateComponents([.day], from: modDate, to: Date()).day ?? 0

            if days <= 1 {
                findings.append(Finding(
                    id: "KEY-001",
                    title: "Keychain Recently Modified",
                    description: "Keychain file was modified recently.",
                    evidence: "Path: \(path) | Modified: \(modDate)",
                    remediation: "Verify expected keychain changes.",
                    riskLevel: .low,
                    mitreAttackID: "T1555.001"
                ))
            }
        }

        return findings
    }

    private func scanRecentBinaries() -> [Finding] {
        var findings: [Finding] = []
        let roots = ["/Applications", "/Library/LaunchDaemons", "/Library/LaunchAgents"]
        let cutoff = Date().addingTimeInterval(-7 * 24 * 60 * 60)

        for root in roots {
            guard let enumerator = FileManager.default.enumerator(atPath: root) else { continue }
            while let file = enumerator.nextObject() as? String {
                let fullPath = root + "/" + file
                guard let attrs = try? FileManager.default.attributesOfItem(atPath: fullPath),
                      let modDate = attrs[.modificationDate] as? Date else { continue }
                if modDate < cutoff { continue }

                if file.hasSuffix(".app") || file.hasSuffix(".plist") {
                    findings.append(Finding(
                        id: "FORENSIC-RECENT",
                        title: "Recently Modified Security-Sensitive File",
                        description: "A sensitive location contains recently modified files.",
                        evidence: "Path: \(fullPath) | Modified: \(modDate)",
                        remediation: "Verify the file is expected and from a trusted source.",
                        riskLevel: .low,
                        mitreAttackID: "T1078"
                    ))
                }
            }
        }

        return findings
    }

    private func scanUnifiedLogs() -> [Finding] {
        let predicate = "eventMessage CONTAINS[c] 'ssh' OR eventMessage CONTAINS[c] 'RemoteDesktop'"
        let result = Shell.run("/usr/bin/log", ["show", "--last", "6h", "--predicate", predicate, "--style", "syslog"], timeout: 10)
        let output = result.output.trimmingCharacters(in: .whitespacesAndNewlines)

        if result.exitCode == 0 && !output.isEmpty {
            return [Finding(
                id: "LOG-001",
                title: "Security-Related Log Activity",
                description: "Unified logs contain entries related to remote access services.",
                evidence: String(output.prefix(2000)),
                remediation: "Review the logs in detail for unexpected access.",
                riskLevel: .info,
                mitreAttackID: "T1021"
            )]
        }

        return []
    }
}
