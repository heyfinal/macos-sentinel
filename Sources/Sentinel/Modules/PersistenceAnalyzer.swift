import Foundation

actor PersistenceAnalyzer: AnalyzerModule {
    let name = "Persistence"

    func run(quick: Bool) async throws -> [Finding] {
        var findings: [Finding] = []
        findings.append(contentsOf: scanLaunchItems(quick: quick))
        findings.append(contentsOf: scanCron())
        findings.append(contentsOf: scanLoginItems())
        findings.append(contentsOf: scanKernelExtensions(quick: quick))
        return findings
    }

    // Known legitimate vendors - not flagged as suspicious
    private let trustedVendorPrefixes = [
        "com.apple",
        "com.google",
        "com.microsoft",
        "com.adobe",
        "com.docker",
        "com.jetbrains",
        "com.github",
        "com.dropbox",
        "com.spotify",
        "com.slack",
        "com.zoom",
        "com.1password",
        "com.agilebits",
        "com.parallels",
        "com.vmware",
        "com.mozilla",
        "org.mozilla",
        "com.brave",
        "io.tailscale",
        "com.logitech",
        "com.elgato",
        "com.alfred",
        "com.raycast",
        "com.sublimetext",
        "com.visualstudio",
        "com.oracle",
        "com.nvidia",
        "com.intel",
        "com.hp.",
        "com.epson",
        "com.brother",
        "com.canon"
    ]

    // Suspicious patterns in plist names
    private let suspiciousPlistPatterns = [
        "hidden",
        "stealth",
        "backdoor",
        "reverse",
        "shell",
        "payload",
        "beacon",
        "implant",
        "rat",
        "keylog",
        "dump",
        "inject"
    ]

    private func scanLaunchItems(quick: Bool) -> [Finding] {
        var findings: [Finding] = []
        let paths = [
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            NSHomeDirectory() + "/Library/LaunchAgents"
        ]

        for path in paths {
            guard let items = try? FileManager.default.contentsOfDirectory(atPath: path) else { continue }
            for item in items where item.hasSuffix(".plist") {
                let lower = item.lowercased()

                // Check if from trusted vendor
                let isTrusted = trustedVendorPrefixes.contains { lower.hasPrefix($0) }

                // Check for explicitly suspicious patterns
                let hasSuspiciousName = suspiciousPlistPatterns.contains { lower.contains($0) }

                // Check for suspicious characteristics
                let fullPath = "\(path)/\(item)"
                let hasSuspiciousPath = checkPlistForSuspiciousContent(at: fullPath)

                // Determine risk level
                let riskLevel: RiskLevel
                if hasSuspiciousName || hasSuspiciousPath {
                    riskLevel = .high
                } else if isTrusted {
                    riskLevel = .info
                } else {
                    // Unknown vendor - medium risk, worth reviewing
                    riskLevel = .low
                }

                // In quick mode, only report high-risk items
                if quick && riskLevel != .high { continue }
                // In full mode, skip info-level trusted items
                if !quick && riskLevel == .info { continue }

                findings.append(Finding(
                    id: "PERSIST-LAUNCH-\(item)",
                    title: riskLevel == .high ? "Suspicious Launch Item" : "Third-Party Launch Item",
                    description: riskLevel == .high
                        ? "LaunchAgent/Daemon has suspicious characteristics."
                        : "Third-party LaunchAgent/Daemon configured to start automatically.",
                    evidence: "Path: \(fullPath)",
                    remediation: riskLevel == .high
                        ? "Investigate immediately - this plist has suspicious indicators."
                        : "Review the plist and verify it belongs to software you installed.",
                    riskLevel: riskLevel,
                    mitreAttackID: "T1543.001"
                ))
            }
        }

        return findings
    }

    private func checkPlistForSuspiciousContent(at path: String) -> Bool {
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { return false }
        let lower = content.lowercased()

        // Suspicious program paths
        let suspiciousPaths = [
            "/tmp/",
            "/var/tmp/",
            "/users/shared/",
            "/.hidden",
            "/dev/tcp",
            "curl",
            "wget"
        ]

        // Check for programs running from suspicious locations
        for suspPath in suspiciousPaths {
            if lower.contains("<string>\(suspPath)") || lower.contains("<string>/\(suspPath)") {
                return true
            }
        }

        // Check for base64 encoded content (common in malware)
        if lower.contains("base64") && (lower.contains("bash") || lower.contains("sh</string>")) {
            return true
        }

        return false
    }

    private func scanCron() -> [Finding] {
        var findings: [Finding] = []
        let result = Shell.run("/usr/bin/crontab", ["-l"])
        if result.exitCode == 0 && !result.output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            findings.append(Finding(
                id: "PERSIST-CRON-USER",
                title: "User Crontab Entries Present",
                description: "Scheduled cron jobs can be used for persistence.",
                evidence: result.output.trimmingCharacters(in: .whitespacesAndNewlines),
                remediation: "Review crontab entries and remove unknown jobs.",
                riskLevel: .medium,
                mitreAttackID: "T1053.003"
            ))
        }

        let systemCron = "/etc/crontab"
        if let content = try? String(contentsOfFile: systemCron, encoding: .utf8), !content.isEmpty {
            findings.append(Finding(
                id: "PERSIST-CRON-SYSTEM",
                title: "System Crontab Entries Present",
                description: "System crontab has entries that run on schedules.",
                evidence: content.trimmingCharacters(in: .whitespacesAndNewlines),
                remediation: "Review /etc/crontab for unexpected entries.",
                riskLevel: .low,
                mitreAttackID: "T1053.003"
            ))
        }

        return findings
    }

    private func scanLoginItems() -> [Finding] {
        let result = Shell.run("/usr/bin/osascript", ["-e", "tell application \"System Events\" to get the name of every login item"])
        let items = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
        if result.exitCode == 0 && !items.isEmpty {
            return [Finding(
                id: "PERSIST-LOGINITEMS",
                title: "Login Items Detected",
                description: "Login items run on user sign-in.",
                evidence: items,
                remediation: "Remove unexpected login items in System Settings.",
                riskLevel: .medium,
                mitreAttackID: "T1547.011"
            )]
        }
        return []
    }

    private func scanKernelExtensions(quick: Bool) -> [Finding] {
        var findings: [Finding] = []
        let result = Shell.run("/usr/sbin/kextstat", ["-l"])
        guard result.exitCode == 0 else { return findings }

        for line in result.output.split(separator: "\n").dropFirst() {
            let lower = line.lowercased()
            if lower.contains("no variant specified") { continue }
            if !lower.contains("com.") { continue }
            let suspicious = !(lower.contains("com.apple") || lower.contains("com.apple.driver"))
            if quick && !suspicious { continue }

            findings.append(Finding(
                id: "PERSIST-KEXT",
                title: "Kernel Extension Loaded",
                description: "Kernel extensions can provide persistence and deep system access.",
                evidence: String(line),
                remediation: "Review loaded kexts and remove unauthorized extensions.",
                riskLevel: suspicious ? .high : .info,
                mitreAttackID: "T1547.006"
            ))
        }

        return findings
    }
}
