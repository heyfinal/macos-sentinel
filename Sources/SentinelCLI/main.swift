import Foundation
import Darwin
import ArgumentParser
import Sentinel

@main
struct SentinelCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "mcguardian",
        abstract: "McGuardian - Comprehensive macOS security analyzer",
        version: Sentinel.version,
        subcommands: [Scan.self, Report.self, Watch.self]
    )
}

struct Scan: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Run comprehensive security scan"
    )

    @Flag(name: .shortAndLong, help: "Quick scan (reduced depth)")
    var quick: Bool = false

    @Flag(name: .shortAndLong, help: "Include ML anomaly detection guidance")
    var ml: Bool = false

    @Option(name: .long, parsing: .upToNextOption, help: "Run only specific modules (system, network, persistence, malware, forensics)")
    var module: [String] = []

    @Option(name: .shortAndLong, help: "Output format (json, html, text)")
    var format: String = "text"

    @Option(name: .shortAndLong, help: "Output file path")
    var output: String?

    func run() async throws {
        printBanner()
        let orchestrator = try ScanOrchestrator(moduleKeys: module)
        var results = try await orchestrator.runFullScan(quick: quick, includeML: ml)
        let actionResults = applySuggestedActions(for: results)
        if !actionResults.isEmpty {
            results = ScanResults(
                categories: results.categories,
                actionResults: actionResults,
                generatedAt: results.generatedAt,
                host: results.host
            )
        }

        switch format.lowercased() {
        case "json":
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(results)
            try write(data: data, to: output)
        case "html":
            let report = HTMLReportGenerator().generate(from: results)
            let path = try write(text: report, to: output, defaultName: "mcguardian_report.html")
            openReport(at: path)
        default:
            printTextReport(results)
        }

        autoLaunchReportIfNeeded(results: results, format: format, output: output)
    }

    private func printBanner() {
        adjustTerminalWidth()
        let lightBlue = "\u{001B}[96m"
        let reset = "\u{001B}[0m"
        let banner = [
            "                                                                       ,,    ,,",
            "`7MMM.     ,MMF'          .g8\"\"\"bgd                                  `7MM    db",
            "  MMMb    dPMM          .dP'     `M                                    MM",
            "  M YM   ,M MM  ,p6\"bo  dM'       ``7MM  `7MM   ,6\"Yb.  `7Mb,od8  ,M\"\"bMM  `7MM   ,6\"Yb.  `7MMpMMMb.",
            "  M  Mb  M' MM 6M'  OO  MM           MM    MM  8)   MM    MM' \"',AP    MM    MM  8)   MM    MM    MM",
            "  M  YM.P'  MM 8M       MM.    `7MMF'MM    MM   ,pm9MM    MM    8MI    MM    MM   ,pm9MM    MM    MM",
            "  M  `YM'   MM YM.    , `Mb.     MM  MM    MM  8M   MM    MM    `Mb    MM    MM  8M   MM    MM    MM",
            ".JML. `'  .JMML.YMbmd'    `\"bmmmdPY  `Mbod\"YML.`Moo9^Yo..JMML.   `Wbmd\"MML..JMML.`Moo9^Yo..JMML  JMML.",
            "",
            "                             McGuardian • macOS Security Analyzer"
        ].joined(separator: "\n")
        print("\(lightBlue)\(banner)\(reset)")
    }

    private func adjustTerminalWidth() {
        var size = winsize()
        if ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0, size.ws_col > 0 {
            let currentCols = Int(size.ws_col)
            let currentRows = Int(size.ws_row)
            let targetCols = min(Int(Double(currentCols) * 1.2), 400)
            if targetCols > currentCols {
                print("\u{001B}[8;\(currentRows);\(targetCols)t", terminator: "")
            }
        }
    }

    private func write(data: Data, to output: String?) throws {
        if let output = output {
            try data.write(to: URL(fileURLWithPath: output))
            print("Wrote output to \(output)")
        } else {
            print(String(data: data, encoding: .utf8) ?? "")
        }
    }

    private func write(text: String, to output: String?, defaultName: String) throws -> String {
        if let output = output {
            try text.write(toFile: output, atomically: true, encoding: .utf8)
            print("Wrote output to \(output)")
            return output
        } else {
            let path = "/tmp/\(defaultName)"
            try text.write(toFile: path, atomically: true, encoding: .utf8)
            print("Wrote output to \(path)")
            return path
        }
    }

    private func printTextReport(_ results: ScanResults) {
        let riskColors: [String: String] = [
            "CRITICAL": "\u{001B}[31m",
            "HIGH": "\u{001B}[33m",
            "MEDIUM": "\u{001B}[36m",
            "LOW": "\u{001B}[32m",
            "INFO": "\u{001B}[37m"
        ]
        let reset = "\u{001B}[0m"

        print("\nSCAN RESULTS")
        print("═══════════════════════════════════════════════════════════\n")

        for category in results.categories {
            print("▶ \(category.name): \(category.findings.count) findings")
            for finding in category.findings {
                let color = riskColors[finding.riskLevel.rawValue] ?? ""
                print("  \(color)[\(finding.riskLevel.rawValue)]\(reset) \(finding.title)")
                print("    └─ \(finding.description)")
            }
            print("")
        }

        let critical = results.allFindings.filter { $0.riskLevel == .critical }.count
        let high = results.allFindings.filter { $0.riskLevel == .high }.count

        print("═══════════════════════════════════════════════════════════")
        print("SUMMARY: \(results.allFindings.count) total findings")
        print("  CRITICAL: \(critical)")
        print("  HIGH: \(high)")
        print("═══════════════════════════════════════════════════════════\n")

        if critical > 0 {
            print("CRITICAL FINDINGS REQUIRE IMMEDIATE ATTENTION")
        }
    }

    private func openReport(at path: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        process.arguments = [path]
        try? process.run()
    }

    private func autoLaunchReportIfNeeded(results: ScanResults, format: String, output: String?) {
        if format.lowercased() == "html" { return }
        let report = HTMLReportGenerator().generate(from: results)
        if let output = output, output.lowercased().hasSuffix(".html") {
            if (try? write(text: report, to: output, defaultName: "mcguardian_report.html")) != nil {
                openReport(at: output)
            }
            return
        }
        if let path = try? write(text: report, to: nil, defaultName: "mcguardian_report.html") {
            openReport(at: path)
        }
    }

    private func applySuggestedActions(for results: ScanResults) -> [ActionResult] {
        let actionable = results.allFindings.map { ($0, suggestedActions(for: $0)) }
            .filter { !$0.1.commands.isEmpty }
        guard !actionable.isEmpty else { return [] }

        let needsSudo = actionable.contains { _, suggestion in
            suggestion.commands.contains { $0.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("sudo ") }
        }
        if needsSudo {
            print("Applying suggested actions requires admin privileges. Authenticating...")
            let sudoCheck = runCommand("sudo -v", timeout: 10)
            if sudoCheck.exitCode != 0 {
                let output = sudoCheck.output.isEmpty ? "sudo authentication failed." : sudoCheck.output
                return actionable.map { finding, suggestion in
                    ActionResult(
                        findingId: finding.id,
                        title: finding.title,
                        summary: "\(suggestion.summary) (sudo failed)",
                        status: .failed,
                        commands: [
                            ActionCommandResult(
                                command: "sudo -v",
                                status: .failed,
                                output: output
                            )
                        ]
                    )
                }
            }
        }

        var actionResults: [ActionResult] = []
        for (finding, suggestion) in actionable {
            var commandResults: [ActionCommandResult] = []
            var success = true
            for command in suggestion.commands {
                let result = runCommand(command, timeout: 20)
                let status: ActionCommandStatus = result.exitCode == 0 ? .success : .failed
                if status == .failed { success = false }
                let output = result.output.isEmpty ? (result.exitCode == -1 ? "Command timed out." : "(no output)") : result.output
                commandResults.append(ActionCommandResult(
                    command: command,
                    status: status,
                    output: output
                ))
            }

            actionResults.append(ActionResult(
                findingId: finding.id,
                title: finding.title,
                summary: suggestion.summary,
                status: success ? .applied : .failed,
                commands: commandResults
            ))
        }

        return actionResults
    }


    private func statusAbbrev(_ status: ActionStatus) -> String {
        switch status {
        case .applied:
            return "APPL"
        case .skipped:
            return "SKIP"
        case .failed:
            return "FAIL"
        }
    }

    private struct CommandExecutionResult {
        let output: String
        let exitCode: Int32
    }

    private func runCommand(_ command: String, timeout: TimeInterval) -> CommandExecutionResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", command]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
        } catch {
            return CommandExecutionResult(output: "Failed to launch command.", exitCode: -1)
        }

        var didTimeout = false
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global())
        timer.schedule(deadline: .now() + timeout)
        timer.setEventHandler {
            if process.isRunning {
                didTimeout = true
                process.terminate()
            }
        }
        timer.resume()

        process.waitUntilExit()
        timer.cancel()

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        let exitCode: Int32 = didTimeout ? -1 : process.terminationStatus
        return CommandExecutionResult(output: output.trimmingCharacters(in: .whitespacesAndNewlines), exitCode: exitCode)
    }
}

struct Watch: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Real-time security monitoring"
    )

    func run() async throws {
        let monitor = try RealtimeMonitor()
        try await monitor.start()
    }
}

struct Report: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Generate security report from existing JSON"
    )

    @Argument(help: "Input findings JSON")
    var input: String

    @Option(name: .shortAndLong, help: "Output format (html, pdf, markdown)")
    var format: String = "html"

    @Option(name: .shortAndLong, help: "Output file path")
    var output: String

    func run() async throws {
        let data = try Data(contentsOf: URL(fileURLWithPath: input))
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let results = try decoder.decode(ScanResults.self, from: data)

        switch format.lowercased() {
        case "pdf":
            try PDFReportGenerator().generate(from: results, outputPath: output)
        case "markdown":
            let text = markdownReport(from: results)
            try text.write(toFile: output, atomically: true, encoding: .utf8)
        default:
            let html = HTMLReportGenerator().generate(from: results)
            try html.write(toFile: output, atomically: true, encoding: .utf8)
        }

        print("Wrote report to \(output)")
    }

    private func markdownReport(from results: ScanResults) -> String {
        var output = "# McGuardian Report\n\n"
        output += "Host: \(results.host)\n\n"
        output += "Generated: \(results.generatedAt)\n\n"
        output += "Overall Risk: \(results.overallRisk.rawValue)\n\n"

        if !results.actionResults.isEmpty {
            output += "## Applied Actions\n\n"
            for action in results.actionResults {
                output += "- [\(statusAbbrev(action.status))] \(action.title)\n"
                output += "  - Summary: \(action.summary)\n"
                if !action.commands.isEmpty {
                    output += "  - Commands:\n"
                    for command in action.commands {
                        output += "    - `\(command.command)` [\(command.status.rawValue.uppercased())]\n"
                        if !command.output.isEmpty {
                            let normalized = command.output.replacingOccurrences(of: "\n", with: " ")
                            output += "      - Output: \(normalized)\n"
                        }
                    }
                }
            }
            output += "\n"
        }

        for category in results.categories {
            output += "## \(category.name) (\(category.findings.count))\n\n"
            for finding in category.findings {
                let actions = suggestedActions(for: finding)
                output += "- [\(finding.riskLevel.rawValue)] \(finding.title)\n"
                output += "  - \(finding.description)\n"
                output += "  - Evidence: \(finding.evidence)\n"
                output += "  - Remediation: \(finding.remediation)\n"
                output += "  - Suggested Actions: \(actions.summary)\n"
                if !actions.commands.isEmpty {
                    output += "  - Commands:\n"
                    for command in actions.commands {
                        output += "    - `\(command)`\n"
                    }
                }
                if !actions.links.isEmpty {
                    output += "  - Links:\n"
                    for link in actions.links {
                        output += "    - [\(link.label)](\(link.url))\n"
                    }
                }
            }
            output += "\n"
        }

        return output
    }

    private func statusAbbrev(_ status: ActionStatus) -> String {
        switch status {
        case .applied:
            return "APPL"
        case .skipped:
            return "SKIP"
        case .failed:
            return "FAIL"
        }
    }
}
