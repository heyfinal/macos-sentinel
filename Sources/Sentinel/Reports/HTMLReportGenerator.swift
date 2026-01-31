import Foundation

public struct HTMLReportGenerator {
    public init() {}

    public func generate(from results: ScanResults) -> String {
        let rows = results.categories.map { category in
            let findingsHTML = category.findings.map { finding in
                let actions = suggestedActions(for: finding)
                let commandLines = actions.commands.map { "<code>\(escape($0))</code>" }.joined(separator: "<br/>")
                let linkLines = actions.links.map { "<a href=\"\($0.url)\">\($0.label)</a>" }.joined(separator: " | ")
                let riskClass = "risk-\(finding.riskLevel.rawValue.lowercased())"
                return """
                <div class=\"finding\">
                  <div class=\"title\"><span class=\"\(riskClass)\">[\(finding.riskLevel.rawValue)]</span> \(escape(finding.title))</div>
                  <div class=\"desc\">\(escape(finding.description))</div>
                  <pre>\(escape(finding.evidence))</pre>
                  <div class=\"rem\"><strong>Remediation:</strong> \(escape(finding.remediation))</div>
                  <div class=\"rem\"><strong>Suggested Actions:</strong> \(escape(actions.summary))</div>
                  \(commandLines.isEmpty ? "" : "<div class=\"rem\"><strong>Commands:</strong><br/>\(commandLines)</div>")
                  \(linkLines.isEmpty ? "" : "<div class=\"rem\"><strong>Links:</strong> \(linkLines)</div>")
                </div>
                """
            }.joined(separator: "\n")

            return """
            <section>
              <h2>\(escape(category.name)) (\(category.findings.count))</h2>
              \(findingsHTML)
            </section>
            """
        }.joined(separator: "\n")
        let actionSection = renderActionResults(results.actionResults)

        return """
        <!doctype html>
        <html lang=\"en\">
        <head>
          <meta charset=\"utf-8\" />
          <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
          <title>McGuardian Report</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, Helvetica, Arial, sans-serif; margin: 24px; background: #1a1a2e; color: #eaeaea; }
            h1 { margin-bottom: 6px; color: #00d4ff; }
            h2 { margin-top: 24px; color: #00d4ff; border-bottom: 1px solid #333; padding-bottom: 8px; }
            .meta { color: #888; margin-bottom: 24px; }
            .finding { border: 1px solid #333; padding: 12px; margin: 12px 0; border-radius: 8px; background: #16213e; }
            .finding:hover { border-color: #00d4ff; }
            .title { font-weight: 600; margin-bottom: 6px; color: #fff; }
            .desc { color: #ccc; margin-bottom: 8px; }
            .rem { color: #aaa; margin-top: 8px; }
            .rem strong { color: #00d4ff; }
            pre { background: #0f0f23; padding: 12px; overflow-x: auto; border-radius: 6px; color: #0f0; font-size: 13px; }
            code { background: #0f0f23; padding: 2px 6px; border-radius: 4px; color: #0f0; }
            a { color: #00d4ff; text-decoration: none; }
            a:hover { text-decoration: underline; }
            .risk-critical { color: #ff4757; }
            .risk-high { color: #ffa502; }
            .risk-medium { color: #ffdd59; }
            .risk-low { color: #7bed9f; }
            .risk-info { color: #70a1ff; }
          </style>
        </head>
        <body>
          <h1>McGuardian Report</h1>
          <div class=\"meta\">Host: \(escape(results.host)) | Generated: \(results.generatedAt)</div>
          <div class=\"meta\">Overall Risk: \(results.overallRisk.rawValue) | Total Findings: \(results.allFindings.count)</div>
          \(actionSection)
          \(rows)
        </body>
        </html>
        """
    }

    private func escape(_ value: String) -> String {
        value
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#39;")
    }

    private func renderActionResults(_ results: [ActionResult]) -> String {
        guard !results.isEmpty else { return "" }
        let items = results.map { result in
            let abbrev = statusAbbrev(result.status)
            let commandBlocks = result.commands.map { command in
                """
                <div class=\"finding\">
                  <div class=\"title\">Command: \(escape(command.command)) [\(command.status.rawValue.uppercased())]</div>
                  <pre>\(escape(command.output))</pre>
                </div>
                """
            }.joined(separator: "\n")

            return """
            <section>
              <h2>Applied Action: \(escape(result.title)) [\(abbrev)]</h2>
              <div class=\"rem\"><strong>Summary:</strong> \(escape(result.summary))</div>
              \(commandBlocks)
            </section>
            """
        }.joined(separator: "\n")

        return """
        <section>
          <h2>Applied Actions</h2>
          \(items)
        </section>
        """
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
