import Foundation

public struct HTMLReportGenerator {
    public init() {}

    public func generate(from results: ScanResults) -> String {
        let rows = results.categories.map { category in
            let findingsHTML = category.findings.map { finding in
                let actions = suggestedActions(for: finding)
                let commandLines = actions.commands.map { "<code>\(escape($0))</code>" }.joined(separator: "<br/>")
                let linkLines = actions.links.map { "<a href=\"\($0.url)\">\($0.label)</a>" }.joined(separator: " | ")
                return """
                <div class=\"finding\">
                  <div class=\"title\">[\(finding.riskLevel.rawValue)] \(escape(finding.title))</div>
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
          <title>macOS Sentinel Report</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, Helvetica, Arial, sans-serif; margin: 24px; color: #1b1b1b; }
            h1 { margin-bottom: 6px; }
            h2 { margin-top: 24px; }
            .meta { color: #555; margin-bottom: 24px; }
            .finding { border: 1px solid #ddd; padding: 12px; margin: 12px 0; border-radius: 8px; }
            .title { font-weight: 600; margin-bottom: 6px; }
            pre { background: #f7f7f7; padding: 8px; overflow-x: auto; }
            code { background: #f7f7f7; padding: 2px 4px; border-radius: 4px; }
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
