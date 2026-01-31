import Foundation

public struct PDFReportGenerator {
    public init() {}

    public enum PDFError: Error, LocalizedError {
        case notImplemented
        case conversionFailed(String)

        public var errorDescription: String? {
            switch self {
            case .notImplemented:
                return "PDF generation requires wkhtmltopdf. Install via: brew install wkhtmltopdf"
            case .conversionFailed(let reason):
                return "PDF conversion failed: \(reason)"
            }
        }
    }

    /// Generate PDF from scan results
    /// Requires wkhtmltopdf to be installed: brew install wkhtmltopdf
    public func generate(from results: ScanResults, outputPath: String) throws {
        // First generate HTML
        let html = HTMLReportGenerator().generate(from: results)

        // Create temp HTML file
        let tempHTML = NSTemporaryDirectory() + "sentinel_report_\(UUID().uuidString).html"
        try html.write(toFile: tempHTML, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: tempHTML) }

        // Try wkhtmltopdf first (best quality)
        if tryWkhtmltopdf(input: tempHTML, output: outputPath) {
            return
        }

        // Try cupsfilter (built-in but lower quality)
        if tryCupsfilter(input: tempHTML, output: outputPath) {
            return
        }

        // No PDF converter available - save as HTML with warning
        let htmlOutput = outputPath.replacingOccurrences(of: ".pdf", with: ".html")
        try html.write(toFile: htmlOutput, atomically: true, encoding: .utf8)

        throw PDFError.notImplemented
    }

    private func tryWkhtmltopdf(input: String, output: String) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/local/bin/wkhtmltopdf")
        process.arguments = ["--quiet", "--enable-local-file-access", input, output]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch {
            // Try homebrew arm64 path
            process.executableURL = URL(fileURLWithPath: "/opt/homebrew/bin/wkhtmltopdf")
            do {
                try process.run()
                process.waitUntilExit()
                return process.terminationStatus == 0
            } catch {
                return false
            }
        }
    }

    private func tryCupsfilter(input: String, output: String) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/cupsfilter")
        process.arguments = ["-m", "application/pdf", input]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()

            if process.terminationStatus == 0 {
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                try data.write(to: URL(fileURLWithPath: output))
                return true
            }
        } catch {}

        return false
    }
}
