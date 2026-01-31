import Foundation

public enum OrchestratorError: Error {
    case invalidModules
}

public final class ScanOrchestrator {
    private let modules: [AnalyzerModule]
    private let moduleFactories: [(String, () -> AnalyzerModule)] = [
        ("system", { SystemAnalyzer() }),
        ("network", { NetworkAnalyzer() }),
        ("persistence", { PersistenceAnalyzer() }),
        ("malware", { MalwareScanner() }),
        ("forensics", { ForensicAnalyzer() })
    ]

    public init(moduleKeys: [String] = []) throws {
        let normalized = Set(moduleKeys.map { $0.lowercased() })
        if normalized.isEmpty {
            self.modules = moduleFactories.map { $0.1() }
        } else {
            let selected = moduleFactories.compactMap { key, factory in
                normalized.contains(key) ? factory() : nil
            }
            if selected.isEmpty {
                throw OrchestratorError.invalidModules
            }
            self.modules = selected
        }
    }

    public func runFullScan(quick: Bool, includeML: Bool) async throws -> ScanResults {
        var categories: [ScanCategory] = []
        let total = modules.count

        for (index, module) in modules.enumerated() {
            let progress = "[\(index + 1)/\(total)]"
            print("\r\u{001B}[K\(progress) Scanning: \(module.name)...", terminator: "")
            fflush(stdout)

            let findings = try await module.run(quick: quick)
            categories.append(ScanCategory(name: module.name, findings: findings))
        }

        // Clear the progress line
        print("\r\u{001B}[K", terminator: "")
        fflush(stdout)

        if includeML {
            let mlFinding = Finding(
                id: "ML-INFO",
                title: "ML Analysis Requested",
                description: "Run the Python analysis engine to perform ML-based anomaly detection.",
                evidence: "Use analysis/analyzer.py with findings JSON output.",
                remediation: "Run: python analysis/analyzer.py -i findings.json -o enhanced_findings.json",
                riskLevel: .info,
                mitreAttackID: nil
            )
            categories.append(ScanCategory(name: "ML Guidance", findings: [mlFinding]))
        }

        return ScanResults(categories: categories.sorted { $0.name < $1.name })
    }
}
