import Foundation

public struct ScanCategory: Codable, Sendable {
    public let name: String
    public let findings: [Finding]

    public init(name: String, findings: [Finding]) {
        self.name = name
        self.findings = findings
    }
}

public struct ScanResults: Codable, Sendable {
    public let categories: [ScanCategory]
    public let allFindings: [Finding]
    public let overallRisk: RiskLevel
    public let generatedAt: Date
    public let host: String
    public let actionResults: [ActionResult]

    public init(
        categories: [ScanCategory],
        actionResults: [ActionResult] = [],
        generatedAt: Date = Date(),
        host: String = Host.current().localizedName ?? "unknown-host"
    ) {
        self.categories = categories
        self.allFindings = categories.flatMap { $0.findings }
        self.overallRisk = self.allFindings.map { $0.riskLevel }.max() ?? .info
        self.generatedAt = generatedAt
        self.host = host
        self.actionResults = actionResults
    }
}
