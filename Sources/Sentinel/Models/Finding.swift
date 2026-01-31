import Foundation

public struct Finding: Codable, Sendable {
    public let id: String
    public let title: String
    public let description: String
    public let evidence: String
    public let remediation: String
    public let riskLevel: RiskLevel
    public let mitreAttackID: String?

    public init(
        id: String,
        title: String,
        description: String,
        evidence: String,
        remediation: String,
        riskLevel: RiskLevel,
        mitreAttackID: String?
    ) {
        self.id = id
        self.title = title
        self.description = description
        self.evidence = evidence
        self.remediation = remediation
        self.riskLevel = riskLevel
        self.mitreAttackID = mitreAttackID
    }
}
