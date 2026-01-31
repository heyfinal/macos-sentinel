import Foundation

public enum RiskLevel: String, Codable, CaseIterable, Comparable, Sendable {
    case critical = "CRITICAL"
    case high = "HIGH"
    case medium = "MEDIUM"
    case low = "LOW"
    case info = "INFO"

    private var severity: Int {
        switch self {
        case .critical: return 5
        case .high: return 4
        case .medium: return 3
        case .low: return 2
        case .info: return 1
        }
    }

    public static func < (lhs: RiskLevel, rhs: RiskLevel) -> Bool {
        lhs.severity < rhs.severity
    }
}
