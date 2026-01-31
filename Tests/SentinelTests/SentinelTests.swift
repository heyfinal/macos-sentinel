import XCTest
@testable import Sentinel

final class SentinelTests: XCTestCase {
    func testRiskLevelOrdering() {
        XCTAssertTrue(RiskLevel.critical > RiskLevel.high)
        XCTAssertTrue(RiskLevel.high > RiskLevel.medium)
        XCTAssertTrue(RiskLevel.medium > RiskLevel.low)
        XCTAssertTrue(RiskLevel.low > RiskLevel.info)
    }

    func testScanResultsAggregatesFindings() {
        let finding = Finding(
            id: "TEST-1",
            title: "Test",
            description: "Desc",
            evidence: "Evidence",
            remediation: "Fix",
            riskLevel: .medium,
            mitreAttackID: nil
        )
        let results = ScanResults(categories: [ScanCategory(name: "Test", findings: [finding])])
        XCTAssertEqual(results.allFindings.count, 1)
        XCTAssertEqual(results.overallRisk, .medium)
    }
}
