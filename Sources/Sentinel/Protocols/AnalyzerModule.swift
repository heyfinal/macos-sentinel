import Foundation

public protocol AnalyzerModule: Sendable {
    var name: String { get }
    func run(quick: Bool) async throws -> [Finding]
}
