import Foundation

public enum ActionStatus: String, Codable, Sendable {
    case applied
    case skipped
    case failed
}

public enum ActionCommandStatus: String, Codable, Sendable {
    case success
    case failed
}

public struct ActionCommandResult: Codable, Sendable {
    public let command: String
    public let status: ActionCommandStatus
    public let output: String

    public init(command: String, status: ActionCommandStatus, output: String) {
        self.command = command
        self.status = status
        self.output = output
    }
}

public struct ActionResult: Codable, Sendable {
    public let findingId: String
    public let title: String
    public let summary: String
    public let status: ActionStatus
    public let commands: [ActionCommandResult]

    public init(
        findingId: String,
        title: String,
        summary: String,
        status: ActionStatus,
        commands: [ActionCommandResult]
    ) {
        self.findingId = findingId
        self.title = title
        self.summary = summary
        self.status = status
        self.commands = commands
    }
}
