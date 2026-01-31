import Foundation

public struct ActionLink: Codable, Sendable {
    public let label: String
    public let url: String

    public init(label: String, url: String) {
        self.label = label
        self.url = url
    }
}

public struct ActionSuggestion: Codable, Sendable {
    public let summary: String
    public let commands: [String]
    public let links: [ActionLink]

    public init(summary: String, commands: [String], links: [ActionLink]) {
        self.summary = summary
        self.commands = commands
        self.links = links
    }
}

public func suggestedActions(for finding: Finding) -> ActionSuggestion {
    var summary = "Review the finding and validate if it is expected for this system."
    var commands: [String] = []
    var links: [ActionLink] = []

    if let mitre = finding.mitreAttackID {
        links.append(ActionLink(label: "MITRE \(mitre)", url: "https://attack.mitre.org/techniques/\(mitre)/"))
    }

    switch finding.id {
    case "SYS-001":
        summary = "Enable SIP from Recovery Mode if you did not intentionally disable it."
        commands = ["csrutil enable"]
        links.append(ActionLink(label: "Apple SIP", url: "https://support.apple.com/en-us/HT204899"))
    case "SYS-002":
        summary = "Enable Gatekeeper to block unsigned apps."
        commands = ["sudo spctl --master-enable"]
        links.append(ActionLink(label: "Gatekeeper", url: "https://support.apple.com/guide/mac-help/mchlp2800/mac"))
    case "NET-001":
        summary = "Enable the macOS application firewall."
        commands = ["sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"]
        links.append(ActionLink(label: "Firewall", url: "https://support.apple.com/guide/mac-help/mh11783/mac"))
    case "NET-002":
        summary = "Enable stealth mode to reduce ICMP probing."
        commands = ["sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"]
    case "SSH-001":
        summary = "Disable Remote Login if not required."
        commands = ["sudo systemsetup -setremotelogin off"]
    case "SSH-004":
        summary = "Disable password auth and use SSH keys."
        commands = [
            "sudo sh -c \"printf '\\nPasswordAuthentication no\\n' >> /etc/ssh/sshd_config\"",
            "sudo launchctl stop com.openssh.sshd",
            "sudo launchctl start com.openssh.sshd"
        ]
    case "VNC-001":
        summary = "Disable Screen Sharing/Remote Management if not needed."
        links.append(ActionLink(label: "Screen Sharing", url: "https://support.apple.com/guide/mac-help/mh11848/mac"))
    case "PERSIST-LOGINITEMS":
        summary = "Review Login Items in System Settings and remove unknown entries."
        links.append(ActionLink(label: "Login Items", url: "https://support.apple.com/guide/mac-help/mh15189/mac"))
    default:
        break
    }

    return ActionSuggestion(summary: summary, commands: commands, links: links)
}
