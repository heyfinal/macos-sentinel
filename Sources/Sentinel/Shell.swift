import Foundation

struct ShellResult {
    let output: String
    let exitCode: Int32
}

struct Shell {
    static func run(_ path: String, _ args: [String], timeout: TimeInterval? = nil) -> ShellResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
        } catch {
            return ShellResult(output: "", exitCode: -1)
        }

        var didTimeout = false
        var timer: DispatchSourceTimer?
        if let timeout = timeout {
            timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global())
            timer?.schedule(deadline: .now() + timeout)
            timer?.setEventHandler {
                if process.isRunning {
                    didTimeout = true
                    process.terminate()
                }
            }
            timer?.resume()
        }

        process.waitUntilExit()
        timer?.cancel()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        let exitCode: Int32 = didTimeout ? -1 : process.terminationStatus
        return ShellResult(output: output, exitCode: exitCode)
    }
}
