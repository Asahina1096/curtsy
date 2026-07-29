import ArgumentParser
import Foundation
import Logging

@main
struct CurtsyCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "curtsy",
        abstract: "Transparent TCP and UDP traffic forwarder",
        version: "0.1.0"
    )

    @Option(name: [.short, .long], help: "Path to the YAML configuration file")
    var config: String

    @Flag(help: "Validate configuration and exit")
    var checkConfig = false

    mutating func run() throws {
        LoggingSystem.bootstrap(StreamLogHandler.standardError)

        let loaded: ForwarderConfiguration
        do {
            loaded = try ConfigurationLoader.load(path: config)
            _ = try ResolvedConfiguration.resolve(loaded)
        } catch {
            writeError("configuration error: \(error)")
            throw ExitCode(2)
        }

        if checkConfig {
            print("configuration is valid")
            return
        }

        do {
            let service = try ForwarderService(configurationPath: config, configuration: loaded)
            try service.run()
        } catch {
            writeError("runtime error: \(error)")
            throw ExitCode.failure
        }
    }

    private func writeError(_ message: String) {
        FileHandle.standardError.write(Data("curtsy: \(message)\n".utf8))
    }
}
