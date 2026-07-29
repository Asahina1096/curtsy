import Atomics
import Logging
import NIOConcurrencyHelpers
import NIOCore

struct ResolvedConfiguration: Sendable {
    let configuration: ForwarderConfiguration
    let listenAddresses: [SocketAddress]
    let upstreamAddress: SocketAddress

    static func resolve(
        _ configuration: ForwarderConfiguration,
        resolver: (String, Int) throws -> SocketAddress = {
            try SocketAddress.makeAddressResolvingHost($0, port: $1)
        }
    ) throws -> ResolvedConfiguration {
        let listenAddresses: [SocketAddress]
        if configuration.listen.host == "*" {
            listenAddresses = [
                try SocketAddress(ipAddress: "0.0.0.0", port: configuration.listen.port),
                try SocketAddress(ipAddress: "::", port: configuration.listen.port)
            ]
        } else {
            listenAddresses = [try resolver(configuration.listen.host, configuration.listen.port)]
        }
        let upstream = try resolver(configuration.upstream.host, configuration.upstream.port)
        return ResolvedConfiguration(
            configuration: configuration,
            listenAddresses: listenAddresses,
            upstreamAddress: upstream
        )
    }

    func listenBindingDiffers(from other: ResolvedConfiguration) -> Bool {
        listenAddresses != other.listenAddresses
    }

    var shouldEnableTCPSockmap: Bool {
        switch configuration.performance.tcpSockmapAcceleration {
        case .enabled, .auto:
            return true
        case .disabled:
            return false
        }
    }

}

final class RuntimeConfiguration: @unchecked Sendable {
    private let storage: NIOLockedValueBox<ResolvedConfiguration>

    init(_ configuration: ResolvedConfiguration) {
        storage = NIOLockedValueBox(configuration)
    }

    func current() -> ResolvedConfiguration {
        storage.withLockedValue { $0 }
    }

    func update(_ configuration: ResolvedConfiguration) {
        storage.withLockedValue { $0 = configuration }
    }
}

final class LogStore: @unchecked Sendable {
    private let logger: NIOLockedValueBox<Logger>
    private let threshold: ManagedAtomic<Int>

    init(level: String) {
        var value = Logger(label: "curtsy")
        value.logLevel = Logger.Level(rawValue: level.lowercased()) ?? .info
        logger = NIOLockedValueBox(value)
        threshold = ManagedAtomic(Self.priority(of: value.logLevel))
    }

    func update(level: String) {
        let newLevel = Logger.Level(rawValue: level.lowercased()) ?? .info
        threshold.store(Self.priority(of: newLevel), ordering: .relaxed)
        logger.withLockedValue {
            $0.logLevel = newLevel
        }
    }

    func debug(_ message: @autoclosure () -> String) {
        log(level: .debug, message())
    }

    func info(_ message: @autoclosure () -> String) {
        log(level: .info, message())
    }

    func warning(_ message: @autoclosure () -> String) {
        log(level: .warning, message())
    }

    func error(_ message: @autoclosure () -> String) {
        log(level: .error, message())
    }

    private func log(level: Logger.Level, _ message: @autoclosure () -> String) {
        guard Self.priority(of: level) >= threshold.load(ordering: .relaxed) else { return }
        let value = message()
        logger.withLockedValue { logger in
            guard level >= logger.logLevel else { return }
            logger.log(level: level, "\(value)")
        }
    }

    private static func priority(of level: Logger.Level) -> Int {
        switch level {
        case .trace: 0
        case .debug: 1
        case .info: 2
        case .notice: 3
        case .warning: 4
        case .error: 5
        case .critical: 6
        }
    }
}

final class ChannelRegistry: @unchecked Sendable {
    private typealias Storage = [ObjectIdentifier: Channel]
    private let shards: [NIOLockedValueBox<Storage>]

    init(shardCount: Int = 16) {
        shards = (0..<max(1, shardCount)).map { _ in NIOLockedValueBox([:]) }
    }

    func insert(_ channel: Channel) {
        let identifier = ObjectIdentifier(channel)
        let index = shardIndex(for: identifier)
        shards[index].withLockedValue { $0[identifier] = channel }
        channel.closeFuture.whenComplete { [weak self] _ in
            guard let self else { return }
            _ = self.shards[index].withLockedValue { $0.removeValue(forKey: identifier) }
        }
    }

    var count: Int {
        shards.reduce(0) { total, shard in
            total + shard.withLockedValue(\.count)
        }
    }

    func closeAll() {
        let snapshot = shards.flatMap { shard in
            shard.withLockedValue { Array($0.values) }
        }
        for channel in snapshot {
            channel.close(promise: nil)
        }
    }

    private func shardIndex(for identifier: ObjectIdentifier) -> Int {
        (identifier.hashValue & Int.max) % shards.count
    }
}

extension SocketAddress {
    var curtsyDescription: String {
        switch self {
        case .v4(let address):
            return "\(address.host):\(port ?? 0)"
        case .v6(let address):
            return "[\(address.host)]:\(port ?? 0)"
        case .unixDomainSocket:
            return description
        }
    }
}
