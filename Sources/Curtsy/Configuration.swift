import Foundation
import Yams

enum ForwardProtocol: String, Codable, CaseIterable, Hashable, Sendable {
    case tcp
    case udp
}

struct EndpointConfiguration: Codable, Equatable, Sendable {
    let host: String
    let port: Int

    init(host: String, port: Int) {
        self.host = host
        self.port = port
    }
}

private struct ListenEndpointConfiguration: Decodable {
    var host: String = "*"
    let port: Int

    private enum CodingKeys: String, CodingKey {
        case host
        case port
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        host = try container.decodeIfPresent(String.self, forKey: .host) ?? "*"
        port = try container.decode(Int.self, forKey: .port)
    }
}

private struct UpstreamEndpointConfiguration: Decodable {
    let host: String
    let port: Int?
}

private extension KeyedDecodingContainer {
    func decodeAutoTunedInt(forKey key: Key, default defaultValue: Int) throws -> (value: Int, isAuto: Bool) {
        guard contains(key) else { return (defaultValue, true) }
        if let value = try? decode(Int.self, forKey: key) {
            return (value, false)
        }
        let value = try decode(String.self, forKey: key)
        guard value.lowercased() == "auto" else {
            throw DecodingError.dataCorruptedError(
                forKey: key,
                in: self,
                debugDescription: "expected an integer or auto"
            )
        }
        return (defaultValue, true)
    }
}

struct LimitAutoTuning: Equatable, Sendable {
    var tcpListenBacklog: Bool = true
    var maxTCPBufferedBytes: Bool = true
    var maxUDPAssociations: Bool = true
    var maxUDPPendingDatagrams: Bool = true
    var maxUDPPendingBytes: Bool = true
}

struct TimeoutConfiguration: Codable, Equatable, Sendable {
    var connectSeconds: Int = 5
    var tcpIdleSeconds: Int = 300
    var udpSessionSeconds: Int = 60
    var shutdownGraceSeconds: Int = 10

    init() {}

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        connectSeconds = try container.decodeIfPresent(Int.self, forKey: .connectSeconds) ?? 5
        tcpIdleSeconds = try container.decodeIfPresent(Int.self, forKey: .tcpIdleSeconds) ?? 300
        udpSessionSeconds = try container.decodeIfPresent(Int.self, forKey: .udpSessionSeconds) ?? 60
        shutdownGraceSeconds = try container.decodeIfPresent(Int.self, forKey: .shutdownGraceSeconds) ?? 10
    }
}

struct LimitConfiguration: Codable, Equatable, Sendable {
    var tcpListenBacklog: Int = 4_096
    var maxTCPBufferedBytes: Int = 256 * 1_024 * 1_024
    var maxUDPAssociations: Int = 4_096
    var maxUDPPendingDatagrams: Int = 64
    var maxUDPPendingBytes: Int = 1 * 1_024 * 1_024
    var autoTuning = LimitAutoTuning()

    private enum CodingKeys: String, CodingKey {
        case tcpListenBacklog
        case maxTCPBufferedBytes
        case maxUDPAssociations
        case maxUDPPendingDatagrams
        case maxUDPPendingBytes
    }

    init() {
        let auto = AutoTune.limits()
        tcpListenBacklog = auto.tcpListenBacklog
        maxTCPBufferedBytes = auto.maxTCPBufferedBytes
        maxUDPAssociations = auto.maxUDPAssociations
        maxUDPPendingDatagrams = auto.maxUDPPendingDatagrams
        maxUDPPendingBytes = auto.maxUDPPendingBytes
        autoTuning = LimitAutoTuning()
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let auto = AutoTune.limits()
        let backlog = try container.decodeAutoTunedInt(
            forKey: .tcpListenBacklog,
            default: auto.tcpListenBacklog
        )
        let tcpBytes = try container.decodeAutoTunedInt(
            forKey: .maxTCPBufferedBytes,
            default: auto.maxTCPBufferedBytes
        )
        let udpAssociations = try container.decodeAutoTunedInt(
            forKey: .maxUDPAssociations,
            default: auto.maxUDPAssociations
        )
        let pendingDatagrams = try container.decodeAutoTunedInt(
            forKey: .maxUDPPendingDatagrams,
            default: auto.maxUDPPendingDatagrams
        )
        let pendingBytes = try container.decodeAutoTunedInt(
            forKey: .maxUDPPendingBytes,
            default: auto.maxUDPPendingBytes
        )
        tcpListenBacklog = backlog.value
        maxTCPBufferedBytes = tcpBytes.value
        maxUDPAssociations = udpAssociations.value
        maxUDPPendingDatagrams = pendingDatagrams.value
        maxUDPPendingBytes = pendingBytes.value
        autoTuning = LimitAutoTuning(
            tcpListenBacklog: backlog.isAuto,
            maxTCPBufferedBytes: tcpBytes.isAuto,
            maxUDPAssociations: udpAssociations.isAuto,
            maxUDPPendingDatagrams: pendingDatagrams.isAuto,
            maxUDPPendingBytes: pendingBytes.isAuto
        )
    }
}

struct LogConfiguration: Codable, Equatable, Sendable {
    var level: String = "info"

    init() {}

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        level = try container.decodeIfPresent(String.self, forKey: .level) ?? "info"
    }
}

enum TCPSockmapAccelerationMode: String, Codable, Sendable {
    case auto
    case enabled
    case disabled
}

struct RuntimeOptions: Codable, Equatable, Sendable {
    var workerThreads: Int = 0
    var tuningDaemon: Bool = true
    var tuningIntervalSeconds: Int = 5

    init(workerThreads: Int = 0, tuningDaemon: Bool = true, tuningIntervalSeconds: Int = 5) {
        self.workerThreads = workerThreads
        self.tuningDaemon = tuningDaemon
        self.tuningIntervalSeconds = tuningIntervalSeconds
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        workerThreads = try container.decodeAutoTunedInt(forKey: .workerThreads, default: 0).value
        tuningDaemon = try container.decodeIfPresent(Bool.self, forKey: .tuningDaemon) ?? true
        tuningIntervalSeconds = try container.decodeIfPresent(Int.self, forKey: .tuningIntervalSeconds) ?? 5
    }
}

struct PerformanceConfiguration: Codable, Equatable, Sendable {
    var tcpSockmapAcceleration: TCPSockmapAccelerationMode = .auto

    init(tcpSockmapAcceleration: TCPSockmapAccelerationMode = .auto) {
        self.tcpSockmapAcceleration = tcpSockmapAcceleration
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        tcpSockmapAcceleration = try container.decodeIfPresent(
            TCPSockmapAccelerationMode.self,
            forKey: .tcpSockmapAcceleration
        ) ?? .auto
    }
}

struct ForwarderConfiguration: Codable, Equatable, Sendable {
    let version: Int
    let protocols: [ForwardProtocol]
    let listen: EndpointConfiguration
    let upstream: EndpointConfiguration
    var timeouts: TimeoutConfiguration
    var limits: LimitConfiguration
    var logging: LogConfiguration
    var runtime: RuntimeOptions
    var performance: PerformanceConfiguration

    init(
        version: Int,
        protocols: [ForwardProtocol],
        listen: EndpointConfiguration,
        upstream: EndpointConfiguration,
        timeouts: TimeoutConfiguration = .init(),
        limits: LimitConfiguration = .init(),
        logging: LogConfiguration = .init(),
        runtime: RuntimeOptions = .init(),
        performance: PerformanceConfiguration = .init()
    ) {
        self.version = version
        self.protocols = protocols
        self.listen = listen
        self.upstream = upstream
        self.timeouts = timeouts
        self.limits = limits
        self.logging = logging
        self.runtime = runtime
        self.performance = performance
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decodeIfPresent(Int.self, forKey: .version) ?? 1
        protocols = try container.decodeIfPresent([ForwardProtocol].self, forKey: .protocols) ?? [.tcp, .udp]
        let listenEndpoint = try container.decode(ListenEndpointConfiguration.self, forKey: .listen)
        let upstreamEndpoint = try container.decode(UpstreamEndpointConfiguration.self, forKey: .upstream)
        listen = EndpointConfiguration(host: listenEndpoint.host, port: listenEndpoint.port)
        upstream = EndpointConfiguration(
            host: upstreamEndpoint.host,
            port: upstreamEndpoint.port ?? listenEndpoint.port
        )
        timeouts = try container.decodeIfPresent(TimeoutConfiguration.self, forKey: .timeouts) ?? .init()
        limits = try container.decodeIfPresent(LimitConfiguration.self, forKey: .limits) ?? .init()
        logging = try container.decodeIfPresent(LogConfiguration.self, forKey: .logging) ?? .init()
        runtime = try container.decodeIfPresent(RuntimeOptions.self, forKey: .runtime) ?? .init()
        performance = try container.decodeIfPresent(
            PerformanceConfiguration.self,
            forKey: .performance
        ) ?? .init()
    }
}

enum ConfigurationError: Error, CustomStringConvertible, Equatable {
    case invalidRoot
    case unknownKey(path: String)
    case invalidValue(String)

    var description: String {
        switch self {
        case .invalidRoot:
            return "YAML root must be a mapping"
        case .unknownKey(let path):
            return "unknown configuration key: \(path)"
        case .invalidValue(let message):
            return message
        }
    }
}

enum ConfigurationLoader {
    private static let allowedKeys: [String: Set<String>] = [
        "": [
            "version", "protocols", "listen", "upstream", "timeouts", "limits", "logging", "runtime", "performance",
        ],
        "listen": ["host", "port"],
        "upstream": ["host", "port"],
        "timeouts": ["connectSeconds", "tcpIdleSeconds", "udpSessionSeconds", "shutdownGraceSeconds"],
        "limits": [
            "tcpListenBacklog",
            "maxTCPBufferedBytes",
            "maxUDPAssociations",
            "maxUDPPendingDatagrams",
            "maxUDPPendingBytes",
        ],
        "logging": ["level"],
        "runtime": ["workerThreads", "tuningDaemon", "tuningIntervalSeconds"],
        "performance": ["tcpSockmapAcceleration"]
    ]

    static func load(path: String) throws -> ForwarderConfiguration {
        let text = try String(contentsOfFile: path, encoding: .utf8)
        return try load(yaml: text)
    }

    static func load(yaml: String) throws -> ForwarderConfiguration {
        let raw = try Yams.load(yaml: yaml)
        guard let root = raw as? [String: Any] else {
            throw ConfigurationError.invalidRoot
        }
        try validateKeys(root, path: "")

        let configuration = try YAMLDecoder().decode(ForwarderConfiguration.self, from: yaml)
        try validate(configuration)
        return configuration
    }

    private static func validateKeys(_ mapping: [String: Any], path: String) throws {
        guard let allowed = allowedKeys[path] else { return }
        for (key, value) in mapping {
            guard allowed.contains(key) else {
                throw ConfigurationError.unknownKey(path: path.isEmpty ? key : "\(path).\(key)")
            }
            if let child = value as? [String: Any], allowedKeys[key] != nil {
                try validateKeys(child, path: key)
            }
        }
    }

    private static func validate(_ configuration: ForwarderConfiguration) throws {
        guard configuration.version == 1 else {
            throw ConfigurationError.invalidValue("unsupported configuration version: \(configuration.version)")
        }
        guard !configuration.protocols.isEmpty else {
            throw ConfigurationError.invalidValue("protocols must not be empty")
        }
        guard Set(configuration.protocols).count == configuration.protocols.count else {
            throw ConfigurationError.invalidValue("protocols must not contain duplicates")
        }
        guard !configuration.listen.host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw ConfigurationError.invalidValue("listen.host must not be empty")
        }
        guard !configuration.upstream.host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw ConfigurationError.invalidValue("upstream.host must not be empty")
        }
        guard (1...65_535).contains(configuration.listen.port) else {
            throw ConfigurationError.invalidValue("listen.port must be between 1 and 65535")
        }
        guard (1...65_535).contains(configuration.upstream.port) else {
            throw ConfigurationError.invalidValue("upstream.port must be between 1 and 65535")
        }
        let timeoutValues = [
            configuration.timeouts.connectSeconds,
            configuration.timeouts.tcpIdleSeconds,
            configuration.timeouts.udpSessionSeconds,
            configuration.timeouts.shutdownGraceSeconds
        ]
        guard timeoutValues.allSatisfy({ $0 > 0 }) else {
            throw ConfigurationError.invalidValue("all timeout values must be positive")
        }
        let maxTimeoutSeconds = Int(Int64.max / 1_000_000_000)
        guard timeoutValues.allSatisfy({ $0 <= maxTimeoutSeconds }) else {
            throw ConfigurationError.invalidValue(
                "all timeout values must be no greater than \(maxTimeoutSeconds) seconds"
            )
        }
        guard (1...Int(Int32.max)).contains(configuration.limits.tcpListenBacklog) else {
            throw ConfigurationError.invalidValue("limits.tcpListenBacklog must be between 1 and \(Int32.max)")
        }
        guard configuration.limits.maxTCPBufferedBytes > 0 else {
            throw ConfigurationError.invalidValue("limits.maxTCPBufferedBytes must be positive")
        }
        guard configuration.limits.maxUDPAssociations > 0 else {
            throw ConfigurationError.invalidValue("limits.maxUDPAssociations must be positive")
        }
        guard configuration.limits.maxUDPPendingDatagrams > 0 else {
            throw ConfigurationError.invalidValue("limits.maxUDPPendingDatagrams must be positive")
        }
        guard configuration.limits.maxUDPPendingBytes > 0 else {
            throw ConfigurationError.invalidValue("limits.maxUDPPendingBytes must be positive")
        }
        guard configuration.runtime.workerThreads >= 0 else {
            throw ConfigurationError.invalidValue("runtime.workerThreads must be zero for auto or positive")
        }
        guard configuration.runtime.tuningIntervalSeconds > 0 else {
            throw ConfigurationError.invalidValue("runtime.tuningIntervalSeconds must be positive")
        }
        let validLogLevels = Set(["trace", "debug", "info", "notice", "warning", "error", "critical"])
        guard validLogLevels.contains(configuration.logging.level.lowercased()) else {
            throw ConfigurationError.invalidValue("logging.level is invalid")
        }
    }
}
