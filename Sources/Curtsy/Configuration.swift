import Foundation
import Yams

enum ForwardProtocol: String, Codable, CaseIterable, Hashable, Sendable {
    case tcp
    case udp
}

struct EndpointConfiguration: Codable, Equatable, Sendable {
    let host: String
    let port: Int
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

    init() {}

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        tcpListenBacklog = try container.decodeIfPresent(Int.self, forKey: .tcpListenBacklog) ?? 4_096
        maxTCPBufferedBytes = try container.decodeIfPresent(
            Int.self,
            forKey: .maxTCPBufferedBytes
        ) ?? 256 * 1_024 * 1_024
        maxUDPAssociations = try container.decodeIfPresent(Int.self, forKey: .maxUDPAssociations) ?? 4_096
        maxUDPPendingDatagrams = try container.decodeIfPresent(
            Int.self,
            forKey: .maxUDPPendingDatagrams
        ) ?? 64
        maxUDPPendingBytes = try container.decodeIfPresent(
            Int.self,
            forKey: .maxUDPPendingBytes
        ) ?? 1 * 1_024 * 1_024
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
    var performance: PerformanceConfiguration

    init(
        version: Int,
        protocols: [ForwardProtocol],
        listen: EndpointConfiguration,
        upstream: EndpointConfiguration,
        timeouts: TimeoutConfiguration = .init(),
        limits: LimitConfiguration = .init(),
        logging: LogConfiguration = .init(),
        performance: PerformanceConfiguration = .init()
    ) {
        self.version = version
        self.protocols = protocols
        self.listen = listen
        self.upstream = upstream
        self.timeouts = timeouts
        self.limits = limits
        self.logging = logging
        self.performance = performance
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        protocols = try container.decode([ForwardProtocol].self, forKey: .protocols)
        listen = try container.decode(EndpointConfiguration.self, forKey: .listen)
        upstream = try container.decode(EndpointConfiguration.self, forKey: .upstream)
        timeouts = try container.decodeIfPresent(TimeoutConfiguration.self, forKey: .timeouts) ?? .init()
        limits = try container.decodeIfPresent(LimitConfiguration.self, forKey: .limits) ?? .init()
        logging = try container.decodeIfPresent(LogConfiguration.self, forKey: .logging) ?? .init()
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
            "version", "protocols", "listen", "upstream", "timeouts", "limits", "logging", "performance",
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
        let validLogLevels = Set(["trace", "debug", "info", "notice", "warning", "error", "critical"])
        guard validLogLevels.contains(configuration.logging.level.lowercased()) else {
            throw ConfigurationError.invalidValue("logging.level is invalid")
        }
    }
}
