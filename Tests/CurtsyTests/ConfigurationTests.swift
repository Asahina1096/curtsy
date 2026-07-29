import NIOCore
import XCTest
@testable import Curtsy

final class ConfigurationTests: XCTestCase {
    func testDisabledLogDoesNotEvaluateMessage() {
        let log = LogStore(level: "critical")
        var evaluated = false

        log.debug({
            evaluated = true
            return "expensive debug message"
        }())

        XCTAssertFalse(evaluated)
    }

    func testLoadsDefaults() throws {
        let configuration = try ConfigurationLoader.load(yaml: """
        version: 1
        protocols: [tcp, udp]
        listen:
          host: "127.0.0.1"
          port: 9000
        upstream:
          host: "localhost"
          port: 9001
        """)

        XCTAssertEqual(configuration.protocols, [.tcp, .udp])
        XCTAssertEqual(configuration.timeouts.connectSeconds, 5)
        XCTAssertEqual(configuration.timeouts.tcpIdleSeconds, 300)
        XCTAssertEqual(configuration.timeouts.udpSessionSeconds, 60)
        XCTAssertEqual(configuration.timeouts.shutdownGraceSeconds, 10)
        XCTAssertEqual(configuration.limits.tcpListenBacklog, 4_096)
        XCTAssertEqual(configuration.limits.maxTCPBufferedBytes, 256 * 1_024 * 1_024)
        XCTAssertEqual(configuration.limits.maxUDPAssociations, 4_096)
        XCTAssertEqual(configuration.logging.level, "info")
        XCTAssertEqual(configuration.performance.tcpSockmapAcceleration, .auto)
    }

    func testLoadsOverrides() throws {
        let configuration = try ConfigurationLoader.load(yaml: """
        version: 1
        protocols: [udp]
        listen: { host: "::1", port: 5353 }
        upstream: { host: "2001:4860:4860::8888", port: 53 }
        timeouts:
          connectSeconds: 2
          tcpIdleSeconds: 20
          udpSessionSeconds: 15
          shutdownGraceSeconds: 3
        limits: { tcpListenBacklog: 2048, maxTCPBufferedBytes: 67108864, maxUDPAssociations: 128 }
        performance: { tcpSockmapAcceleration: enabled }
        logging: { level: debug }
        """)

        XCTAssertEqual(configuration.protocols, [.udp])
        XCTAssertEqual(configuration.timeouts.udpSessionSeconds, 15)
        XCTAssertEqual(configuration.limits.tcpListenBacklog, 2_048)
        XCTAssertEqual(configuration.limits.maxTCPBufferedBytes, 64 * 1_024 * 1_024)
        XCTAssertEqual(configuration.limits.maxUDPAssociations, 128)
        XCTAssertEqual(configuration.logging.level, "debug")
        XCTAssertEqual(configuration.performance.tcpSockmapAcceleration, .enabled)
    }

    func testRejectsUnknownKey() {
        XCTAssertThrowsError(try ConfigurationLoader.load(yaml: """
        version: 1
        protocols: [tcp]
        listen: { host: "127.0.0.1", port: 9000, typo: true }
        upstream: { host: "127.0.0.1", port: 9001 }
        """)) { error in
            XCTAssertEqual(error as? ConfigurationError, .unknownKey(path: "listen.typo"))
        }

        XCTAssertThrowsError(try ConfigurationLoader.load(yaml: """
        version: 1
        protocols: [tcp]
        listen: { host: "127.0.0.1", port: 9000 }
        upstream: { host: "127.0.0.1", port: 9001 }
        performance: { sockmap: enabled }
        """)) { error in
            XCTAssertEqual(error as? ConfigurationError, .unknownKey(path: "performance.sockmap"))
        }
    }

    func testRejectsDuplicateProtocols() {
        XCTAssertThrowsError(try ConfigurationLoader.load(yaml: """
        version: 1
        protocols: [tcp, tcp]
        listen: { host: "127.0.0.1", port: 9000 }
        upstream: { host: "127.0.0.1", port: 9001 }
        """))
    }

    func testRejectsInvalidRangesAndLogLevel() {
        let invalidDocuments = [
            """
            version: 1
            protocols: []
            listen: { host: "127.0.0.1", port: 9000 }
            upstream: { host: "127.0.0.1", port: 9001 }
            """,
            """
            version: 1
            protocols: [tcp]
            listen: { host: "127.0.0.1", port: 9000 }
            upstream: { host: "127.0.0.1", port: 9001 }
            limits: { tcpListenBacklog: 0 }
            """,
            """
            version: 1
            protocols: [tcp]
            listen: { host: "127.0.0.1", port: 9000 }
            upstream: { host: "127.0.0.1", port: 9001 }
            limits: { maxTCPBufferedBytes: 0 }
            """,
            """
            version: 1
            protocols: [tcp]
            listen: { host: "127.0.0.1", port: 0 }
            upstream: { host: "127.0.0.1", port: 9001 }
            """,
            """
            version: 1
            protocols: [udp]
            listen: { host: "127.0.0.1", port: 9000 }
            upstream: { host: "127.0.0.1", port: 9001 }
            timeouts: { udpSessionSeconds: 0 }
            """,
            """
            version: 1
            protocols: [tcp]
            listen: { host: "127.0.0.1", port: 9000 }
            upstream: { host: "127.0.0.1", port: 9001 }
            logging: { level: verbose }
            """,
            """
            version: 1
            protocols: [tcp]
            listen: { host: "127.0.0.1", port: 9000 }
            upstream: { host: "127.0.0.1", port: 9001 }
            performance: { tcpSockmapAcceleration: sometimes }
            """
        ]

        for document in invalidDocuments {
            XCTAssertThrowsError(try ConfigurationLoader.load(yaml: document))
        }
    }

    func testResolvesIPv4IPv6AndHostname() throws {
        let ipv4 = try ResolvedConfiguration.resolve(makeConfiguration(upstreamHost: "127.0.0.1"))
        XCTAssertNotNil(ipv4.upstreamAddress.port)

        let ipv6 = try ResolvedConfiguration.resolve(makeConfiguration(upstreamHost: "::1"))
        XCTAssertNotNil(ipv6.upstreamAddress.port)

        let hostname = try ResolvedConfiguration.resolve(makeConfiguration(upstreamHost: "localhost"))
        XCTAssertNotNil(hostname.upstreamAddress.port)
    }

    func testSockmapAutoDisablesLoopbackAndEnablesRemoteUpstreams() throws {
        let ipv4 = try ResolvedConfiguration.resolve(makeConfiguration(upstreamHost: "127.42.0.1"))
        XCTAssertFalse(ipv4.shouldEnableTCPSockmap)

        let ipv6 = try ResolvedConfiguration.resolve(makeConfiguration(upstreamHost: "::1"))
        XCTAssertFalse(ipv6.shouldEnableTCPSockmap)

        let hostname = try ResolvedConfiguration.resolve(
            makeConfiguration(upstreamHost: "loopback.internal")
        ) { _, port in
            try SocketAddress(ipAddress: "127.0.0.1", port: port)
        }
        XCTAssertFalse(hostname.shouldEnableTCPSockmap)

        let remote = try ResolvedConfiguration.resolve(makeConfiguration(upstreamHost: "192.0.2.1"))
        XCTAssertTrue(remote.shouldEnableTCPSockmap)
    }

    func testSockmapExplicitModesOverrideAddressSelection() throws {
        var enabled = makeConfiguration(upstreamHost: "127.0.0.1")
        enabled.performance = PerformanceConfiguration(tcpSockmapAcceleration: .enabled)
        XCTAssertTrue(try ResolvedConfiguration.resolve(enabled).shouldEnableTCPSockmap)

        var disabled = makeConfiguration(upstreamHost: "192.0.2.1")
        disabled.performance = PerformanceConfiguration(tcpSockmapAcceleration: .disabled)
        XCTAssertFalse(try ResolvedConfiguration.resolve(disabled).shouldEnableTCPSockmap)
    }

    func testDetectsListenHostnameResolutionChange() throws {
        let configuration = ForwarderConfiguration(
            version: 1,
            protocols: [.tcp],
            listen: EndpointConfiguration(host: "listener.internal", port: 9000),
            upstream: EndpointConfiguration(host: "upstream.internal", port: 9001)
        )
        let original = try ResolvedConfiguration.resolve(configuration) { host, port in
            try SocketAddress(
                ipAddress: host == "listener.internal" ? "127.0.0.1" : "127.0.0.10",
                port: port
            )
        }
        let changed = try ResolvedConfiguration.resolve(configuration) { host, port in
            try SocketAddress(
                ipAddress: host == "listener.internal" ? "127.0.0.2" : "127.0.0.10",
                port: port
            )
        }

        XCTAssertTrue(original.listenBindingDiffers(from: changed))
    }

    func testTreatsListenAliasesForSameAddressAsSameBinding() throws {
        let originalConfiguration = ForwarderConfiguration(
            version: 1,
            protocols: [.tcp],
            listen: EndpointConfiguration(host: "listener.internal", port: 9000),
            upstream: EndpointConfiguration(host: "upstream.internal", port: 9001)
        )
        let aliasConfiguration = ForwarderConfiguration(
            version: 1,
            protocols: [.tcp],
            listen: EndpointConfiguration(host: "listener-alias.internal", port: 9000),
            upstream: EndpointConfiguration(host: "upstream.internal", port: 9001)
        )
        let resolver: (String, Int) throws -> SocketAddress = { host, port in
            try SocketAddress(
                ipAddress: host == "upstream.internal" ? "127.0.0.10" : "127.0.0.1",
                port: port
            )
        }
        let original = try ResolvedConfiguration.resolve(originalConfiguration, resolver: resolver)
        let alias = try ResolvedConfiguration.resolve(aliasConfiguration, resolver: resolver)

        XCTAssertFalse(original.listenBindingDiffers(from: alias))
    }

    private func makeConfiguration(upstreamHost: String) -> ForwarderConfiguration {
        ForwarderConfiguration(
            version: 1,
            protocols: [.tcp],
            listen: EndpointConfiguration(host: "127.0.0.1", port: 9000),
            upstream: EndpointConfiguration(host: upstreamHost, port: 9001)
        )
    }
}
