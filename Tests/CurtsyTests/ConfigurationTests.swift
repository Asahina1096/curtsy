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
        listen:
          port: 9000
        upstream:
          host: "localhost"
        """)
        let autoLimits = AutoTune.limits()

        XCTAssertEqual(configuration.version, 1)
        XCTAssertEqual(configuration.protocols, [.tcp, .udp])
        XCTAssertEqual(configuration.listen.host, "*")
        XCTAssertEqual(configuration.listen.port, 9000)
        XCTAssertEqual(configuration.upstream.host, "localhost")
        XCTAssertEqual(configuration.upstream.port, 9000)
        XCTAssertEqual(configuration.timeouts.connectSeconds, 5)
        XCTAssertEqual(configuration.timeouts.tcpIdleSeconds, 300)
        XCTAssertEqual(configuration.timeouts.udpSessionSeconds, 60)
        XCTAssertEqual(configuration.timeouts.shutdownGraceSeconds, 10)
        XCTAssertEqual(configuration.limits.tcpListenBacklog, autoLimits.tcpListenBacklog)
        XCTAssertEqual(configuration.limits.maxTCPBufferedBytes, autoLimits.maxTCPBufferedBytes)
        XCTAssertEqual(configuration.limits.maxUDPAssociations, autoLimits.maxUDPAssociations)
        XCTAssertEqual(configuration.limits.maxUDPPendingDatagrams, autoLimits.maxUDPPendingDatagrams)
        XCTAssertEqual(configuration.limits.maxUDPPendingBytes, autoLimits.maxUDPPendingBytes)
        XCTAssertEqual(configuration.runtime.workerThreads, 0)
        XCTAssertTrue(configuration.runtime.tuningDaemon)
        XCTAssertEqual(configuration.runtime.tuningIntervalSeconds, 5)
        XCTAssertTrue(configuration.limits.autoTuning.maxTCPBufferedBytes)
        XCTAssertEqual(configuration.logging.level, "info")
        XCTAssertEqual(configuration.performance.tcpSockmapAcceleration, .auto)
        XCTAssertEqual(configuration.performance.udpSockmapAcceleration, .auto)
        XCTAssertEqual(
            configuration.performance.udpSocketBufferBytes,
            PerformanceConfiguration.defaultUDPSocketBufferBytes
        )
        XCTAssertEqual(configuration.performance.udpIOThreads, 0)
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
        limits:
          tcpListenBacklog: 2048
          maxTCPBufferedBytes: 67108864
          maxUDPAssociations: 128
          maxUDPPendingDatagrams: 8
          maxUDPPendingBytes: 4096
        runtime: { workerThreads: 2, tuningDaemon: false, tuningIntervalSeconds: 10 }
        performance: { tcpSockmapAcceleration: enabled, udpSockmapAcceleration: disabled, udpSocketBufferBytes: 8388608, udpIOThreads: 2 }
        logging: { level: debug }
        """)

        XCTAssertEqual(configuration.protocols, [.udp])
        XCTAssertEqual(configuration.timeouts.udpSessionSeconds, 15)
        XCTAssertEqual(configuration.limits.tcpListenBacklog, 2_048)
        XCTAssertEqual(configuration.limits.maxTCPBufferedBytes, 64 * 1_024 * 1_024)
        XCTAssertEqual(configuration.limits.maxUDPAssociations, 128)
        XCTAssertEqual(configuration.limits.maxUDPPendingDatagrams, 8)
        XCTAssertEqual(configuration.limits.maxUDPPendingBytes, 4_096)
        XCTAssertEqual(configuration.logging.level, "debug")
        XCTAssertEqual(configuration.runtime.workerThreads, 2)
        XCTAssertFalse(configuration.runtime.tuningDaemon)
        XCTAssertEqual(configuration.runtime.tuningIntervalSeconds, 10)
        XCTAssertFalse(configuration.limits.autoTuning.maxTCPBufferedBytes)
        XCTAssertEqual(configuration.performance.tcpSockmapAcceleration, .enabled)
        XCTAssertEqual(configuration.performance.udpSockmapAcceleration, .disabled)
        XCTAssertEqual(configuration.performance.udpSocketBufferBytes, 8 * 1_024 * 1_024)
        XCTAssertEqual(configuration.performance.udpIOThreads, 2)
    }

    func testAcceptsExplicitAutoValues() throws {
        let configuration = try ConfigurationLoader.load(yaml: """
        listen: { port: 9000 }
        upstream: { host: "localhost", port: 9001 }
        runtime: { workerThreads: auto }
        limits:
          tcpListenBacklog: auto
          maxTCPBufferedBytes: auto
          maxUDPAssociations: auto
          maxUDPPendingDatagrams: auto
          maxUDPPendingBytes: auto
        """)
        let autoLimits = AutoTune.limits()

        XCTAssertEqual(configuration.runtime.workerThreads, 0)
        XCTAssertEqual(configuration.limits.tcpListenBacklog, autoLimits.tcpListenBacklog)
        XCTAssertEqual(configuration.limits.maxTCPBufferedBytes, autoLimits.maxTCPBufferedBytes)
        XCTAssertEqual(configuration.limits.maxUDPAssociations, autoLimits.maxUDPAssociations)
        XCTAssertEqual(configuration.limits.maxUDPPendingDatagrams, autoLimits.maxUDPPendingDatagrams)
        XCTAssertEqual(configuration.limits.maxUDPPendingBytes, autoLimits.maxUDPPendingBytes)
    }

    func testAutoTuneCalculatesConservativeDefaults() {
        let tiny = AutoTune.limits(
            snapshot: AutoTuneSnapshot(processorCount: 1, totalMemoryBytes: 512 * 1_024 * 1_024)
        )
        XCTAssertEqual(tiny.tcpListenBacklog, 4_096)
        XCTAssertEqual(tiny.maxTCPBufferedBytes, 64 * 1_024 * 1_024)
        XCTAssertEqual(tiny.maxUDPAssociations, 1_024)

        let large = AutoTune.limits(
            snapshot: AutoTuneSnapshot(processorCount: 96, totalMemoryBytes: 256 * 1_024 * 1_024 * 1_024)
        )
        XCTAssertEqual(large.tcpListenBacklog, 65_535)
        XCTAssertEqual(large.maxTCPBufferedBytes, 512 * 1_024 * 1_024)
        XCTAssertEqual(large.maxUDPAssociations, 65_536)
        XCTAssertEqual(AutoTune.workerThreads(configured: 0, snapshot: .init(processorCount: 96)), 32)
        XCTAssertEqual(AutoTune.workerThreads(configured: 6, snapshot: .init(processorCount: 96)), 6)
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
            protocols: [udp]
            listen: { host: "127.0.0.1", port: 9000 }
            upstream: { host: "127.0.0.1", port: 9001 }
            limits: { maxUDPPendingDatagrams: 0 }
            """,
            """
            version: 1
            protocols: [udp]
            listen: { host: "127.0.0.1", port: 9000 }
            upstream: { host: "127.0.0.1", port: 9001 }
            limits: { maxUDPPendingBytes: 0 }
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
            timeouts: { tcpIdleSeconds: 9223372037 }
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
            runtime: { workerThreads: -1 }
            """,
            """
            version: 1
            protocols: [tcp]
            listen: { host: "127.0.0.1", port: 9000 }
            upstream: { host: "127.0.0.1", port: 9001 }
            runtime: { tuningIntervalSeconds: 0 }
            """,
            """
            version: 1
            protocols: [tcp]
            listen: { host: "127.0.0.1", port: 9000 }
            upstream: { host: "127.0.0.1", port: 9001 }
            performance: { tcpSockmapAcceleration: sometimes }
            """,
            """
            version: 1
            protocols: [udp]
            listen: { host: "127.0.0.1", port: 9000 }
            upstream: { host: "127.0.0.1", port: 9001 }
            limits: { maxUDPAssociations: 2147483648 }
            """,
            """
            version: 1
            protocols: [udp]
            listen: { host: "127.0.0.1", port: 9000 }
            upstream: { host: "127.0.0.1", port: 9001 }
            performance: { udpSockmapAcceleration: sometimes }
            """,
            """
            version: 1
            protocols: [udp]
            listen: { host: "127.0.0.1", port: 9000 }
            upstream: { host: "127.0.0.1", port: 9001 }
            performance: { udpSocketBufferBytes: -1 }
            """,
            """
            version: 1
            protocols: [udp]
            listen: { host: "127.0.0.1", port: 9000 }
            upstream: { host: "127.0.0.1", port: 9001 }
            performance: { udpSocketBufferBytes: 536870912 }
            """,
            """
            version: 1
            protocols: [udp]
            listen: { host: "127.0.0.1", port: 9000 }
            upstream: { host: "127.0.0.1", port: 9001 }
            performance: { udpIOThreads: -1 }
            """
        ]

        for document in invalidDocuments {
            XCTAssertThrowsError(try ConfigurationLoader.load(yaml: document))
        }
    }

    func testSockmapLoadersRejectInvalidMapSizesBeforeSyscall() {
        XCTAssertThrowsError(try TCPSockmapAccelerator.load(maxEntries: 0))
        XCTAssertThrowsError(try UDPSockmapAccelerator.load(maxEntries: 0))
        XCTAssertThrowsError(try TCPSockmapAccelerator.load(maxEntries: Int(UInt32.max) + 1))
        XCTAssertThrowsError(try UDPSockmapAccelerator.load(maxEntries: Int(UInt32.max) + 1))
    }

    func testResolvesIPv4IPv6AndHostname() throws {
        let ipv4 = try ResolvedConfiguration.resolve(makeConfiguration(upstreamHost: "127.0.0.1"))
        XCTAssertNotNil(ipv4.upstreamAddress.port)

        let ipv6 = try ResolvedConfiguration.resolve(makeConfiguration(upstreamHost: "::1"))
        XCTAssertNotNil(ipv6.upstreamAddress.port)

        let hostname = try ResolvedConfiguration.resolve(makeConfiguration(upstreamHost: "localhost"))
        XCTAssertNotNil(hostname.upstreamAddress.port)
    }

    func testSockmapAutoEnablesLoopbackAndRemoteUpstreams() throws {
        let ipv4 = try ResolvedConfiguration.resolve(makeConfiguration(upstreamHost: "127.42.0.1"))
        XCTAssertTrue(ipv4.shouldEnableTCPSockmap)

        let ipv6 = try ResolvedConfiguration.resolve(makeConfiguration(upstreamHost: "::1"))
        XCTAssertTrue(ipv6.shouldEnableTCPSockmap)

        let hostname = try ResolvedConfiguration.resolve(
            makeConfiguration(upstreamHost: "loopback.internal")
        ) { _, port in
            try SocketAddress(ipAddress: "127.0.0.1", port: port)
        }
        XCTAssertTrue(hostname.shouldEnableTCPSockmap)

        let remote = try ResolvedConfiguration.resolve(makeConfiguration(upstreamHost: "192.0.2.1"))
        XCTAssertTrue(remote.shouldEnableTCPSockmap)
    }

    func testSockmapExplicitModesOverrideAuto() throws {
        var enabled = makeConfiguration(upstreamHost: "127.0.0.1")
        enabled.performance = PerformanceConfiguration(tcpSockmapAcceleration: .enabled)
        XCTAssertTrue(try ResolvedConfiguration.resolve(enabled).shouldEnableTCPSockmap)

        var disabled = makeConfiguration(upstreamHost: "192.0.2.1")
        disabled.performance = PerformanceConfiguration(tcpSockmapAcceleration: .disabled)
        XCTAssertFalse(try ResolvedConfiguration.resolve(disabled).shouldEnableTCPSockmap)

        var udpEnabled = makeConfiguration(upstreamHost: "127.0.0.1")
        udpEnabled.performance = PerformanceConfiguration(udpSockmapAcceleration: .enabled)
        XCTAssertTrue(try ResolvedConfiguration.resolve(udpEnabled).shouldEnableUDPSockmap)

        var udpDisabled = makeConfiguration(upstreamHost: "192.0.2.1")
        udpDisabled.performance = PerformanceConfiguration(udpSockmapAcceleration: .disabled)
        XCTAssertFalse(try ResolvedConfiguration.resolve(udpDisabled).shouldEnableUDPSockmap)

        let udpAuto = try ResolvedConfiguration.resolve(makeConfiguration(upstreamHost: "192.0.2.1"))
        XCTAssertTrue(udpAuto.shouldEnableUDPSockmap)
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
