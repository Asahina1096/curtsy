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
        XCTAssertEqual(configuration.limits.maxUDPAssociations, 4_096)
        XCTAssertEqual(configuration.logging.level, "info")
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
        limits: { tcpListenBacklog: 2048, maxUDPAssociations: 128 }
        logging: { level: debug }
        """)

        XCTAssertEqual(configuration.protocols, [.udp])
        XCTAssertEqual(configuration.timeouts.udpSessionSeconds, 15)
        XCTAssertEqual(configuration.limits.tcpListenBacklog, 2_048)
        XCTAssertEqual(configuration.limits.maxUDPAssociations, 128)
        XCTAssertEqual(configuration.logging.level, "debug")
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

    private func makeConfiguration(upstreamHost: String) -> ForwarderConfiguration {
        ForwarderConfiguration(
            version: 1,
            protocols: [.tcp],
            listen: EndpointConfiguration(host: "127.0.0.1", port: 9000),
            upstream: EndpointConfiguration(host: upstreamHost, port: 9001)
        )
    }
}
