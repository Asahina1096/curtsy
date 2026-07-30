import Foundation
import NIOConcurrencyHelpers
import NIOCore
import NIOEmbedded
import NIOPosix
import XCTest
@testable import Curtsy

final class ForwardingTests: XCTestCase {
    private var group: MultiThreadedEventLoopGroup!

    override func setUp() {
        group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
    }

    override func tearDown() {
        XCTAssertNoThrow(try group.syncShutdownGracefully())
        group = nil
    }

    func testTCPRoundTrip() throws {
        let echo = try ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(TCPEchoHandler())
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        defer { try? echo.close().wait() }

        let configuration = makeResolvedConfiguration(protocols: [.tcp], upstreamPort: echo.localAddress!.port!)
        let listener = TCPListener(
            group: group,
            configuration: configuration,
            log: LogStore(level: "critical"),
            enableSockmapAcceleration: false
        )
        try listener.start()
        XCTAssertEqual(listener.listenerChannelCount, 2)
        defer {
            listener.stopAccepting()
            listener.forceCloseConnections()
        }

        let recorder = DataRecorder(testCase: self)
        let client = try ClientBootstrap(group: group)
            .channelInitializer { channel in
                channel.pipeline.addHandler(TCPRecordingHandler(recorder: recorder))
            }
            .connect(to: listener.localAddresses[0])
            .wait()
        defer { try? client.close().wait() }

        Thread.sleep(forTimeInterval: 0.1)
        XCTAssertEqual(listener.activeConnectionCount, 1)

        var buffer = client.allocator.buffer(capacity: 12)
        buffer.writeString("hello curtsy")
        try client.writeAndFlush(buffer).wait()

        recorder.wait()
        XCTAssertEqual(recorder.string, "hello curtsy")
    }

    func testTCPListenerUsesResolvedSockmapDecisionAndAllowsTestOverride() {
        let loopback = makeResolvedConfiguration(protocols: [.tcp], upstreamPort: 9)
        var loadCount = 0
        let loader: () throws -> TCPSockmapAccelerator = {
            loadCount += 1
            throw TCPSockmapAccelerator.AcceleratorError.unsupportedChannel
        }

        // Auto mode attempts to load even for loopback upstreams.
        let automatic = TCPListener(
            group: group,
            configuration: loopback,
            log: LogStore(level: "critical"),
            loadSockmapAccelerator: loader
        )
        XCTAssertEqual(loadCount, 1)

        // Failed loads are retried on configuration updates while sockmap stays requested.
        automatic.update(configuration: loopback)
        XCTAssertEqual(loadCount, 2)

        // Explicit override forces the decision regardless of configuration.
        _ = TCPListener(
            group: group,
            configuration: loopback,
            log: LogStore(level: "critical"),
            enableSockmapAcceleration: false,
            loadSockmapAccelerator: loader
        )
        XCTAssertEqual(loadCount, 2)

        _ = TCPListener(
            group: group,
            configuration: loopback,
            log: LogStore(level: "critical"),
            enableSockmapAcceleration: true,
            loadSockmapAccelerator: loader
        )
        XCTAssertEqual(loadCount, 3)
    }

    func testTCPBufferBudgetCapsAggregateQueuedBytes() {
        let budget = TCPBufferBudget(limit: 10)

        XCTAssertTrue(budget.tryAcquire(6))
        XCTAssertEqual(budget.used, 6)
        XCTAssertFalse(budget.tryAcquire(5))

        budget.release(6)
        XCTAssertTrue(budget.tryAcquire(10))
        budget.updateLimit(5)
        XCTAssertFalse(budget.tryAcquire(1))

        budget.release(10)
        XCTAssertTrue(budget.tryAcquire(5))
        budget.release(5)
        XCTAssertEqual(budget.used, 0)
    }

    func testTCPLargeTransferCompletesThroughBatchedFlushes() throws {
        let echo = try ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(TCPEchoHandler())
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        defer { try? echo.close().wait() }

        let configuration = makeResolvedConfiguration(protocols: [.tcp], upstreamPort: echo.localAddress!.port!)
        let listener = TCPListener(
            group: group,
            configuration: configuration,
            log: LogStore(level: "critical"),
            enableSockmapAcceleration: false
        )
        try listener.start()
        defer {
            listener.stopAccepting()
            listener.forceCloseConnections()
        }

        let byteCount = 8 * 1_024 * 1_024
        let recorder = ByteCountRecorder(testCase: self, expectedBytes: byteCount)
        let client = try ClientBootstrap(group: group)
            .channelInitializer { channel in
                channel.pipeline.addHandler(TCPByteCountingHandler(recorder: recorder))
            }
            .connect(to: listener.localAddresses[0])
            .wait()
        defer { try? client.close().wait() }

        var buffer = client.allocator.buffer(capacity: byteCount)
        buffer.writeRepeatingByte(0xa5, count: byteCount)
        try client.writeAndFlush(buffer).wait()

        recorder.wait()
        XCTAssertEqual(recorder.bytes, byteCount)
    }

    func testUDPRoundTripAndClientIsolation() throws {
        let echo = try DatagramBootstrap(group: group)
            .channelInitializer { channel in
                channel.pipeline.addHandler(UDPEchoHandler())
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        defer { try? echo.close().wait() }

        let configuration = makeResolvedConfiguration(protocols: [.udp], upstreamPort: echo.localAddress!.port!)
        let listener = UDPListener(
            group: group,
            configuration: configuration,
            log: LogStore(level: "critical"),
            enableSockmapAcceleration: false
        )
        try listener.start()
        defer { listener.stop() }

        let first = try makeUDPClient(message: "first", destination: listener.localAddresses[0])
        defer { try? first.channel.close().wait() }
        let second = try makeUDPClient(message: "second", destination: listener.localAddresses[0])
        defer { try? second.channel.close().wait() }

        first.recorder.wait()
        second.recorder.wait()
        XCTAssertEqual(first.recorder.string, "first")
        XCTAssertEqual(second.recorder.string, "second")
    }

    func testUDPWildcardListenersShareAssociationLimit() throws {
        let echo = try DatagramBootstrap(group: group)
            .channelInitializer { channel in
                channel.pipeline.addHandler(UDPEchoHandler())
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        defer { try? echo.close().wait() }

        var limits = LimitConfiguration()
        limits.maxUDPAssociations = 1
        let configuration = ForwarderConfiguration(
            version: 1,
            protocols: [.udp],
            listen: EndpointConfiguration(host: "*", port: 0),
            upstream: EndpointConfiguration(host: "127.0.0.1", port: echo.localAddress!.port!),
            limits: limits
        )
        let listener = UDPListener(
            group: group,
            configuration: try ResolvedConfiguration.resolve(configuration),
            log: LogStore(level: "critical"),
            enableSockmapAcceleration: false
        )
        try listener.start()
        defer { listener.stop() }

        let ipv4Address = try SocketAddress(
            ipAddress: "127.0.0.1",
            port: listener.localAddresses.first(where: { if case .v4 = $0 { true } else { false } })!.port!
        )
        let ipv6Address = try SocketAddress(
            ipAddress: "::1",
            port: listener.localAddresses.first(where: { if case .v6 = $0 { true } else { false } })!.port!
        )

        let first = try makeUDPClient(message: "first", destination: ipv4Address)
        defer { try? first.channel.close().wait() }
        first.recorder.wait()
        XCTAssertEqual(listener.associationCount, 1)

        let second = try DatagramBootstrap(group: group)
            .bind(host: "::1", port: 0)
            .wait()
        defer { try? second.close().wait() }
        var buffer = second.allocator.buffer(capacity: 6)
        buffer.writeString("second")
        try second.writeAndFlush(AddressedEnvelope(remoteAddress: ipv6Address, data: buffer)).wait()

        Thread.sleep(forTimeInterval: 0.1)
        XCTAssertEqual(listener.associationCount, 1)
    }

    func testUDPMultipleIOThreadsSharePortAndBudget() throws {
        let echo = try DatagramBootstrap(group: group)
            .channelInitializer { channel in
                channel.pipeline.addHandler(UDPEchoHandler())
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        defer { try? echo.close().wait() }

        var performance = PerformanceConfiguration()
        performance.udpIOThreads = 2
        var limits = LimitConfiguration()
        limits.maxUDPAssociations = 2
        let configuration = makeResolvedConfiguration(
            protocols: [.udp],
            upstreamPort: echo.localAddress!.port!,
            limits: limits,
            performance: performance
        )
        let listener = UDPListener(
            group: group,
            configuration: configuration,
            log: LogStore(level: "critical"),
            enableSockmapAcceleration: false
        )
        try listener.start()
        defer { listener.stop() }

        // Both engine threads bind the same address through SO_REUSEPORT, so
        // the listener still exposes exactly one address.
        XCTAssertEqual(listener.localAddresses.count, 1)

        let first = try makeUDPClient(message: "first", destination: listener.localAddresses[0])
        defer { try? first.channel.close().wait() }
        let second = try makeUDPClient(message: "second", destination: listener.localAddresses[0])
        defer { try? second.channel.close().wait() }

        first.recorder.wait()
        second.recorder.wait()
        XCTAssertEqual(first.recorder.string, "first")
        XCTAssertEqual(second.recorder.string, "second")
        // The association limit is shared globally across engine threads.
        XCTAssertTrue(waitForCondition { listener.associationCount == 2 })
    }

    func testUDPResetAssociationsClearsAndRebuilds() throws {
        let echo = try DatagramBootstrap(group: group)
            .channelInitializer { channel in
                channel.pipeline.addHandler(UDPEchoHandler())
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        defer { try? echo.close().wait() }

        let configuration = makeResolvedConfiguration(protocols: [.udp], upstreamPort: echo.localAddress!.port!)
        let listener = UDPListener(
            group: group,
            configuration: configuration,
            log: LogStore(level: "critical"),
            enableSockmapAcceleration: false
        )
        try listener.start()
        defer { listener.stop() }

        let first = try makeUDPClient(message: "first", destination: listener.localAddresses[0])
        defer { try? first.channel.close().wait() }
        first.recorder.wait()
        XCTAssertEqual(first.recorder.string, "first")
        XCTAssertTrue(waitForCondition { listener.associationCount == 1 })

        listener.update(configuration: configuration, resetAssociations: true)
        XCTAssertTrue(waitForCondition { listener.associationCount == 0 })

        let second = try makeUDPClient(message: "second", destination: listener.localAddresses[0])
        defer { try? second.channel.close().wait() }
        second.recorder.wait()
        XCTAssertEqual(second.recorder.string, "second")
        XCTAssertTrue(waitForCondition { listener.associationCount == 1 })
    }

    func testUDPUpstreamActivityRefreshesAssociationExpiry() throws {
        let echo = try DatagramBootstrap(group: group)
            .channelInitializer { channel in
                channel.pipeline.addHandler(UDPEchoHandler())
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        defer { try? echo.close().wait() }

        let configuration = makeResolvedConfiguration(
            protocols: [.udp],
            upstreamPort: echo.localAddress!.port!,
            udpSessionSeconds: 1
        )
        let listener = UDPListener(
            group: group,
            configuration: configuration,
            log: LogStore(level: "critical"),
            enableSockmapAcceleration: false
        )
        try listener.start()
        defer { listener.stop() }

        let client = try makeUDPSocket()
        defer { try? client.close().wait() }
        for _ in 0..<4 {
            try sendUDP(client, "ping", to: listener.localAddresses[0])
            XCTAssertTrue(waitForCondition { listener.associationCount == 1 })
            Thread.sleep(forTimeInterval: 0.4)
        }
        XCTAssertEqual(listener.associationCount, 1)

        // Without further traffic the association expires after one second.
        XCTAssertTrue(waitForCondition(timeout: 3) { listener.associationCount == 0 })
    }

    func testUDPTimeoutReloadExpiresAssociationWithShortenedTimeout() throws {
        let echo = try DatagramBootstrap(group: group)
            .channelInitializer { channel in
                channel.pipeline.addHandler(UDPEchoHandler())
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        defer { try? echo.close().wait() }

        let configuration = makeResolvedConfiguration(
            protocols: [.udp],
            upstreamPort: echo.localAddress!.port!,
            udpSessionSeconds: 10
        )
        let listener = UDPListener(
            group: group,
            configuration: configuration,
            log: LogStore(level: "critical"),
            enableSockmapAcceleration: false
        )
        try listener.start()
        defer { listener.stop() }

        let client = try makeUDPSocket()
        defer { try? client.close().wait() }
        try sendUDP(client, "ping", to: listener.localAddresses[0])
        XCTAssertTrue(waitForCondition { listener.associationCount == 1 })

        let shortened = makeResolvedConfiguration(
            protocols: [.udp],
            upstreamPort: echo.localAddress!.port!,
            udpSessionSeconds: 1
        )
        listener.update(configuration: shortened, resetAssociations: false)
        XCTAssertTrue(waitForCondition(timeout: 3) { listener.associationCount == 0 })
    }

    func testUDPTimeoutReloadCanExtendActiveAssociation() throws {
        let echo = try DatagramBootstrap(group: group)
            .channelInitializer { channel in
                channel.pipeline.addHandler(UDPEchoHandler())
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        defer { try? echo.close().wait() }

        let configuration = makeResolvedConfiguration(
            protocols: [.udp],
            upstreamPort: echo.localAddress!.port!,
            udpSessionSeconds: 1
        )
        let listener = UDPListener(
            group: group,
            configuration: configuration,
            log: LogStore(level: "critical"),
            enableSockmapAcceleration: false
        )
        try listener.start()
        defer { listener.stop() }

        let client = try makeUDPSocket()
        defer { try? client.close().wait() }
        try sendUDP(client, "ping", to: listener.localAddresses[0])
        XCTAssertTrue(waitForCondition { listener.associationCount == 1 })

        let extended = makeResolvedConfiguration(
            protocols: [.udp],
            upstreamPort: echo.localAddress!.port!,
            udpSessionSeconds: 10
        )
        listener.update(configuration: extended, resetAssociations: false)
        Thread.sleep(forTimeInterval: 1.5)
        XCTAssertEqual(listener.associationCount, 1)
    }

    func testUDPListenerUsesResolvedSockmapDecisionAndAllowsTestOverride() throws {
        // Pin a single I/O thread so the loader call counts stay exact.
        var performance = PerformanceConfiguration()
        performance.udpIOThreads = 1
        let loopback = makeResolvedConfiguration(protocols: [.udp], upstreamPort: 9, performance: performance)
        var loadCount = 0
        let loader: (Int) throws -> UDPSockmapAccelerator = { _ in
            loadCount += 1
            throw UDPSockmapAccelerator.AcceleratorError.systemCall(errorNumber: EPERM)
        }

        // Auto mode attempts to load even for loopback upstreams.
        let automatic = UDPListener(
            group: group,
            configuration: loopback,
            log: LogStore(level: "critical"),
            loadSockmapAccelerator: loader
        )
        try automatic.start()
        defer { automatic.stop() }
        XCTAssertEqual(loadCount, 1)

        // Failed loads are retried on configuration updates while sockmap stays requested.
        automatic.update(configuration: loopback, resetAssociations: false)
        XCTAssertTrue(waitForCondition { loadCount == 2 })

        // Explicit override forces the decision regardless of configuration.
        let disabled = UDPListener(
            group: group,
            configuration: loopback,
            log: LogStore(level: "critical"),
            enableSockmapAcceleration: false,
            loadSockmapAccelerator: loader
        )
        try disabled.start()
        defer { disabled.stop() }
        XCTAssertEqual(loadCount, 2)
    }

    func testUDPSockmapLoaderFailureFallsBackToUserspaceRelay() throws {
        let echo = try DatagramBootstrap(group: group)
            .channelInitializer { channel in
                channel.pipeline.addHandler(UDPEchoHandler())
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        defer { try? echo.close().wait() }

        let configuration = makeResolvedConfiguration(protocols: [.udp], upstreamPort: echo.localAddress!.port!)
        let listener = UDPListener(
            group: group,
            configuration: configuration,
            log: LogStore(level: "critical"),
            enableSockmapAcceleration: true,
            loadSockmapAccelerator: { _ in
                throw UDPSockmapAccelerator.AcceleratorError.systemCall(errorNumber: EPERM)
            }
        )
        try listener.start()
        defer { listener.stop() }

        let client = try makeUDPClient(message: "ping", destination: listener.localAddresses[0])
        defer { try? client.channel.close().wait() }
        client.recorder.wait()
        XCTAssertEqual(client.recorder.string, "ping")
        XCTAssertTrue(waitForCondition { listener.associationCount == 1 })
    }

    func testTCPListeningBacklogCanBeUpdatedInPlace() throws {
        let configuration = makeResolvedConfiguration(protocols: [.tcp], upstreamPort: 9)
        let listener = TCPListener(
            group: group,
            configuration: configuration,
            log: LogStore(level: "critical"),
            enableSockmapAcceleration: false
        )
        try listener.start()
        defer {
            listener.stopAccepting()
            listener.forceCloseConnections()
        }
        let addresses = listener.localAddresses

        try listener.updateListeningBacklog(128)

        XCTAssertEqual(listener.currentListeningBacklog, 128)
        XCTAssertEqual(listener.localAddresses, addresses)
    }

    func testWildcardCreatesIPv4AndIPv6Listeners() throws {
        let base = ForwarderConfiguration(
            version: 1,
            protocols: [.tcp],
            listen: EndpointConfiguration(host: "*", port: 0),
            upstream: EndpointConfiguration(host: "127.0.0.1", port: 9)
        )
        let resolved = try ResolvedConfiguration.resolve(base)

        let tcp = TCPListener(
            group: group,
            configuration: resolved,
            log: LogStore(level: "critical"),
            enableSockmapAcceleration: false
        )
        try tcp.start()
        XCTAssertEqual(tcp.localAddresses.count, 2)
        XCTAssertEqual(tcp.listenerChannelCount, 4)
        tcp.stopAccepting()

        let udp = UDPListener(
            group: group,
            configuration: resolved,
            log: LogStore(level: "critical"),
            enableSockmapAcceleration: false
        )
        try udp.start()
        XCTAssertEqual(udp.localAddresses.count, 2)
        udp.stop()
    }

    func testTCPListenerFallsBackWhenSockmapLoaderThrows() throws {
        let echo = try ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(TCPEchoHandler())
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        defer { try? echo.close().wait() }

        let configuration = makeResolvedConfiguration(
            protocols: [.tcp],
            upstreamPort: echo.localAddress!.port!
        )
        let listener = TCPListener(
            group: group,
            configuration: configuration,
            log: LogStore(level: "critical"),
            enableSockmapAcceleration: true,
            loadSockmapAccelerator: {
                throw TCPSockmapAccelerator.AcceleratorError.unsupportedChannel
            }
        )
        try listener.start()
        defer {
            listener.stopAccepting()
            listener.forceCloseConnections()
        }

        let recorder = DataRecorder(testCase: self)
        let client = try ClientBootstrap(group: group)
            .channelInitializer { channel in
                channel.pipeline.addHandler(TCPRecordingHandler(recorder: recorder))
            }
            .connect(to: listener.localAddresses[0])
            .wait()
        defer { try? client.close().wait() }

        var buffer = client.allocator.buffer(capacity: 8)
        buffer.writeString("fallback")
        try client.writeAndFlush(buffer).wait()

        recorder.wait()
        XCTAssertEqual(recorder.string, "fallback")
    }

    func testEBPFLoadersWhenExplicitlyEnabled() throws {
        guard ProcessInfo.processInfo.environment["CURTSY_ENABLE_EBPF_TESTS"] == "1" else {
            throw XCTSkip("set CURTSY_ENABLE_EBPF_TESTS=1 on a Linux host with eBPF permissions")
        }

        let reusePortProgram = try ReusePortBPFProgram.load(workerCount: 1)
        reusePortProgram.close()

        _ = try TCPSockmapAccelerator.load(maxEntries: 8)

        let observer = try BPFObserver.load()
        _ = try observer.readCounters()
    }

    private func makeUDPClient(message: String, destination: SocketAddress) throws -> (channel: Channel, recorder: DataRecorder) {
        let recorder = DataRecorder(testCase: self)
        let channel = try DatagramBootstrap(group: group)
            .channelInitializer { channel in
                channel.pipeline.addHandler(UDPRecordingHandler(recorder: recorder))
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        try sendUDP(channel, message, to: destination)
        return (channel, recorder)
    }

    private func makeUDPSocket() throws -> Channel {
        try DatagramBootstrap(group: group)
            .bind(host: "127.0.0.1", port: 0)
            .wait()
    }

    private func sendUDP(_ channel: Channel, _ message: String, to destination: SocketAddress) throws {
        var buffer = channel.allocator.buffer(capacity: message.utf8.count)
        buffer.writeString(message)
        try channel.writeAndFlush(AddressedEnvelope(remoteAddress: destination, data: buffer)).wait()
    }

    private func waitForCondition(
        timeout: TimeInterval = 3,
        _ condition: @escaping () -> Bool
    ) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() { return true }
            Thread.sleep(forTimeInterval: 0.02)
        }
        return condition()
    }

    private func makeResolvedConfiguration(
        protocols: [ForwardProtocol],
        upstreamHost: String = "127.0.0.1",
        upstreamPort: Int,
        udpSessionSeconds: Int = 5,
        limits: LimitConfiguration = .init(),
        performance: PerformanceConfiguration = .init()
    ) -> ResolvedConfiguration {
        var timeouts = TimeoutConfiguration()
        timeouts.tcpIdleSeconds = 5
        timeouts.udpSessionSeconds = udpSessionSeconds
        let configuration = ForwarderConfiguration(
            version: 1,
            protocols: protocols,
            listen: EndpointConfiguration(host: "127.0.0.1", port: 0),
            upstream: EndpointConfiguration(host: upstreamHost, port: upstreamPort),
            timeouts: timeouts,
            limits: limits,
            performance: performance
        )
        return try! ResolvedConfiguration.resolve(configuration)
    }
}

private final class DataRecorder: @unchecked Sendable {
    private let expectation: XCTestExpectation
    private let storage = NIOLockedValueBox<String?>(nil)
    private weak var testCase: XCTestCase?

    init(testCase: XCTestCase) {
        self.testCase = testCase
        expectation = testCase.expectation(description: "received forwarded data")
    }

    var string: String? { storage.withLockedValue { $0 } }

    func record(_ buffer: ByteBuffer) {
        storage.withLockedValue { $0 = buffer.getString(at: buffer.readerIndex, length: buffer.readableBytes) }
        expectation.fulfill()
    }

    func wait() {
        guard let testCase else { return }
        testCase.wait(for: [expectation], timeout: 3)
    }
}

private final class ByteCountRecorder: @unchecked Sendable {
    private struct State {
        var bytes = 0
        var fulfilled = false
    }

    private let expectation: XCTestExpectation
    private let expectedBytes: Int
    private let storage = NIOLockedValueBox(State())
    private weak var testCase: XCTestCase?

    init(testCase: XCTestCase, expectedBytes: Int) {
        self.testCase = testCase
        self.expectedBytes = expectedBytes
        expectation = testCase.expectation(description: "received complete large TCP transfer")
    }

    var bytes: Int { storage.withLockedValue(\.bytes) }

    func record(_ buffer: ByteBuffer) {
        let shouldFulfill = storage.withLockedValue { state in
            state.bytes += buffer.readableBytes
            if state.bytes >= expectedBytes, !state.fulfilled {
                state.fulfilled = true
                return true
            }
            return false
        }
        if shouldFulfill { expectation.fulfill() }
    }

    func wait() {
        guard let testCase else { return }
        testCase.wait(for: [expectation], timeout: 5)
    }
}

private final class TCPEchoHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.write(data, promise: nil)
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        context.flush()
    }
}

private final class TCPRecordingHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private let recorder: DataRecorder

    init(recorder: DataRecorder) { self.recorder = recorder }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        recorder.record(unwrapInboundIn(data))
    }
}

private final class TCPByteCountingHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private let recorder: ByteCountRecorder

    init(recorder: ByteCountRecorder) { self.recorder = recorder }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        recorder.record(unwrapInboundIn(data))
    }
}

private final class UDPEchoHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.writeAndFlush(data, promise: nil)
    }
}

private final class UDPRecordingHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    private let recorder: DataRecorder

    init(recorder: DataRecorder) { self.recorder = recorder }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        recorder.record(unwrapInboundIn(data).data)
    }
}
