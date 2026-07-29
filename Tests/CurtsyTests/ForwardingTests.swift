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

        let automatic = TCPListener(
            group: group,
            configuration: loopback,
            log: LogStore(level: "critical"),
            loadSockmapAccelerator: {
                loadCount += 1
                return nil
            }
        )
        XCTAssertEqual(loadCount, 0)

        let remote = makeResolvedConfiguration(
            protocols: [.tcp],
            upstreamHost: "192.0.2.1",
            upstreamPort: 9
        )
        automatic.update(configuration: remote)
        XCTAssertEqual(loadCount, 1)
        automatic.update(configuration: loopback)
        automatic.update(configuration: remote)
        XCTAssertEqual(loadCount, 2)

        _ = TCPListener(
            group: group,
            configuration: loopback,
            log: LogStore(level: "critical"),
            enableSockmapAcceleration: true,
            loadSockmapAccelerator: {
                loadCount += 1
                return nil
            }
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
        let listener = UDPListener(group: group, configuration: configuration, log: LogStore(level: "critical"))
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
            log: LogStore(level: "critical")
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

    func testUDPResetRejectsStalePendingConnection() throws {
        let eventLoop = EmbeddedEventLoop()
        let connectionPromise = eventLoop.makePromise(of: Channel.self)
        let budget = UDPAssociationBudget()
        let configuration = makeResolvedConfiguration(protocols: [.udp], upstreamPort: 9)
        let handler = UDPRelayHandler(
            runtime: RuntimeConfiguration(configuration),
            budget: budget,
            log: LogStore(level: "critical"),
            connectUpstream: { _, _, _, _, _, _ in connectionPromise.futureResult }
        )
        let listener = EmbeddedChannel(handler: handler, loop: eventLoop)
        let clientAddress = try SocketAddress(ipAddress: "127.0.0.1", port: 12_345)
        var buffer = listener.allocator.buffer(capacity: 4)
        buffer.writeString("test")

        XCTAssertNoThrow(
            try listener.writeInbound(AddressedEnvelope(remoteAddress: clientAddress, data: buffer))
        )
        XCTAssertEqual(budget.count, 1)

        handler.resetAssociations()
        XCTAssertEqual(budget.count, 0)

        let staleUpstream = EmbeddedChannel(loop: eventLoop)
        connectionPromise.succeed(staleUpstream)
        eventLoop.run()

        XCTAssertFalse(staleUpstream.isActive)
        XCTAssertEqual(budget.count, 0)
        XCTAssertNoThrow(try listener.finish())
        _ = try? staleUpstream.finish()
    }

    func testUDPPendingAssociationDatagramLimitDropsExcessBuffers() throws {
        let eventLoop = EmbeddedEventLoop()
        let connectionPromise = eventLoop.makePromise(of: Channel.self)
        let budget = UDPAssociationBudget()
        var limits = LimitConfiguration()
        limits.maxUDPPendingDatagrams = 2
        limits.maxUDPPendingBytes = 1_024
        let configuration = makeResolvedConfiguration(
            protocols: [.udp],
            upstreamPort: 9,
            limits: limits
        )
        let handler = UDPRelayHandler(
            runtime: RuntimeConfiguration(configuration),
            budget: budget,
            log: LogStore(level: "critical"),
            connectUpstream: { _, _, _, _, _, _ in connectionPromise.futureResult }
        )
        let listener = EmbeddedChannel(handler: handler, loop: eventLoop)
        let clientAddress = try SocketAddress(ipAddress: "127.0.0.1", port: 12_345)

        for value in ["one", "two", "three"] {
            var buffer = listener.allocator.buffer(capacity: value.utf8.count)
            buffer.writeString(value)
            XCTAssertNoThrow(
                try listener.writeInbound(AddressedEnvelope(remoteAddress: clientAddress, data: buffer))
            )
        }
        XCTAssertEqual(budget.count, 1)

        let upstream = EmbeddedChannel(loop: eventLoop)
        connectionPromise.succeed(upstream)
        eventLoop.run()

        let first: ByteBuffer? = try upstream.readOutbound()
        let second: ByteBuffer? = try upstream.readOutbound()
        let third: ByteBuffer? = try upstream.readOutbound()
        XCTAssertEqual(first.map { $0.getString(at: $0.readerIndex, length: $0.readableBytes) }, "one")
        XCTAssertEqual(second.map { $0.getString(at: $0.readerIndex, length: $0.readableBytes) }, "two")
        XCTAssertNil(third)
        XCTAssertNoThrow(try listener.finish())
        _ = try? upstream.finish()
    }

    func testUDPPendingAssociationByteLimitRejectsOversizedFirstDatagram() throws {
        let eventLoop = EmbeddedEventLoop()
        let budget = UDPAssociationBudget()
        var connectCount = 0
        var limits = LimitConfiguration()
        limits.maxUDPPendingBytes = 2
        let configuration = makeResolvedConfiguration(
            protocols: [.udp],
            upstreamPort: 9,
            limits: limits
        )
        let handler = UDPRelayHandler(
            runtime: RuntimeConfiguration(configuration),
            budget: budget,
            log: LogStore(level: "critical"),
            connectUpstream: { _, _, _, _, _, _ in
                connectCount += 1
                return eventLoop.makeSucceededFuture(EmbeddedChannel(loop: eventLoop))
            }
        )
        let listener = EmbeddedChannel(handler: handler, loop: eventLoop)
        let clientAddress = try SocketAddress(ipAddress: "127.0.0.1", port: 12_345)
        var buffer = listener.allocator.buffer(capacity: 3)
        buffer.writeString("big")

        XCTAssertNoThrow(
            try listener.writeInbound(AddressedEnvelope(remoteAddress: clientAddress, data: buffer))
        )

        XCTAssertEqual(connectCount, 0)
        XCTAssertEqual(budget.count, 0)
        XCTAssertNoThrow(try listener.finish())
    }

    func testUDPUpstreamActivityRefreshesAssociationExpiry() throws {
        let eventLoop = EmbeddedEventLoop()
        let connectionPromise = eventLoop.makePromise(of: Channel.self)
        let activity = NIOLockedValueBox<(@Sendable () -> Void)?>(nil)
        let budget = UDPAssociationBudget()
        let configuration = makeResolvedConfiguration(protocols: [.udp], upstreamPort: 9)
        let handler = UDPRelayHandler(
            runtime: RuntimeConfiguration(configuration),
            budget: budget,
            log: LogStore(level: "critical"),
            connectUpstream: { _, _, _, _, _, recordActivity in
                activity.withLockedValue { $0 = recordActivity }
                return connectionPromise.futureResult
            }
        )
        let listener = EmbeddedChannel(handler: handler, loop: eventLoop)
        let clientAddress = try SocketAddress(ipAddress: "127.0.0.1", port: 12_345)
        var buffer = listener.allocator.buffer(capacity: 4)
        buffer.writeString("test")

        XCTAssertNoThrow(
            try listener.writeInbound(AddressedEnvelope(remoteAddress: clientAddress, data: buffer))
        )
        let upstream = EmbeddedChannel(loop: eventLoop)
        connectionPromise.succeed(upstream)
        eventLoop.run()
        XCTAssertEqual(budget.count, 1)

        eventLoop.advanceTime(by: .seconds(4))
        activity.withLockedValue { $0 }?()
        eventLoop.run()
        eventLoop.advanceTime(by: .seconds(4))
        XCTAssertEqual(budget.count, 1)

        eventLoop.advanceTime(by: .seconds(2))
        XCTAssertEqual(budget.count, 0)
        XCTAssertNoThrow(try listener.finish())
        _ = try? upstream.finish()
    }

    func testUDPTimeoutReloadReschedulesActiveAssociation() throws {
        let eventLoop = EmbeddedEventLoop()
        let connectionPromise = eventLoop.makePromise(of: Channel.self)
        let budget = UDPAssociationBudget()
        let initial = makeResolvedConfiguration(
            protocols: [.udp],
            upstreamPort: 9,
            udpSessionSeconds: 10
        )
        let runtime = RuntimeConfiguration(initial)
        let handler = UDPRelayHandler(
            runtime: runtime,
            budget: budget,
            log: LogStore(level: "critical"),
            connectUpstream: { _, _, _, _, _, _ in connectionPromise.futureResult }
        )
        let listener = EmbeddedChannel(handler: handler, loop: eventLoop)
        let clientAddress = try SocketAddress(ipAddress: "127.0.0.1", port: 12_345)
        var buffer = listener.allocator.buffer(capacity: 4)
        buffer.writeString("test")

        XCTAssertNoThrow(
            try listener.writeInbound(AddressedEnvelope(remoteAddress: clientAddress, data: buffer))
        )
        let upstream = EmbeddedChannel(loop: eventLoop)
        connectionPromise.succeed(upstream)
        eventLoop.run()
        XCTAssertEqual(budget.count, 1)

        eventLoop.advanceTime(by: .seconds(6))
        let shortened = makeResolvedConfiguration(
            protocols: [.udp],
            upstreamPort: 9,
            udpSessionSeconds: 5
        )
        runtime.update(shortened)
        handler.rescheduleAssociationExpiries(on: eventLoop)

        XCTAssertEqual(budget.count, 0)
        XCTAssertFalse(upstream.isActive)
        XCTAssertNoThrow(try listener.finish())
        _ = try? upstream.finish()
    }

    func testUDPTimeoutReloadCanExtendActiveAssociation() throws {
        let eventLoop = EmbeddedEventLoop()
        let connectionPromise = eventLoop.makePromise(of: Channel.self)
        let budget = UDPAssociationBudget()
        let initial = makeResolvedConfiguration(
            protocols: [.udp],
            upstreamPort: 9,
            udpSessionSeconds: 5
        )
        let runtime = RuntimeConfiguration(initial)
        let handler = UDPRelayHandler(
            runtime: runtime,
            budget: budget,
            log: LogStore(level: "critical"),
            connectUpstream: { _, _, _, _, _, _ in connectionPromise.futureResult }
        )
        let listener = EmbeddedChannel(handler: handler, loop: eventLoop)
        let clientAddress = try SocketAddress(ipAddress: "127.0.0.1", port: 12_345)
        var buffer = listener.allocator.buffer(capacity: 4)
        buffer.writeString("test")

        XCTAssertNoThrow(
            try listener.writeInbound(AddressedEnvelope(remoteAddress: clientAddress, data: buffer))
        )
        let upstream = EmbeddedChannel(loop: eventLoop)
        connectionPromise.succeed(upstream)
        eventLoop.run()
        XCTAssertEqual(budget.count, 1)

        eventLoop.advanceTime(by: .seconds(4))
        let extended = makeResolvedConfiguration(
            protocols: [.udp],
            upstreamPort: 9,
            udpSessionSeconds: 10
        )
        runtime.update(extended)
        handler.rescheduleAssociationExpiries(on: eventLoop)

        eventLoop.advanceTime(by: .seconds(2))
        XCTAssertEqual(budget.count, 1)
        eventLoop.advanceTime(by: .seconds(4))
        XCTAssertEqual(budget.count, 0)
        XCTAssertFalse(upstream.isActive)
        XCTAssertNoThrow(try listener.finish())
        _ = try? upstream.finish()
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

        let udp = UDPListener(group: group, configuration: resolved, log: LogStore(level: "critical"))
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

    func testOptionalEBPFLoadersWhenExplicitlyEnabled() throws {
        #if os(Linux)
        guard ProcessInfo.processInfo.environment["CURTSY_ENABLE_EBPF_TESTS"] == "1" else {
            throw XCTSkip("set CURTSY_ENABLE_EBPF_TESTS=1 on a Linux host with eBPF permissions")
        }

        let reusePortProgram = try ReusePortBPFProgram.load(workerCount: 1)
        reusePortProgram?.close()

        let sockmapAccelerator = try TCPSockmapAccelerator.load(maxEntries: 8)
        XCTAssertNotNil(sockmapAccelerator)

        let observer = try BPFObserver.load()
        _ = try observer.readCounters()
        #else
        throw XCTSkip("eBPF loader tests only run on Linux")
        #endif
    }

    private func makeUDPClient(message: String, destination: SocketAddress) throws -> (channel: Channel, recorder: DataRecorder) {
        let recorder = DataRecorder(testCase: self)
        let channel = try DatagramBootstrap(group: group)
            .channelInitializer { channel in
                channel.pipeline.addHandler(UDPRecordingHandler(recorder: recorder))
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        var buffer = channel.allocator.buffer(capacity: message.utf8.count)
        buffer.writeString(message)
        try channel.writeAndFlush(AddressedEnvelope(remoteAddress: destination, data: buffer)).wait()
        return (channel, recorder)
    }

    private func makeResolvedConfiguration(
        protocols: [ForwardProtocol],
        upstreamHost: String = "127.0.0.1",
        upstreamPort: Int,
        udpSessionSeconds: Int = 5,
        limits: LimitConfiguration = .init()
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
            limits: limits
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
