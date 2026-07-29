import Atomics
import Glibc
import NIOConcurrencyHelpers
import NIOCore
import NIOPosix

private enum TCPPerformanceTuning {
    // Large reads and batched flushes keep syscall and event-loop overhead low enough
    // for a single connection to sustain gigabit throughput.
    static var receiveAllocator: AdaptiveRecvByteBufferAllocator {
        AdaptiveRecvByteBufferAllocator(
            minimum: 64 * 1_024,
            initial: 256 * 1_024,
            maximum: 1_024 * 1_024
        )
    }

    // Eight 1 MiB buffers form an 8 MiB maximum read batch, halving the read
    // and epoll_wait syscall rate measured under load compared to four buffers.
    static let maxMessagesPerRead: UInt = 8
    // Keep one full read batch below the high watermark with hysteresis above
    // the low watermark so a batch never toggles autoRead or issues redundant
    // epoll_ctl calls. Worst case is 12 MiB buffered per connection, still
    // bounded globally by TCPBufferBudget.
    static let writeBufferWaterMark = ChannelOptions.Types.WriteBufferWaterMark(
        low: 4 * 1_024 * 1_024,
        high: 12 * 1_024 * 1_024
    )
}

final class TCPBufferBudget: @unchecked Sendable {
    private let usedBytes = ManagedAtomic(0)
    private let configuredLimit: ManagedAtomic<Int>

    init(limit: Int) {
        precondition(limit > 0)
        configuredLimit = ManagedAtomic(limit)
    }

    func tryAcquire(_ byteCount: Int) -> Bool {
        guard byteCount > 0 else { return true }
        while true {
            let current = usedBytes.load(ordering: .relaxed)
            let limit = configuredLimit.load(ordering: .relaxed)
            guard current <= limit, byteCount <= limit - current else { return false }
            let result = usedBytes.compareExchange(
                expected: current,
                desired: current + byteCount,
                ordering: .relaxed
            )
            if result.exchanged { return true }
        }
    }

    func release(_ byteCount: Int) {
        guard byteCount > 0 else { return }
        let previous = usedBytes.loadThenWrappingDecrement(by: byteCount, ordering: .relaxed)
        precondition(previous >= byteCount, "TCP buffer budget released more than acquired")
    }

    func updateLimit(_ limit: Int) {
        precondition(limit > 0)
        configuredLimit.store(limit, ordering: .relaxed)
    }

    var limit: Int { configuredLimit.load(ordering: .relaxed) }
    var used: Int { usedBytes.load(ordering: .relaxed) }
}

final class TCPListener: @unchecked Sendable {
    private struct State {
        var configuration: ResolvedConfiguration
        var sockmapRequested: Bool
        var sockmapAccelerator: TCPSockmapAccelerator?
    }

    private let group: EventLoopGroup
    private let state: NIOLockedValueBox<State>
    private let log: LogStore
    private let bufferBudget: TCPBufferBudget
    private let enableSockmapAccelerationOverride: Bool?
    private let loadSockmapAccelerator: () throws -> TCPSockmapAccelerator
    private let activeChannels = ChannelRegistry()
    private let accepting = ManagedAtomic(true)
    private var listenerChannels: [Channel] = []
    private var configuredBacklog: Int

    init(
        group: EventLoopGroup,
        configuration: ResolvedConfiguration,
        log: LogStore,
        enableSockmapAcceleration: Bool? = nil,
        bufferBudget: TCPBufferBudget? = nil,
        loadSockmapAccelerator: @escaping () throws -> TCPSockmapAccelerator = {
            try TCPSockmapAccelerator.load()
        }
    ) {
        self.group = group
        self.log = log
        self.bufferBudget = bufferBudget ?? TCPBufferBudget(
            limit: configuration.configuration.limits.maxTCPBufferedBytes
        )
        enableSockmapAccelerationOverride = enableSockmapAcceleration
        self.loadSockmapAccelerator = loadSockmapAccelerator
        configuredBacklog = configuration.configuration.limits.tcpListenBacklog
        let shouldEnableSockmap = enableSockmapAcceleration ?? configuration.shouldEnableTCPSockmap
        let accelerator: TCPSockmapAccelerator?
        if shouldEnableSockmap {
            do {
                accelerator = try loadSockmapAccelerator()
                log.info("tcp sockmap acceleration enabled")
            } catch {
                accelerator = nil
                log.warning("tcp sockmap acceleration unavailable; using userspace relay error=\(error)")
            }
        } else {
            accelerator = nil
            log.info("tcp sockmap acceleration disabled")
        }
        state = NIOLockedValueBox(
            State(
                configuration: configuration,
                sockmapRequested: shouldEnableSockmap,
                sockmapAccelerator: accelerator
            )
        )
    }

    func start() throws {
        let resolved = state.withLockedValue(\.configuration)
        let configuration = resolved.configuration
        let eventLoops = Array(group.makeIterator())
        let workerCount = eventLoops.count
        var bound: [Channel] = []

        let reusePortProgram: ReusePortBPFProgram?
        if workerCount > 1 {
            do {
                reusePortProgram = try ReusePortBPFProgram.load(workerCount: workerCount)
            } catch {
                reusePortProgram = nil
                log.warning("tcp reuseport eBPF unavailable; using kernel hash workers=\(workerCount) error=\(error)")
            }
        } else {
            reusePortProgram = nil
        }
        defer { reusePortProgram?.close() }

        do {
            for listenAddress in resolved.listenAddresses {
                var hostChannels: [Channel] = []
                var bindAddress = listenAddress

                for eventLoop in eventLoops {
                    var bootstrap = ServerBootstrap(group: eventLoop, childGroup: eventLoop)
                        .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
                        .serverChannelOption(ReusePortSocketOptions.reusePort, value: 1)
                        .serverChannelOption(.backlog, value: Int32(configuration.limits.tcpListenBacklog))
                        .childChannelOption(.tcpOption(.tcp_nodelay), value: 1)
                        .childChannelOption(.allowRemoteHalfClosure, value: true)
                        .childChannelOption(.autoRead, value: false)
                        .childChannelOption(.recvAllocator, value: TCPPerformanceTuning.receiveAllocator)
                        .childChannelOption(.maxMessagesPerRead, value: TCPPerformanceTuning.maxMessagesPerRead)
                        .childChannelOption(.writeBufferWaterMark, value: TCPPerformanceTuning.writeBufferWaterMark)
                        .childChannelInitializer { [self] channel in
                            return self.initializeClient(channel).flatMapError { error in
                                self.log.error("tcp client initialization failed error=\(error)")
                                return channel.eventLoop.makeFailedFuture(error)
                            }
                        }

                    if case .v6 = listenAddress {
                        bootstrap = bootstrap.serverChannelOption(
                            ChannelOptions.Types.SocketOption(level: .ipv6, name: .ipv6_v6only),
                            value: 1
                        )
                    }

                    let channel = try bootstrap.bind(to: bindAddress).wait()
                    hostChannels.append(channel)
                    bound.append(channel)
                    if listenAddress.port == 0, let localAddress = channel.localAddress {
                        bindAddress = localAddress
                    }
                }

                var balancer = workerCount > 1 ? "kernel-hash" : "single-worker"
                if let reusePortProgram, let channel = hostChannels.first {
                    do {
                        try reusePortProgram.attach(to: channel)
                        balancer = "ebpf"
                    } catch {
                        log.warning("tcp reuseport eBPF attach failed; using kernel hash address=\(listenAddress.curtsyDescription) error=\(error)")
                    }
                }
                let address = hostChannels.first?.localAddress?.curtsyDescription
                    ?? listenAddress.curtsyDescription
                log.info("tcp listening on \(address) workers=\(workerCount) balancer=\(balancer)")
            }
            listenerChannels = bound
        } catch {
            accepting.store(false, ordering: .releasing)
            for channel in bound { try? channel.close().wait() }
            activeChannels.closeAll()
            throw error
        }
    }

    func update(configuration: ResolvedConfiguration) {
        let requested = enableSockmapAccelerationOverride ?? configuration.shouldEnableTCPSockmap
        let current = state.withLockedValue { ($0.sockmapRequested, $0.sockmapAccelerator) }
        var accelerator = current.1

        if requested {
            if accelerator == nil {
                do {
                    accelerator = try loadSockmapAccelerator()
                    log.info("tcp sockmap acceleration enabled")
                } catch {
                    log.warning("tcp sockmap acceleration unavailable; using userspace relay error=\(error)")
                }
            }
        } else {
            accelerator = nil
            if current.0 {
                log.info("tcp sockmap acceleration disabled")
            }
        }

        bufferBudget.updateLimit(configuration.configuration.limits.maxTCPBufferedBytes)
        state.withLockedValue {
            $0 = State(
                configuration: configuration,
                sockmapRequested: requested,
                sockmapAccelerator: accelerator
            )
        }
    }

    func updateListeningBacklog(_ backlog: Int) throws {
        guard backlog != configuredBacklog else { return }
        let oldBacklog = configuredBacklog
        var updatedChannels: [Channel] = []
        do {
            for channel in listenerChannels {
                try setListeningBacklog(backlog, on: channel)
                updatedChannels.append(channel)
            }
            configuredBacklog = backlog
        } catch {
            for channel in updatedChannels {
                try? setListeningBacklog(oldBacklog, on: channel)
            }
            throw error
        }
    }

    var currentListeningBacklog: Int { configuredBacklog }

    func stopAccepting() {
        accepting.store(false, ordering: .releasing)
        let channels = listenerChannels
        listenerChannels.removeAll()
        for channel in channels { try? channel.close().wait() }
    }

    var activeConnectionCount: Int { activeChannels.count }

    var listenerChannelCount: Int { listenerChannels.count }

    var localAddresses: [SocketAddress] {
        var seen: Set<String> = []
        return listenerChannels.compactMap(\.localAddress).filter { address in
            seen.insert(address.curtsyDescription).inserted
        }
    }

    func forceCloseConnections() {
        activeChannels.closeAll()
    }

    private func initializeClient(_ client: Channel) -> EventLoopFuture<Void> {
        guard accepting.load(ordering: .acquiring) else {
            return client.close()
        }
        let connectionState = state.withLockedValue {
            ($0.configuration, $0.sockmapAccelerator)
        }
        log.debug("tcp accepted client=\(client.remoteAddress?.curtsyDescription ?? "unknown")")
        activeChannels.insert(client)
        guard accepting.load(ordering: .acquiring) else {
            return client.close()
        }
        return client.pipeline.addHandler(
            TCPFrontendHandler(
                snapshot: connectionState.0,
                log: log,
                sockmapAccelerator: connectionState.1,
                bufferBudget: bufferBudget
            )
        )
    }

    private func setListeningBacklog(_ backlog: Int, on channel: Channel) throws {
        try channel.eventLoop.submit {
            let result = try channel.pipeline.syncOperations.withUnsafeTransportIfAvailable(
                of: NIOBSDSocket.Handle.self
            ) { descriptor -> Bool in
                let status = Glibc.listen(descriptor, Int32(backlog))
                guard status == 0 else {
                    throw IOError(errnoCode: errno, reason: "listen backlog update")
                }
                return true
            }
            guard result == true else {
                throw IOError(errnoCode: ENOTSUP, reason: "channel does not expose its socket")
            }
        }.wait()
    }
}

private final class TCPFrontendHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    private let snapshot: ResolvedConfiguration
    private let log: LogStore
    private let sockmapAccelerator: TCPSockmapAccelerator?
    private let bufferBudget: TCPBufferBudget
    private var upstream: Channel?
    private var acceleration: TCPSockmapConnection?
    private var idleCheck: Scheduled<Void>?
    private var bytes: Int64 = 0
    private var bufferLimitExceeded = false

    init(
        snapshot: ResolvedConfiguration,
        log: LogStore,
        sockmapAccelerator: TCPSockmapAccelerator?,
        bufferBudget: TCPBufferBudget
    ) {
        self.snapshot = snapshot
        self.log = log
        self.sockmapAccelerator = sockmapAccelerator
        self.bufferBudget = bufferBudget
    }

    func channelActive(context: ChannelHandlerContext) {
        let configuration = snapshot.configuration
        let clientChannel = context.channel
        let clientAddress = clientChannel.remoteAddress?.curtsyDescription ?? "unknown"
        log.debug("tcp opening upstream client=\(clientAddress) upstream=\(snapshot.upstreamAddress.curtsyDescription)")
        let bootstrap = ClientBootstrap(group: context.eventLoop)
            .channelOption(.tcpOption(.tcp_nodelay), value: 1)
            .channelOption(.allowRemoteHalfClosure, value: true)
            .channelOption(.autoRead, value: false)
            .channelOption(.connectTimeout, value: .seconds(Int64(configuration.timeouts.connectSeconds)))
            .channelOption(.recvAllocator, value: TCPPerformanceTuning.receiveAllocator)
            .channelOption(.maxMessagesPerRead, value: TCPPerformanceTuning.maxMessagesPerRead)
            .channelOption(.writeBufferWaterMark, value: TCPPerformanceTuning.writeBufferWaterMark)

        bootstrap.connect(to: snapshot.upstreamAddress).whenComplete { [weak self] result in
            guard let self else {
                if case .success(let upstream) = result {
                    upstream.close(promise: nil)
                }
                return
            }
            switch result {
            case .success(let upstream):
                let timeout = TimeAmount.seconds(Int64(configuration.timeouts.tcpIdleSeconds))
                let relayHandler = TCPRelayHandler(
                    peer: clientChannel,
                    log: self.log,
                    bufferBudget: self.bufferBudget
                )
                do {
                    try upstream.pipeline.syncOperations.addHandler(relayHandler)
                } catch {
                    self.log.error("tcp pipeline setup failed client=\(clientAddress) error=\(error)")
                    upstream.close(promise: nil)
                    clientChannel.close(promise: nil)
                    return
                }
                self.upstream = upstream

                guard let sockmapAccelerator = self.sockmapAccelerator else {
                    self.activateUserspaceRelay(
                        client: clientChannel,
                        upstream: upstream,
                        timeout: timeout,
                        clientAddress: clientAddress
                    )
                    return
                }

                sockmapAccelerator.pair(client: clientChannel, upstream: upstream).whenComplete { result in
                    switch result {
                    case .success(let acceleration):
                        guard clientChannel.isActive, upstream.isActive else {
                            acceleration.close()
                            upstream.close(promise: nil)
                            clientChannel.close(promise: nil)
                            return
                        }
                        self.acceleration = acceleration
                        relayHandler.acceleration = acceleration
                        self.scheduleAcceleratedIdleCheck(
                            client: clientChannel,
                            upstream: upstream,
                            timeoutSeconds: configuration.timeouts.tcpIdleSeconds
                        )
                        self.activateReads(client: clientChannel, upstream: upstream, clientAddress: clientAddress)
                        self.log.debug("tcp connected mode=sockmap client=\(clientAddress) upstream=\(self.snapshot.upstreamAddress.curtsyDescription)")
                    case .failure(let error):
                        self.log.debug("tcp sockmap pairing failed; using userspace relay client=\(clientAddress) error=\(error)")
                        self.activateUserspaceRelay(
                            client: clientChannel,
                            upstream: upstream,
                            timeout: timeout,
                            clientAddress: clientAddress
                        )
                    }
                }
            case .failure(let error):
                self.log.error("tcp connect failed client=\(clientAddress) upstream=\(self.snapshot.upstreamAddress.curtsyDescription) error=\(error)")
                clientChannel.close(promise: nil)
            }
        }
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard let upstream, !bufferLimitExceeded else { return }
        let buffer = unwrapInboundIn(data)
        bytes += Int64(buffer.readableBytes)
        guard write(buffer, to: upstream) else {
            bufferLimitExceeded = true
            log.warning("tcp buffer budget exhausted limit=\(bufferBudget.limit)")
            upstream.close(promise: nil)
            context.close(promise: nil)
            return
        }
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        upstream?.flush()
        context.fireChannelReadComplete()
    }

    func channelWritabilityChanged(context: ChannelHandlerContext) {
        upstream?.setOption(.autoRead, value: context.channel.isWritable).whenFailure { [log] error in
            log.error("tcp backpressure update failed error=\(error)")
        }
        context.fireChannelWritabilityChanged()
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let channelEvent = event as? ChannelEvent, channelEvent == .inputClosed {
            upstream?.close(mode: .output, promise: nil)
            return
        }
        if event is IdleStateHandler.IdleStateEvent {
            upstream?.close(promise: nil)
            context.close(promise: nil)
            return
        }
        context.fireUserInboundEventTriggered(event)
    }

    func channelInactive(context: ChannelHandlerContext) {
        idleCheck?.cancel()
        acceleration?.close()
        upstream?.close(promise: nil)
        log.debug("tcp client connection closed bytes_to_upstream=\(bytes)")
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        idleCheck?.cancel()
        acceleration?.close()
        log.error("tcp client channel error error=\(error)")
        upstream?.close(promise: nil)
        context.close(promise: nil)
    }

    private func activateUserspaceRelay(
        client: Channel,
        upstream: Channel,
        timeout: TimeAmount,
        clientAddress: String
    ) {
        do {
            try client.pipeline.syncOperations.addHandler(
                IdleStateHandler(allTimeout: timeout),
                position: .first
            )
        } catch {
            log.error("tcp idle handler setup failed client=\(clientAddress) error=\(error)")
            upstream.close(promise: nil)
            client.close(promise: nil)
            return
        }
        activateReads(client: client, upstream: upstream, clientAddress: clientAddress)
        log.debug("tcp connected mode=userspace client=\(clientAddress) upstream=\(snapshot.upstreamAddress.curtsyDescription)")
    }

    private func write(_ buffer: ByteBuffer, to channel: Channel) -> Bool {
        let byteCount = buffer.readableBytes
        guard bufferBudget.tryAcquire(byteCount) else { return false }
        let promise = channel.eventLoop.makePromise(of: Void.self)
        promise.futureResult.whenComplete { [bufferBudget] _ in
            bufferBudget.release(byteCount)
        }
        channel.write(buffer, promise: promise)
        return true
    }

    private func activateReads(client: Channel, upstream: Channel, clientAddress: String) {
        client.setOption(.autoRead, value: true).and(
            upstream.setOption(.autoRead, value: true)
        ).whenFailure { [log] error in
            log.error("tcp read activation failed client=\(clientAddress) error=\(error)")
            upstream.close(promise: nil)
            client.close(promise: nil)
        }
        client.read()
        upstream.read()
    }

    private func scheduleAcceleratedIdleCheck(client: Channel, upstream: Channel, timeoutSeconds: Int) {
        let timeoutNanoseconds = UInt64(timeoutSeconds) * 1_000_000_000
        scheduleAcceleratedIdleCheck(
            client: client,
            upstream: upstream,
            timeoutNanoseconds: timeoutNanoseconds,
            delayNanoseconds: timeoutNanoseconds
        )
    }

    private func scheduleAcceleratedIdleCheck(
        client: Channel,
        upstream: Channel,
        timeoutNanoseconds: UInt64,
        delayNanoseconds: UInt64
    ) {
        let boundedDelay = Int64(min(delayNanoseconds, UInt64(Int64.max)))
        idleCheck = client.eventLoop.scheduleTask(in: .nanoseconds(max(1_000_000, boundedDelay))) { [weak self] in
            guard let self, let acceleration = self.acceleration else { return }
            do {
                let remaining = try acceleration.idleRemaining(timeoutNanoseconds: timeoutNanoseconds)
                if remaining == 0 {
                    self.log.debug("tcp sockmap connection closed after idle timeout")
                    acceleration.close()
                    upstream.close(promise: nil)
                    client.close(promise: nil)
                } else {
                    self.scheduleAcceleratedIdleCheck(
                        client: client,
                        upstream: upstream,
                        timeoutNanoseconds: timeoutNanoseconds,
                        delayNanoseconds: remaining
                    )
                }
            } catch {
                self.log.warning("tcp sockmap activity lookup failed; closing connection error=\(error)")
                acceleration.close()
                upstream.close(promise: nil)
                client.close(promise: nil)
            }
        }
    }
}

private final class TCPRelayHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    private let peer: Channel
    private let log: LogStore
    private let bufferBudget: TCPBufferBudget
    var acceleration: TCPSockmapConnection?
    private var bytes: Int64 = 0
    private var bufferLimitExceeded = false

    init(peer: Channel, log: LogStore, bufferBudget: TCPBufferBudget) {
        self.peer = peer
        self.log = log
        self.bufferBudget = bufferBudget
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !bufferLimitExceeded else { return }
        let buffer = unwrapInboundIn(data)
        bytes += Int64(buffer.readableBytes)
        let byteCount = buffer.readableBytes
        guard bufferBudget.tryAcquire(byteCount) else {
            bufferLimitExceeded = true
            log.warning("tcp buffer budget exhausted limit=\(bufferBudget.limit)")
            peer.close(promise: nil)
            context.close(promise: nil)
            return
        }
        let promise = peer.eventLoop.makePromise(of: Void.self)
        promise.futureResult.whenComplete { [bufferBudget] _ in
            bufferBudget.release(byteCount)
        }
        peer.write(buffer, promise: promise)
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        peer.flush()
        context.fireChannelReadComplete()
    }

    func channelWritabilityChanged(context: ChannelHandlerContext) {
        peer.setOption(.autoRead, value: context.channel.isWritable).whenFailure { error in
            self.log.error("tcp backpressure update failed error=\(error)")
        }
        context.fireChannelWritabilityChanged()
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let channelEvent = event as? ChannelEvent, channelEvent == .inputClosed {
            peer.close(mode: .output, promise: nil)
            return
        }
        if event is IdleStateHandler.IdleStateEvent {
            log.debug("tcp connection closed after idle timeout")
            peer.close(promise: nil)
            context.close(promise: nil)
            return
        }
        context.fireUserInboundEventTriggered(event)
    }

    func channelInactive(context: ChannelHandlerContext) {
        acceleration?.close()
        peer.close(promise: nil)
        log.debug("tcp relay direction closed bytes=\(bytes)")
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        acceleration?.close()
        log.error("tcp channel error error=\(error)")
        peer.close(promise: nil)
        context.close(promise: nil)
    }
}
