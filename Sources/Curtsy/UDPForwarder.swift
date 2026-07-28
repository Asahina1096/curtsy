import NIOConcurrencyHelpers
import NIOCore
import NIOPosix

final class UDPAssociationBudget: @unchecked Sendable {
    private let used = NIOLockedValueBox(0)

    func tryAcquire(limit: Int) -> Bool {
        used.withLockedValue { used in
            guard used < limit else { return false }
            used += 1
            return true
        }
    }

    func release(_ count: Int = 1) {
        guard count > 0 else { return }
        used.withLockedValue { used in
            used -= count
            precondition(used >= 0, "UDP association budget released more than acquired")
        }
    }

    var count: Int { used.withLockedValue { $0 } }
}

final class UDPListener: @unchecked Sendable {
    private let group: EventLoopGroup
    private let runtime: RuntimeConfiguration
    private let log: LogStore
    private let associationBudget = UDPAssociationBudget()
    private var listenerChannels: [Channel] = []
    private var handlers: [UDPRelayHandler] = []

    init(group: EventLoopGroup, configuration: ResolvedConfiguration, log: LogStore) {
        self.group = group
        runtime = RuntimeConfiguration(configuration)
        self.log = log
    }

    func start() throws {
        let configuration = runtime.current().configuration
        let hosts = configuration.listen.host == "*" ? ["0.0.0.0", "::"] : [configuration.listen.host]
        var bound: [Channel] = []
        var installedHandlers: [UDPRelayHandler] = []

        do {
            for host in hosts {
                let handler = UDPRelayHandler(runtime: runtime, budget: associationBudget, log: log)
                var bootstrap = DatagramBootstrap(group: group)
                    .channelOption(.socketOption(.so_reuseaddr), value: 1)
                    .channelInitializer { channel in
                        channel.pipeline.addHandler(handler)
                    }
                if host == "::" {
                    bootstrap = bootstrap.channelOption(
                        ChannelOptions.Types.SocketOption(level: .ipv6, name: .ipv6_v6only),
                        value: 1
                    )
                }

                let channel = try bootstrap.bind(host: host, port: configuration.listen.port).wait()
                bound.append(channel)
                installedHandlers.append(handler)
                log.info("udp listening on \(channel.localAddress?.curtsyDescription ?? host)")
            }
            listenerChannels = bound
            handlers = installedHandlers
        } catch {
            for channel in bound { try? channel.close().wait() }
            throw error
        }
    }

    func update(configuration: ResolvedConfiguration, resetAssociations: Bool) {
        runtime.update(configuration)
        guard resetAssociations else { return }
        let pairs = Array(zip(listenerChannels, handlers))
        for (channel, handler) in pairs {
            let promise = channel.eventLoop.makePromise(of: Void.self)
            channel.eventLoop.execute {
                handler.resetAssociations()
                promise.succeed(())
            }
            try? promise.futureResult.wait()
        }
    }

    var localAddresses: [SocketAddress] {
        listenerChannels.compactMap(\.localAddress)
    }

    var associationCount: Int { associationBudget.count }

    func stop() {
        let pairs = Array(zip(listenerChannels, handlers))
        listenerChannels.removeAll()
        handlers.removeAll()
        for (channel, handler) in pairs {
            channel.eventLoop.execute { handler.resetAssociations() }
            try? channel.close().wait()
        }
    }
}

typealias UDPUpstreamConnector = (
    EventLoop,
    SocketAddress,
    Channel,
    SocketAddress,
    LogStore
) -> EventLoopFuture<Channel>

final class UDPRelayHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>

    private struct ActiveAssociation {
        let channel: Channel
        var expiry: Scheduled<Void>
    }

    private struct PendingAssociation {
        let generation: UInt64
        var buffers: [ByteBuffer]
    }

    private let runtime: RuntimeConfiguration
    private let budget: UDPAssociationBudget
    private let log: LogStore
    private let connectUpstream: UDPUpstreamConnector
    private var active: [SocketAddress: ActiveAssociation] = [:]
    private var pending: [SocketAddress: PendingAssociation] = [:]
    private weak var listenerChannel: Channel?
    private var warnedAtLimit = false
    private var generation: UInt64 = 0

    init(
        runtime: RuntimeConfiguration,
        budget: UDPAssociationBudget,
        log: LogStore,
        connectUpstream: @escaping UDPUpstreamConnector = UDPRelayHandler.makeUpstreamConnection
    ) {
        self.runtime = runtime
        self.budget = budget
        self.log = log
        self.connectUpstream = connectUpstream
    }

    func handlerAdded(context: ChannelHandlerContext) {
        listenerChannel = context.channel
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = unwrapInboundIn(data)
        let client = envelope.remoteAddress

        if var association = active[client] {
            association.expiry.cancel()
            association.expiry = scheduleExpiry(client: client, on: context.eventLoop)
            active[client] = association
            association.channel.writeAndFlush(envelope.data).whenFailure { [log] error in
                log.error("udp upstream write failed client=\(client.curtsyDescription) error=\(error)")
            }
            return
        }

        if var association = pending[client] {
            association.buffers.append(envelope.data)
            pending[client] = association
            return
        }

        let snapshot = runtime.current()
        guard budget.tryAcquire(limit: snapshot.configuration.limits.maxUDPAssociations) else {
            if !warnedAtLimit {
                warnedAtLimit = true
                log.warning("udp association limit reached limit=\(snapshot.configuration.limits.maxUDPAssociations)")
            }
            return
        }

        let pendingGeneration = generation
        pending[client] = PendingAssociation(generation: pendingGeneration, buffers: [envelope.data])
        let eventLoop = context.eventLoop
        connectUpstream(eventLoop, snapshot.upstreamAddress, context.channel, client, log).whenComplete { [weak self] result in
            guard let self else {
                if case .success(let channel) = result {
                    channel.close(promise: nil)
                }
                return
            }
            guard
                self.generation == pendingGeneration,
                self.pending[client]?.generation == pendingGeneration
            else {
                if case .success(let channel) = result {
                    channel.close(promise: nil)
                }
                return
            }

            let buffers = self.pending.removeValue(forKey: client)?.buffers ?? []
            switch result {
            case .success(let channel):
                let expiry = self.scheduleExpiry(client: client, on: eventLoop)
                self.active[client] = ActiveAssociation(channel: channel, expiry: expiry)
                self.warnedAtLimit = false
                channel.closeFuture.whenComplete { [weak self, weak channel] _ in
                    guard let self, let channel else { return }
                    eventLoop.execute {
                        if self.active[client]?.channel === channel {
                            self.active.removeValue(forKey: client)?.expiry.cancel()
                            self.budget.release()
                            self.warnedAtLimit = false
                        }
                    }
                }
                for buffer in buffers {
                    channel.writeAndFlush(buffer).whenFailure { [log = self.log] error in
                        log.error("udp upstream write failed client=\(client.curtsyDescription) error=\(error)")
                    }
                }
                self.log.debug("udp association opened client=\(client.curtsyDescription) upstream=\(snapshot.upstreamAddress.curtsyDescription)")
            case .failure(let error):
                self.budget.release()
                self.warnedAtLimit = false
                self.log.error("udp association failed client=\(client.curtsyDescription) error=\(error)")
            }
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        resetAssociations()
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        log.error("udp listener error error=\(error)")
    }

    func resetAssociations() {
        generation &+= 1
        let releasedCount = active.count + pending.count
        for association in active.values {
            association.expiry.cancel()
            association.channel.close(promise: nil)
        }
        active.removeAll()
        pending.removeAll()
        budget.release(releasedCount)
        warnedAtLimit = false
    }

    private func scheduleExpiry(client: SocketAddress, on eventLoop: EventLoop) -> Scheduled<Void> {
        let seconds = runtime.current().configuration.timeouts.udpSessionSeconds
        return eventLoop.scheduleTask(in: .seconds(Int64(seconds))) { [weak self] in
            guard let self, let association = self.active.removeValue(forKey: client) else { return }
            association.channel.close(promise: nil)
            self.budget.release()
            self.warnedAtLimit = false
            self.log.debug("udp association expired client=\(client.curtsyDescription)")
        }
    }

    private static func makeUpstreamConnection(
        eventLoop: EventLoop,
        upstreamAddress: SocketAddress,
        listener: Channel,
        clientAddress: SocketAddress,
        log: LogStore
    ) -> EventLoopFuture<Channel> {
        let upstreamHandler = UDPUpstreamHandler(
            listener: listener,
            clientAddress: clientAddress,
            log: log
        )
        let bootstrap = DatagramBootstrap(group: eventLoop)
            .channelOption(.autoRead, value: false)
            .channelInitializer { channel in
                channel.pipeline.addHandler(upstreamHandler)
            }

        return bootstrap.connect(to: upstreamAddress).flatMap { channel in
            channel.setOption(.autoRead, value: true).map { channel }
        }
    }
}

private final class UDPUpstreamHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>

    private let listener: Channel
    private let clientAddress: SocketAddress
    private let log: LogStore

    init(listener: Channel, clientAddress: SocketAddress, log: LogStore) {
        self.listener = listener
        self.clientAddress = clientAddress
        self.log = log
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let upstreamEnvelope = unwrapInboundIn(data)
        let response = AddressedEnvelope(remoteAddress: clientAddress, data: upstreamEnvelope.data)
        listener.writeAndFlush(response).whenFailure { [log] error in
            log.error("udp client write failed client=\(self.clientAddress.curtsyDescription) error=\(error)")
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        log.error("udp upstream error client=\(clientAddress.curtsyDescription) error=\(error)")
        context.close(promise: nil)
    }
}
