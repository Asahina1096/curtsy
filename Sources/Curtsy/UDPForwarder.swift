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
        let resolved = runtime.current()
        var bound: [Channel] = []
        var installedHandlers: [UDPRelayHandler] = []

        do {
            for listenAddress in resolved.listenAddresses {
                let handler = UDPRelayHandler(runtime: runtime, budget: associationBudget, log: log)
                var bootstrap = DatagramBootstrap(group: group)
                    .channelOption(.socketOption(.so_reuseaddr), value: 1)
                    .channelInitializer { channel in
                        channel.pipeline.addHandler(handler)
                    }
                if case .v6 = listenAddress {
                    bootstrap = bootstrap.channelOption(
                        ChannelOptions.Types.SocketOption(level: .ipv6, name: .ipv6_v6only),
                        value: 1
                    )
                }

                let channel = try bootstrap.bind(to: listenAddress).wait()
                bound.append(channel)
                installedHandlers.append(handler)
                log.info("udp listening on \(channel.localAddress?.curtsyDescription ?? listenAddress.curtsyDescription)")
            }
            listenerChannels = bound
            handlers = installedHandlers
        } catch {
            for channel in bound { try? channel.close().wait() }
            throw error
        }
    }

    func update(configuration: ResolvedConfiguration, resetAssociations: Bool) {
        let timeoutChanged = runtime.current().configuration.timeouts.udpSessionSeconds
            != configuration.configuration.timeouts.udpSessionSeconds
        runtime.update(configuration)
        guard resetAssociations || timeoutChanged else { return }
        let pairs = Array(zip(listenerChannels, handlers))
        for (channel, handler) in pairs {
            let promise = channel.eventLoop.makePromise(of: Void.self)
            channel.eventLoop.execute {
                if resetAssociations {
                    handler.resetAssociations()
                } else {
                    handler.rescheduleAssociationExpiries(on: channel.eventLoop)
                }
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
    LogStore,
    @escaping @Sendable () -> Void
) -> EventLoopFuture<Channel>

final class UDPRelayHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>

    private struct ActiveAssociation {
        let identifier: UInt64
        let channel: Channel
        var lastActivity: NIODeadline
        var expiry: Scheduled<Void>
    }

    private struct PendingAssociation {
        let generation: UInt64
        let identifier: UInt64
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
    private var nextAssociationIdentifier: UInt64 = 0

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

        if let association = active[client] {
            refreshAssociation(
                client: client,
                identifier: association.identifier,
                on: context.eventLoop
            )
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
        nextAssociationIdentifier &+= 1
        let associationIdentifier = nextAssociationIdentifier
        pending[client] = PendingAssociation(
            generation: pendingGeneration,
            identifier: associationIdentifier,
            buffers: [envelope.data]
        )
        let eventLoop = context.eventLoop
        let recordUpstreamActivity: @Sendable () -> Void = { [weak self] in
            guard let self else { return }
            if eventLoop.inEventLoop {
                refreshAssociation(
                    client: client,
                    identifier: associationIdentifier,
                    on: eventLoop
                )
                return
            }
            eventLoop.execute { [self] in
                refreshAssociation(
                    client: client,
                    identifier: associationIdentifier,
                    on: eventLoop
                )
            }
        }
        connectUpstream(
            eventLoop,
            snapshot.upstreamAddress,
            context.channel,
            client,
            log,
            recordUpstreamActivity
        ).whenComplete { [weak self] result in
            guard let self else {
                if case .success(let channel) = result {
                    channel.close(promise: nil)
                }
                return
            }
            guard
                self.generation == pendingGeneration,
                self.pending[client]?.generation == pendingGeneration,
                self.pending[client]?.identifier == associationIdentifier
            else {
                if case .success(let channel) = result {
                    channel.close(promise: nil)
                }
                return
            }

            let pendingAssociation = self.pending.removeValue(forKey: client)
            let buffers = pendingAssociation?.buffers ?? []
            switch result {
            case .success(let channel):
                let lastActivity = eventLoop.now
                let deadline = self.expirationDeadline(lastActivity: lastActivity)
                let expiry = self.scheduleExpiry(
                    client: client,
                    identifier: associationIdentifier,
                    deadline: deadline,
                    on: eventLoop
                )
                self.active[client] = ActiveAssociation(
                    identifier: associationIdentifier,
                    channel: channel,
                    lastActivity: lastActivity,
                    expiry: expiry
                )
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

    func rescheduleAssociationExpiries(on eventLoop: EventLoop) {
        eventLoop.assertInEventLoop()
        let now = eventLoop.now
        for client in Array(active.keys) {
            guard var association = active[client] else { continue }
            association.expiry.cancel()
            let deadline = expirationDeadline(lastActivity: association.lastActivity)
            if deadline <= now {
                expireAssociation(client: client, identifier: association.identifier)
                continue
            }
            association.expiry = scheduleExpiry(
                client: client,
                identifier: association.identifier,
                deadline: deadline,
                on: eventLoop
            )
            active[client] = association
        }
    }

    private func scheduleExpiry(
        client: SocketAddress,
        identifier: UInt64,
        deadline: NIODeadline,
        on eventLoop: EventLoop
    ) -> Scheduled<Void> {
        return eventLoop.scheduleTask(deadline: deadline) { [weak self] in
            self?.expireAssociation(client: client, identifier: identifier)
        }
    }

    private func expirationDeadline(lastActivity: NIODeadline) -> NIODeadline {
        let seconds = runtime.current().configuration.timeouts.udpSessionSeconds
        return lastActivity + .seconds(Int64(seconds))
    }

    private func expireAssociation(client: SocketAddress, identifier: UInt64) {
        guard
            active[client]?.identifier == identifier,
            let association = active.removeValue(forKey: client)
        else { return }
        association.channel.close(promise: nil)
        budget.release()
        warnedAtLimit = false
        log.debug("udp association expired client=\(client.curtsyDescription)")
    }

    private func refreshAssociation(client: SocketAddress, identifier: UInt64, on eventLoop: EventLoop) {
        guard var association = active[client], association.identifier == identifier else { return }
        association.expiry.cancel()
        association.lastActivity = eventLoop.now
        let deadline = expirationDeadline(lastActivity: association.lastActivity)
        association.expiry = scheduleExpiry(
            client: client,
            identifier: identifier,
            deadline: deadline,
            on: eventLoop
        )
        active[client] = association
    }

    private static func makeUpstreamConnection(
        eventLoop: EventLoop,
        upstreamAddress: SocketAddress,
        listener: Channel,
        clientAddress: SocketAddress,
        log: LogStore,
        recordActivity: @escaping @Sendable () -> Void
    ) -> EventLoopFuture<Channel> {
        let upstreamHandler = UDPUpstreamHandler(
            listener: listener,
            clientAddress: clientAddress,
            log: log,
            recordActivity: recordActivity
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
    private let recordActivity: @Sendable () -> Void

    init(
        listener: Channel,
        clientAddress: SocketAddress,
        log: LogStore,
        recordActivity: @escaping @Sendable () -> Void
    ) {
        self.listener = listener
        self.clientAddress = clientAddress
        self.log = log
        self.recordActivity = recordActivity
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let upstreamEnvelope = unwrapInboundIn(data)
        recordActivity()
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
