import CBPFSupport
import Foundation
import Glibc
import NIOConcurrencyHelpers
import NIOCore

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
    private let runtime: RuntimeConfiguration
    private let log: LogStore
    private let enableSockmapAccelerationOverride: Bool?
    private let loadSockmapAccelerator: (Int) throws -> UDPSockmapAccelerator
    // Shared across all engine threads so the configured association limit
    // stays a global bound rather than a per-thread one.
    private let budget = UDPAssociationBudget()
    private var engines: [(runtime: RuntimeConfiguration, engine: UDPRelayEngine)] = []

    init(
        group: EventLoopGroup,
        configuration: ResolvedConfiguration,
        log: LogStore,
        enableSockmapAcceleration: Bool? = nil,
        loadSockmapAccelerator: @escaping (Int) throws -> UDPSockmapAccelerator = { maxEntries in
            try UDPSockmapAccelerator.load(maxEntries: maxEntries)
        }
    ) {
        // The batched transport runs its own I/O threads instead of event loop
        // channels; the group parameter only keeps call sites unchanged.
        _ = group
        runtime = RuntimeConfiguration(configuration)
        self.log = log
        enableSockmapAccelerationOverride = enableSockmapAcceleration
        self.loadSockmapAccelerator = loadSockmapAccelerator
    }

    func start() throws {
        let snapshot = runtime.current()
        let threadCount = AutoTune.workerThreads(configured: snapshot.configuration.performance.udpIOThreads)
        // The first engine binds the configured addresses; the rest bind the
        // addresses it actually got (relevant when the configured port is 0),
        // sharing each port through SO_REUSEPORT.
        try startEngine(runtime: runtime, engineCount: threadCount, announceListen: true)
        let boundAddresses = engines[0].engine.localAddresses
        for _ in 1..<threadCount {
            let resolved = ResolvedConfiguration(
                configuration: snapshot.configuration,
                listenAddresses: boundAddresses,
                upstreamAddress: snapshot.upstreamAddress
            )
            try startEngine(
                runtime: RuntimeConfiguration(resolved),
                engineCount: threadCount,
                announceListen: false
            )
        }
        if threadCount > 1 {
            log.info("udp relay io_threads=\(threadCount)")
        }
    }

    private func startEngine(
        runtime: RuntimeConfiguration,
        engineCount: Int,
        announceListen: Bool
    ) throws {
        let engine = UDPRelayEngine(
            runtime: runtime,
            log: log,
            budget: budget,
            engineCount: engineCount,
            enableSockmapAcceleration: enableSockmapAccelerationOverride,
            loadSockmapAccelerator: loadSockmapAccelerator,
            announceListen: announceListen
        )
        do {
            try engine.start()
        } catch {
            for slot in engines { slot.engine.stop() }
            engines = []
            throw error
        }
        engines.append((runtime, engine))
    }

    func update(configuration: ResolvedConfiguration, resetAssociations: Bool) {
        // Timeout changes apply on each engine's next expiry sweep, which reads
        // the current snapshot; only upstream changes need association resets.
        runtime.update(configuration)
        for (index, slot) in engines.enumerated() {
            if index > 0 {
                // Keep the concrete addresses this engine bound at start; the
                // candidate may still carry the configured wildcard port 0.
                slot.runtime.update(
                    ResolvedConfiguration(
                        configuration: configuration.configuration,
                        listenAddresses: slot.engine.localAddresses,
                        upstreamAddress: configuration.upstreamAddress
                    )
                )
            }
            slot.engine.updateAccelerator()
            if resetAssociations {
                slot.engine.resetAssociations()
            }
        }
    }

    var localAddresses: [SocketAddress] { engines.first?.engine.localAddresses ?? [] }

    var associationCount: Int { budget.count }

    func stop() {
        for slot in engines { slot.engine.stop() }
        engines = []
    }
}

// Batched UDP relay: one I/O thread polls all listen and upstream sockets
// with epoll and moves datagrams with recvmmsg/sendmmsg batches. UDP connect
// is synchronous, so associations are established on the first datagram with
// no pending-buffer window.
final class UDPRelayEngine: @unchecked Sendable {
    private enum Command {
        case stop
        case resetAssociations
        case reloadAccelerator
    }

    private struct Association {
        let client: SocketAddress
        let clientAddress: sockaddr_storage
        let clientAddressLength: socklen_t
        let listenFD: Int32
        let upstreamFD: Int32
        // Connected per-client socket and its kernel pairing; present only
        // when this association is steered by the sockmap verdict program.
        let clientFD: Int32?
        let sockmap: UDPSockmapAssociation?
        var lastActivityMilliseconds: UInt64
    }

    private static let batchSize = 64
    private static let datagramCapacity = 65_536
    private static let sweepIntervalMilliseconds: Int32 = 50

    private let runtime: RuntimeConfiguration
    private let log: LogStore
    private let budget: UDPAssociationBudget
    // Number of engine threads sharing this listener; used to size the
    // per-engine sockmap so all maps together match the configured limit.
    private let engineCount: Int
    private let announceListen: Bool
    private let pendingCommands = NIOLockedValueBox<[Command]>([])
    private let enableSockmapAccelerationOverride: Bool?
    private let loadSockmapAccelerator: (Int) throws -> UDPSockmapAccelerator
    // running is set before the I/O thread starts and cleared in its defer
    // before teardown; the wake fd stays open until stop() joins the thread,
    // so a signal write can never land on a closed or reused descriptor.
    private let lifecycle = NIOLockedValueBox(false)
    private let finishSignal = DispatchSemaphore(value: 0)
    private let boundAddresses = NIOLockedValueBox<[SocketAddress]>([])

    // I/O-thread-confined state below; only touched from run() and its callees,
    // except the fds created in start() before the thread spawns.
    private var epollFD: Int32 = -1
    private var wakeFD: Int32 = -1
    private var listenFDs: [Int32] = []
    private var associations: [SocketAddress: Association] = [:]
    private var upstreamToClient: [Int32: SocketAddress] = [:]
    private var clientFDToClient: [Int32: SocketAddress] = [:]
    private var listenBoundAddresses: [Int32: sockaddr_storage] = [:]
    private var sockmapAccelerator: UDPSockmapAccelerator?
    private var warnedAtLimit = false

    init(
        runtime: RuntimeConfiguration,
        log: LogStore,
        budget: UDPAssociationBudget? = nil,
        engineCount: Int = 1,
        enableSockmapAcceleration: Bool? = nil,
        loadSockmapAccelerator: @escaping (Int) throws -> UDPSockmapAccelerator = { maxEntries in
            try UDPSockmapAccelerator.load(maxEntries: maxEntries)
        },
        announceListen: Bool = true
    ) {
        self.runtime = runtime
        self.log = log
        self.budget = budget ?? UDPAssociationBudget()
        self.engineCount = max(1, engineCount)
        self.announceListen = announceListen
        enableSockmapAccelerationOverride = enableSockmapAcceleration
        self.loadSockmapAccelerator = loadSockmapAccelerator
    }

    var localAddresses: [SocketAddress] { boundAddresses.withLockedValue { $0 } }

    var associationCount: Int { budget.count }

    func start() throws {
        let snapshot = runtime.current()
        var addresses: [SocketAddress] = []
        var createdFDs: [Int32] = []
        var boundStorages: [Int32: sockaddr_storage] = [:]
        var epollFD: Int32 = -1
        var wakeFD: Int32 = -1

        do {
            for listenAddress in snapshot.listenAddresses {
                let fd = try listenAddress.withSockAddr { pointer, length in
                    var bound = sockaddr_storage()
                    var boundLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
                    let fd = curtsy_udp_listen_socket(pointer, socklen_t(length), &bound, &boundLength)
                    guard fd >= 0 else {
                        throw IOError(errnoCode: errno, reason: "udp listen socket")
                    }
                    guard let boundAddress = Self.socketAddress(from: bound) else {
                        Glibc.close(fd)
                        throw IOError(errnoCode: EAFNOSUPPORT, reason: "udp listen address family")
                    }
                    boundStorages[fd] = bound
                    addresses.append(boundAddress)
                    return fd
                }
                createdFDs.append(fd)
                applySocketBuffers(to: fd, context: "listen=\(listenAddress.curtsyDescription)", warnOnFailure: true)
                if announceListen {
                    log.info("udp listening on \(addresses.last?.curtsyDescription ?? listenAddress.curtsyDescription)")
                }
            }

            epollFD = curtsy_epoll_create()
            guard epollFD >= 0 else {
                throw IOError(errnoCode: errno, reason: "epoll_create1")
            }
            wakeFD = curtsy_eventfd_create()
            guard wakeFD >= 0 else {
                throw IOError(errnoCode: errno, reason: "eventfd")
            }
            guard curtsy_epoll_add(epollFD, wakeFD) == 0 else {
                throw IOError(errnoCode: errno, reason: "epoll add wake fd")
            }
            for fd in createdFDs {
                guard curtsy_epoll_add(epollFD, fd) == 0 else {
                    throw IOError(errnoCode: errno, reason: "epoll add listen socket")
                }
            }
        } catch {
            for fd in createdFDs { Glibc.close(fd) }
            if epollFD >= 0 { Glibc.close(epollFD) }
            if wakeFD >= 0 { Glibc.close(wakeFD) }
            throw error
        }

        self.epollFD = epollFD
        self.wakeFD = wakeFD
        listenFDs = createdFDs
        listenBoundAddresses = boundStorages
        boundAddresses.withLockedValue { $0 = addresses }

        let shouldEnableSockmap = enableSockmapAccelerationOverride ?? snapshot.shouldEnableUDPSockmap
        if shouldEnableSockmap {
            do {
                sockmapAccelerator = try loadSockmapAccelerator(sockmapMaxEntries(for: snapshot))
                log.info("udp sockmap acceleration enabled")
            } catch {
                log.warning("udp sockmap acceleration unavailable; using userspace relay error=\(error)")
            }
        } else {
            log.info("udp sockmap acceleration disabled")
        }

        lifecycle.withLockedValue { $0 = true }

        let thread = Thread { [weak self] in self?.run() }
        thread.name = "curtsy-udp-io"
        thread.start()
    }

    func resetAssociations() {
        enqueue(.resetAssociations)
    }

    func updateAccelerator() {
        enqueue(.reloadAccelerator)
    }

    func stop() {
        let wasRunning = lifecycle.withLockedValue { running -> Bool in
            defer { running = false }
            return running
        }
        guard wasRunning else { return }
        enqueue(.stop)
        finishSignal.wait()
        boundAddresses.withLockedValue { $0 = [] }
    }

    private func enqueue(_ command: Command) {
        pendingCommands.withLockedValue { $0.append(command) }
        let running = lifecycle.withLockedValue { $0 }
        if running, wakeFD >= 0 {
            curtsy_eventfd_signal(wakeFD)
        }
    }

    private func run() {
        defer {
            lifecycle.withLockedValue { $0 = false }
            teardown()
            finishSignal.signal()
        }

        let bufferBase = UnsafeMutablePointer<UInt8>.allocate(
            capacity: Self.batchSize * Self.datagramCapacity
        )
        defer { bufferBase.deallocate() }
        var recvSlots = [curtsy_udp_slot](repeating: curtsy_udp_slot(), count: Self.batchSize)
        for index in 0..<Self.batchSize {
            recvSlots[index].data = bufferBase.advanced(by: index * Self.datagramCapacity)
            recvSlots[index].capacity = UInt32(Self.datagramCapacity)
        }
        var sendSlots = [curtsy_udp_slot](repeating: curtsy_udp_slot(), count: Self.batchSize)
        var readyFDs = [Int32](repeating: -1, count: Self.batchSize + 1)

        while true {
            let ready = readyFDs.withUnsafeMutableBufferPointer { buffer in
                curtsy_epoll_wait(
                    epollFD,
                    buffer.baseAddress,
                    UInt32(buffer.count),
                    Self.sweepIntervalMilliseconds
                )
            }
            if ready < 0 {
                log.error("udp event wait failed error=\(Self.errnoDescription())")
            }

            let commands = pendingCommands.withLockedValue { pending -> [Command] in
                let drained = pending
                pending = []
                return drained
            }
            for command in commands {
                switch command {
                case .stop:
                    return
                case .resetAssociations:
                    closeAllAssociations()
                case .reloadAccelerator:
                    reloadAccelerator()
                }
            }

            if ready > 0 {
                for fd in readyFDs.prefix(Int(ready)) {
                    if fd == wakeFD {
                        curtsy_eventfd_drain(wakeFD)
                    } else if clientFDToClient[fd] != nil {
                        drainClient(fd: fd, slots: &recvSlots)
                    } else if upstreamToClient[fd] != nil {
                        drainUpstream(fd: fd, slots: &recvSlots)
                    } else {
                        drainListen(fd: fd, slots: &recvSlots, sendSlots: &sendSlots)
                    }
                }
            }
            sweepExpiredAssociations()
        }
    }

    private func teardown() {
        closeAllAssociations()
        for fd in listenFDs { Glibc.close(fd) }
        listenFDs = []
        listenBoundAddresses = [:]
        if epollFD >= 0 { Glibc.close(epollFD) }
        if wakeFD >= 0 { Glibc.close(wakeFD) }
        epollFD = -1
        wakeFD = -1
        sockmapAccelerator = nil
    }

    private func sockmapMaxEntries(for snapshot: ResolvedConfiguration) -> Int {
        let associations = snapshot.configuration.limits.maxUDPAssociations / engineCount
        guard associations <= Int(UInt32.max / 2) else {
            return Int(UInt32.max)
        }
        return max(1024, associations * 2)
    }

    // Oversized requests are silently clamped to the kernel rmem/wmem maxima,
    // so only genuine failures (not clamping) surface here.
    private func applySocketBuffers(to fd: Int32, context: String, warnOnFailure: Bool) {
        let bytes = runtime.current().configuration.performance.udpSocketBufferBytes
        guard bytes > 0 else { return }
        guard curtsy_udp_set_socket_buffers(fd, Int32(bytes)) == 0 else {
            let message = "udp socket buffer setup failed \(context) bytes=\(bytes) error=\(Self.errnoDescription())"
            if warnOnFailure {
                log.warning(message)
            } else {
                log.debug(message)
            }
            return
        }
    }

    private func reloadAccelerator() {
        let snapshot = runtime.current()
        let requested = enableSockmapAccelerationOverride ?? snapshot.shouldEnableUDPSockmap
        if requested, sockmapAccelerator == nil {
            do {
                sockmapAccelerator = try loadSockmapAccelerator(sockmapMaxEntries(for: snapshot))
                log.info("udp sockmap acceleration enabled")
                // Only newly established associations are steered.
                closeAllAssociations()
            } catch {
                log.warning("udp sockmap acceleration unavailable; using userspace relay error=\(error)")
            }
        } else if !requested, sockmapAccelerator != nil {
            log.info("udp sockmap acceleration disabled")
            // Close first so existing sessions fall back to the userspace
            // relay before the runtime is destroyed.
            closeAllAssociations()
            sockmapAccelerator = nil
        }
    }

    private func drainListen(
        fd: Int32,
        slots: inout [curtsy_udp_slot],
        sendSlots: inout [curtsy_udp_slot]
    ) {
        slots.withUnsafeMutableBufferPointer { slotBuffer in
            sendSlots.withUnsafeMutableBufferPointer { sendBuffer in
                while true {
                    let received = curtsy_udp_recv_batch(
                        fd,
                        slotBuffer.baseAddress,
                        UInt32(Self.batchSize)
                    )
                    if received == 0 { return }
                    if received < 0 {
                        log.error("udp listener read failed error=\(Self.errnoDescription())")
                        return
                    }
                    forwardClientDatagrams(
                        count: Int(received),
                        listenFD: fd,
                        slots: slotBuffer,
                        sendSlots: sendBuffer
                    )
                }
            }
        }
    }

    private func forwardClientDatagrams(
        count: Int,
        listenFD: Int32,
        slots: UnsafeMutableBufferPointer<curtsy_udp_slot>,
        sendSlots: UnsafeMutableBufferPointer<curtsy_udp_slot>
    ) {
        guard let slotBase = slots.baseAddress, let sendBase = sendSlots.baseAddress else { return }
        var runFD: Int32 = -1
        var runLength = 0
        for index in 0..<count {
            let slot = slotBase[index]
            guard let client = Self.socketAddress(from: slot.address) else { continue }
            let association = associations[client]
                ?? openAssociation(
                    client: client,
                    clientAddress: slot.address,
                    clientAddressLength: slot.address_length,
                    listenFD: listenFD
                )
            guard let association else { continue }
            associations[client]?.lastActivityMilliseconds = Self.monotonicMilliseconds()
            if association.upstreamFD != runFD {
                if runLength > 0 {
                    sendAllDatagrams(
                        fd: runFD,
                        address: nil,
                        addressLength: 0,
                        slots: sendBase,
                        count: runLength,
                        context: "direction=client_to_upstream"
                    )
                }
                runFD = association.upstreamFD
                runLength = 0
            }
            sendBase[runLength].data = slot.data
            sendBase[runLength].length = slot.length
            runLength += 1
        }
        if runLength > 0 {
            sendAllDatagrams(
                fd: runFD,
                address: nil,
                addressLength: 0,
                slots: sendBase,
                count: runLength,
                context: "direction=client_to_upstream"
            )
        }
    }

    // Fallback path for an accelerated association: datagrams queued on the
    // connected client socket before pairing completed (or passed through via
    // SK_PASS) are relayed by userspace like ordinary listen-socket traffic.
    private func drainClient(fd: Int32, slots: inout [curtsy_udp_slot]) {
        guard
            let client = clientFDToClient[fd],
            let association = associations[client]
        else { return }
        slots.withUnsafeMutableBufferPointer { slotBuffer in
            while true {
                let received = curtsy_udp_recv_batch(
                    fd,
                    slotBuffer.baseAddress,
                    UInt32(Self.batchSize)
                )
                if received == 0 { return }
                if received < 0 {
                    log.error(
                        "udp client socket read failed client=\(client.curtsyDescription) "
                            + "error=\(Self.errnoDescription())"
                    )
                    closeAssociation(client: client)
                    return
                }
                associations[client]?.lastActivityMilliseconds = Self.monotonicMilliseconds()
                if let baseAddress = slotBuffer.baseAddress {
                    sendAllDatagrams(
                        fd: association.upstreamFD,
                        address: nil,
                        addressLength: 0,
                        slots: baseAddress,
                        count: Int(received),
                        context: "direction=client_to_upstream client=\(client.curtsyDescription)"
                    )
                }
            }
        }
    }

    private func drainUpstream(fd: Int32, slots: inout [curtsy_udp_slot]) {
        guard
            let client = upstreamToClient[fd],
            let association = associations[client]
        else { return }
        slots.withUnsafeMutableBufferPointer { slotBuffer in
            while true {
                let received = curtsy_udp_recv_batch(
                    fd,
                    slotBuffer.baseAddress,
                    UInt32(Self.batchSize)
                )
                if received == 0 { return }
                if received < 0 {
                    log.error(
                        "udp upstream error client=\(client.curtsyDescription) "
                            + "error=\(Self.errnoDescription())"
                    )
                    closeAssociation(client: client)
                    return
                }
                associations[client]?.lastActivityMilliseconds = Self.monotonicMilliseconds()
                var clientAddress = association.clientAddress
                withUnsafePointer(to: &clientAddress) { storagePointer in
                    storagePointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { address in
                        if let baseAddress = slotBuffer.baseAddress {
                            sendAllDatagrams(
                                fd: association.listenFD,
                                address: address,
                                addressLength: association.clientAddressLength,
                                slots: baseAddress,
                                count: Int(received),
                                context: "direction=upstream_to_client client=\(client.curtsyDescription)"
                            )
                        }
                    }
                }
            }
        }
    }

    @discardableResult
    private func sendAllDatagrams(
        fd: Int32,
        address: UnsafePointer<sockaddr>?,
        addressLength: socklen_t,
        slots: UnsafePointer<curtsy_udp_slot>,
        count: Int,
        context: String
    ) -> Bool {
        guard count > 0 else { return true }
        var sentTotal = 0
        while sentTotal < count {
            let sent = curtsy_udp_send_batch(
                fd,
                address,
                addressLength,
                slots.advanced(by: sentTotal),
                UInt32(count - sentTotal)
            )
            if sent > 0 {
                sentTotal += Int(sent)
                continue
            }

            let errorDescription = sent < 0 ? Self.errnoDescription() : "sendmmsg made no progress"
            log.warning(
                "udp datagrams dropped \(context) sent=\(sentTotal) "
                    + "dropped=\(count - sentTotal) error=\(errorDescription)"
            )
            return false
        }
        return true
    }

    private func openAssociation(
        client: SocketAddress,
        clientAddress: sockaddr_storage,
        clientAddressLength: socklen_t,
        listenFD: Int32
    ) -> Association? {
        let snapshot = runtime.current()
        guard budget.tryAcquire(limit: snapshot.configuration.limits.maxUDPAssociations) else {
            if !warnedAtLimit {
                warnedAtLimit = true
                log.warning("udp association limit reached limit=\(snapshot.configuration.limits.maxUDPAssociations)")
            }
            return nil
        }
        do {
            let upstreamFD = try snapshot.upstreamAddress.withSockAddr { pointer, length in
                let fd = curtsy_udp_upstream_socket(pointer, socklen_t(length))
                guard fd >= 0 else {
                    throw IOError(errnoCode: errno, reason: "udp upstream socket")
                }
                return fd
            }
            guard curtsy_epoll_add(epollFD, upstreamFD) == 0 else {
                let errorNumber = errno
                Glibc.close(upstreamFD)
                throw IOError(errnoCode: errorNumber, reason: "epoll add upstream socket")
            }
            applySocketBuffers(
                to: upstreamFD,
                context: "direction=upstream client=\(client.curtsyDescription)",
                warnOnFailure: false
            )
            var clientFD: Int32? = nil
            var pairing: UDPSockmapAssociation? = nil
            if let accelerator = sockmapAccelerator, let bindStorage = listenBoundAddresses[listenFD] {
                do {
                    (clientFD, pairing) = try accelerateAssociation(
                        accelerator: accelerator,
                        bindStorage: bindStorage,
                        clientAddress: clientAddress,
                        clientAddressLength: clientAddressLength,
                        upstreamFD: upstreamFD
                    )
                } catch {
                    // Kernel steering is best-effort per association; fall
                    // back to the userspace relay for this client.
                    log.debug(
                        "udp sockmap pairing failed client=\(client.curtsyDescription) error=\(error)"
                    )
                }
            }
            let association = Association(
                client: client,
                clientAddress: clientAddress,
                clientAddressLength: clientAddressLength,
                listenFD: listenFD,
                upstreamFD: upstreamFD,
                clientFD: clientFD,
                sockmap: pairing,
                lastActivityMilliseconds: Self.monotonicMilliseconds()
            )
            associations[client] = association
            upstreamToClient[upstreamFD] = client
            if let clientFD {
                clientFDToClient[clientFD] = client
            }
            warnedAtLimit = false
            log.debug(
                "udp association opened client=\(client.curtsyDescription) "
                    + "upstream=\(snapshot.upstreamAddress.curtsyDescription)"
            )
            return association
        } catch {
            budget.release()
            log.error("udp association failed client=\(client.curtsyDescription) error=\(error)")
            return nil
        }
    }

    // Creates the connected per-client socket and pairs it with the upstream
    // socket in the sockmap. Once bound, the kernel demux prefers this
    // four-tuple socket over the wildcard listener, so subsequent datagrams
    // from the client are steered by the verdict program.
    private func accelerateAssociation(
        accelerator: UDPSockmapAccelerator,
        bindStorage: sockaddr_storage,
        clientAddress: sockaddr_storage,
        clientAddressLength: socklen_t,
        upstreamFD: Int32
    ) throws -> (Int32, UDPSockmapAssociation) {
        let bindLength: socklen_t
        switch Int32(bindStorage.ss_family) {
        case AF_INET:
            bindLength = socklen_t(MemoryLayout<sockaddr_in>.size)
        case AF_INET6:
            bindLength = socklen_t(MemoryLayout<sockaddr_in6>.size)
        default:
            throw IOError(errnoCode: EAFNOSUPPORT, reason: "udp client socket address family")
        }
        var bindStorage = bindStorage
        var clientAddress = clientAddress
        let fd = withUnsafePointer(to: &bindStorage) { bindPointer in
            withUnsafePointer(to: &clientAddress) { clientPointer in
                bindPointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { bindAddress in
                    clientPointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { peerAddress in
                        curtsy_udp_connected_client_socket(
                            bindAddress,
                            bindLength,
                            peerAddress,
                            clientAddressLength
                        )
                    }
                }
            }
        }
        guard fd >= 0 else {
            throw IOError(errnoCode: errno, reason: "udp client socket")
        }
        applySocketBuffers(to: fd, context: "direction=client", warnOnFailure: false)
        do {
            let pairing = try accelerator.pair(clientFD: fd, upstreamFD: upstreamFD)
            guard curtsy_epoll_add(epollFD, fd) == 0 else {
                throw IOError(errnoCode: errno, reason: "epoll add client socket")
            }
            return (fd, pairing)
        } catch {
            Glibc.close(fd)
            throw error
        }
    }

    private func closeAssociation(client: SocketAddress) {
        guard let association = associations.removeValue(forKey: client) else { return }
        // Stop kernel steering first; further datagrams then fall back to the
        // userspace relay (or to the listener once the sockets are gone).
        association.sockmap?.close()
        upstreamToClient.removeValue(forKey: association.upstreamFD)
        if let clientFD = association.clientFD {
            clientFDToClient.removeValue(forKey: clientFD)
            Glibc.close(clientFD)
        }
        Glibc.close(association.upstreamFD)
        budget.release()
        warnedAtLimit = false
    }

    private func closeAllAssociations() {
        for client in Array(associations.keys) {
            closeAssociation(client: client)
        }
    }

    private func sweepExpiredAssociations() {
        let timeoutSeconds = runtime.current().configuration.timeouts.udpSessionSeconds
        let timeoutMilliseconds = UInt64(max(1, timeoutSeconds)) * 1_000
        let timeoutNanoseconds = timeoutMilliseconds * 1_000_000
        let now = Self.monotonicMilliseconds()
        for client in Array(associations.keys) {
            guard let association = associations[client] else { continue }
            if let pairing = association.sockmap {
                // Steered traffic never reaches userspace; the BPF peer state
                // holds the last-activity timestamp instead.
                let remaining = try? pairing.idleRemaining(timeoutNanoseconds: timeoutNanoseconds)
                guard let remaining, remaining > 0 else {
                    log.debug("udp association expired client=\(client.curtsyDescription)")
                    closeAssociation(client: client)
                    continue
                }
            } else {
                guard now &- association.lastActivityMilliseconds < timeoutMilliseconds else {
                    log.debug("udp association expired client=\(client.curtsyDescription)")
                    closeAssociation(client: client)
                    continue
                }
            }
        }
    }

    private static func monotonicMilliseconds() -> UInt64 {
        var time = timespec()
        clock_gettime(CLOCK_MONOTONIC, &time)
        return UInt64(time.tv_sec) * 1_000 + UInt64(time.tv_nsec) / 1_000_000
    }

    private static func errnoDescription() -> String {
        String(cString: strerror(errno))
    }

    private static func socketAddress(from storage: sockaddr_storage) -> SocketAddress? {
        var storage = storage
        switch Int32(storage.ss_family) {
        case AF_INET:
            return withUnsafePointer(to: &storage) { pointer in
                pointer.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                    SocketAddress($0.pointee)
                }
            }
        case AF_INET6:
            return withUnsafePointer(to: &storage) { pointer in
                pointer.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
                    SocketAddress($0.pointee)
                }
            }
        default:
            return nil
        }
    }
}
