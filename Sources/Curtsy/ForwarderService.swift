import Dispatch
import Foundation
import NIOCore
import NIOPosix

#if canImport(Glibc)
import Glibc
#else
import Darwin
#endif

final class ForwarderService: @unchecked Sendable {
    private let configurationPath: String
    private let group: MultiThreadedEventLoopGroup
    private let controlQueue = DispatchQueue(label: "curtsy.control")
    private let stopped = DispatchSemaphore(value: 0)
    private let log: LogStore
    private var configuration: ResolvedConfiguration
    private var tcpListener: TCPListener?
    private var udpListener: UDPListener?
    private var retiredTCPListeners: [TCPListener] = []
    private var retiredTCPReapScheduled = false
    private var signalSources: [DispatchSourceSignal] = []
    private var shuttingDown = false

    init(configurationPath: String, configuration: ForwarderConfiguration) throws {
        self.configurationPath = configurationPath
        self.configuration = try ResolvedConfiguration.resolve(configuration)
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: max(1, System.coreCount))
        self.log = LogStore(level: configuration.logging.level)
    }

    func run() throws {
        do {
            try startInitialListeners()
        } catch {
            try? group.syncShutdownGracefully()
            throw error
        }

        installSignalHandlers()
        log.info("forwarder started protocols=\(configuration.configuration.protocols.map(\.rawValue).joined(separator: ",")) upstream=\(configuration.upstreamAddress.curtsyDescription)")
        stopped.wait()
        signalSources.forEach { $0.cancel() }
        try group.syncShutdownGracefully()
    }

    private func startInitialListeners() throws {
        var startedTCP: TCPListener?
        do {
            if configuration.configuration.protocols.contains(.tcp) {
                let listener = TCPListener(group: group, configuration: configuration, log: log)
                try listener.start()
                startedTCP = listener
            }
            if configuration.configuration.protocols.contains(.udp) {
                let listener = UDPListener(group: group, configuration: configuration, log: log)
                try listener.start()
                udpListener = listener
            }
            tcpListener = startedTCP
        } catch {
            startedTCP?.stopAccepting()
            startedTCP?.forceCloseConnections()
            udpListener?.stop()
            throw error
        }
    }

    private func installSignalHandlers() {
        #if canImport(Glibc)
        _ = Glibc.signal(SIGPIPE, SIG_IGN)
        _ = Glibc.signal(SIGINT, SIG_IGN)
        _ = Glibc.signal(SIGTERM, SIG_IGN)
        _ = Glibc.signal(SIGHUP, SIG_IGN)
        #else
        _ = Darwin.signal(SIGPIPE, SIG_IGN)
        _ = Darwin.signal(SIGINT, SIG_IGN)
        _ = Darwin.signal(SIGTERM, SIG_IGN)
        _ = Darwin.signal(SIGHUP, SIG_IGN)
        #endif

        let interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: controlQueue)
        interrupt.setEventHandler { [weak self] in self?.shutdown(reason: "SIGINT") }
        let terminate = DispatchSource.makeSignalSource(signal: SIGTERM, queue: controlQueue)
        terminate.setEventHandler { [weak self] in self?.shutdown(reason: "SIGTERM") }
        let reload = DispatchSource.makeSignalSource(signal: SIGHUP, queue: controlQueue)
        reload.setEventHandler { [weak self] in self?.reload() }

        signalSources = [interrupt, terminate, reload]
        signalSources.forEach { $0.resume() }
    }

    private func reload() {
        guard !shuttingDown else { return }
        log.info("reloading configuration path=\(configurationPath)")

        do {
            let loaded = try ConfigurationLoader.load(path: configurationPath)
            let candidate = try ResolvedConfiguration.resolve(loaded)
            try apply(candidate)
            log.update(level: loaded.logging.level)
            log.info("configuration reloaded protocols=\(loaded.protocols.map(\.rawValue).joined(separator: ",")) upstream=\(candidate.upstreamAddress.curtsyDescription)")
        } catch {
            log.error("configuration reload rejected error=\(error)")
        }
    }

    private func apply(_ candidate: ResolvedConfiguration) throws {
        let old = configuration
        let endpointChanged = old.listenBindingDiffers(from: candidate)
        let newProtocols = Set(candidate.configuration.protocols)

        if endpointChanged {
            var newTCP: TCPListener?
            var newUDP: UDPListener?
            do {
                if newProtocols.contains(.tcp) {
                    let listener = TCPListener(group: group, configuration: candidate, log: log)
                    try listener.start()
                    newTCP = listener
                } else {
                    newTCP = nil
                }
                if newProtocols.contains(.udp) {
                    let listener = UDPListener(group: group, configuration: candidate, log: log)
                    try listener.start()
                    newUDP = listener
                } else {
                    newUDP = nil
                }
            } catch {
                newTCP?.stopAccepting()
                newTCP?.forceCloseConnections()
                newUDP?.stop()
                throw error
            }

            if let oldTCP = tcpListener {
                oldTCP.stopAccepting()
                retire(oldTCP)
            }
            udpListener?.stop()
            tcpListener = newTCP
            udpListener = newUDP
            configuration = candidate
            return
        }

        let replaceTCP = newProtocols.contains(.tcp)
            && tcpListener != nil
            && old.tcpAccelerationDiffers(from: candidate)
        var addedTCP: TCPListener?
        var addedUDP: UDPListener?
        do {
            if newProtocols.contains(.tcp), tcpListener == nil || replaceTCP {
                let listener = TCPListener(group: group, configuration: candidate, log: log)
                try listener.start()
                addedTCP = listener
            }
            if newProtocols.contains(.udp), udpListener == nil {
                let listener = UDPListener(group: group, configuration: candidate, log: log)
                try listener.start()
                addedUDP = listener
            }

            let backlogChanged = old.configuration.limits.tcpListenBacklog
                != candidate.configuration.limits.tcpListenBacklog
            if newProtocols.contains(.tcp), backlogChanged, addedTCP == nil {
                try (addedTCP ?? tcpListener)?.updateListeningBacklog(
                    candidate.configuration.limits.tcpListenBacklog
                )
            }
        } catch {
            addedTCP?.stopAccepting()
            addedTCP?.forceCloseConnections()
            addedUDP?.stop()
            throw error
        }

        if let addedTCP {
            let oldTCP = tcpListener
            tcpListener = addedTCP
            if let oldTCP {
                oldTCP.stopAccepting()
                retire(oldTCP)
            }
        }
        if let addedUDP { udpListener = addedUDP }

        let upstreamChanged = old.upstreamAddress != candidate.upstreamAddress
        tcpListener?.update(configuration: candidate)
        udpListener?.update(configuration: candidate, resetAssociations: upstreamChanged)

        if !newProtocols.contains(.tcp), let oldTCP = tcpListener {
            oldTCP.stopAccepting()
            retire(oldTCP)
            tcpListener = nil
        }
        if !newProtocols.contains(.udp) {
            udpListener?.stop()
            udpListener = nil
        }
        configuration = candidate
    }

    private func shutdown(reason: String) {
        guard !shuttingDown else { return }
        shuttingDown = true
        log.info("shutdown requested signal=\(reason)")

        if let listener = tcpListener {
            listener.stopAccepting()
            retire(listener)
            tcpListener = nil
        }
        udpListener?.stop()
        udpListener = nil

        let grace = configuration.configuration.timeouts.shutdownGraceSeconds
        let deadline = Date().addingTimeInterval(TimeInterval(grace))
        while Date() < deadline, retiredTCPListeners.reduce(0, { $0 + $1.activeConnectionCount }) > 0 {
            Thread.sleep(forTimeInterval: 0.05)
        }

        let remaining = retiredTCPListeners.reduce(0, { $0 + $1.activeConnectionCount })
        if remaining > 0 {
            log.warning("forcing tcp connections closed count=\(remaining)")
            retiredTCPListeners.forEach { $0.forceCloseConnections() }
        }
        log.info("forwarder stopped")
        stopped.signal()
    }

    private func retire(_ listener: TCPListener) {
        retiredTCPListeners.append(listener)
        scheduleRetiredTCPReap()
    }

    private func scheduleRetiredTCPReap() {
        guard !retiredTCPReapScheduled, !shuttingDown else { return }
        retiredTCPReapScheduled = true
        controlQueue.asyncAfter(deadline: .now() + .seconds(1)) { [weak self] in
            guard let self else { return }
            self.retiredTCPReapScheduled = false
            self.retiredTCPListeners.removeAll { $0.activeConnectionCount == 0 }
            if !self.retiredTCPListeners.isEmpty {
                self.scheduleRetiredTCPReap()
            }
        }
    }
}
