import Dispatch
import Foundation

struct NetstatCounters: Equatable, Sendable {
    var listenOverflows: UInt64
    var listenDrops: UInt64

    static let zero = NetstatCounters(listenOverflows: 0, listenDrops: 0)

    func delta(from previous: NetstatCounters) -> NetstatCounters {
        NetstatCounters(
            listenOverflows: listenOverflows >= previous.listenOverflows ? listenOverflows - previous.listenOverflows : 0,
            listenDrops: listenDrops >= previous.listenDrops ? listenDrops - previous.listenDrops : 0
        )
    }

    static func read() -> NetstatCounters? {
        guard let text = try? String(contentsOfFile: "/proc/net/netstat", encoding: .utf8) else {
            return nil
        }
        var header: [Substring]?
        for line in text.split(separator: "\n") where line.hasPrefix("TcpExt:") {
            let fields = line.split(separator: " ")
            if header == nil {
                header = fields
                continue
            }
            guard let header else { return nil }
            var values: [Substring: UInt64] = [:]
            for index in 1..<min(header.count, fields.count) {
                values[header[index]] = UInt64(fields[index])
            }
            return NetstatCounters(
                listenOverflows: values["ListenOverflows"] ?? 0,
                listenDrops: values["ListenDrops"] ?? 0
            )
        }
        return nil
    }
}

struct TuningSnapshot: Sendable {
    var configuration: ResolvedConfiguration
    var tcpBufferedBytes: Int
    var udpAssociations: Int
}

final class TuningDaemon: @unchecked Sendable {
    typealias SnapshotProvider = @Sendable () -> TuningSnapshot?
    typealias ApplyLimits = @Sendable (LimitConfiguration) -> Void

    private let queue: DispatchQueue
    private let intervalSeconds: Int
    private let log: LogStore
    private let snapshotProvider: SnapshotProvider
    private let applyLimits: ApplyLimits
    private var timer: DispatchSourceTimer?
    private var observer: BPFObserver?
    private var lastBPFCounters: BPFObserverCounters?
    private var lastNetstatCounters: NetstatCounters?

    init(
        queue: DispatchQueue,
        intervalSeconds: Int,
        log: LogStore,
        snapshotProvider: @escaping SnapshotProvider,
        applyLimits: @escaping ApplyLimits
    ) {
        precondition(intervalSeconds > 0)
        self.queue = queue
        self.intervalSeconds = intervalSeconds
        self.log = log
        self.snapshotProvider = snapshotProvider
        self.applyLimits = applyLimits
    }

    func start() {
        do {
            observer = try BPFObserver.load()
            log.info("tuning daemon ebpf observer enabled")
        } catch {
            observer = nil
            log.warning("tuning daemon ebpf observer unavailable; using internal counters error=\(error)")
        }
        lastBPFCounters = try? observer?.readCounters()
        lastNetstatCounters = NetstatCounters.read()

        let source = DispatchSource.makeTimerSource(queue: queue)
        source.schedule(deadline: .now() + .seconds(intervalSeconds), repeating: .seconds(intervalSeconds))
        source.setEventHandler { [weak self] in self?.tick() }
        timer = source
        source.resume()
    }

    func stop() {
        timer?.cancel()
        timer = nil
        observer = nil
    }

    private func tick() {
        guard let snapshot = snapshotProvider() else { return }
        let current = snapshot.configuration.configuration.limits
        var tuned = current
        let auto = current.autoTuning
        let target = AutoTune.limits()
        var reasons: [String] = []

        let bpfDelta = readBPFDeltas()
        let netstatDelta = readNetstatDelta()

        if auto.tcpListenBacklog,
           (netstatDelta.listenOverflows > 0 || netstatDelta.listenDrops > 0) {
            let next = min(Int(Int32.max), max(current.tcpListenBacklog + 1, current.tcpListenBacklog * 2))
            if next != current.tcpListenBacklog {
                tuned.tcpListenBacklog = next
                reasons.append("listen_queue_pressure")
            }
        }

        if auto.maxTCPBufferedBytes {
            let usage = ratio(used: snapshot.tcpBufferedBytes, limit: current.maxTCPBufferedBytes)
            let highCap = AutoTune.highTCPBufferBudget()
            if usage >= 0.75, current.maxTCPBufferedBytes < highCap {
                tuned.maxTCPBufferedBytes = min(highCap, max(current.maxTCPBufferedBytes + 1, current.maxTCPBufferedBytes + current.maxTCPBufferedBytes / 4))
                reasons.append("tcp_buffer_pressure")
            } else if usage <= 0.10, current.maxTCPBufferedBytes > target.maxTCPBufferedBytes {
                tuned.maxTCPBufferedBytes = max(target.maxTCPBufferedBytes, current.maxTCPBufferedBytes - current.maxTCPBufferedBytes / 10)
                reasons.append("tcp_buffer_idle")
            }
        }

        if auto.maxUDPAssociations {
            let usage = ratio(used: snapshot.udpAssociations, limit: current.maxUDPAssociations)
            let highCap = AutoTune.highUDPAssociationLimit()
            if usage >= 0.80, current.maxUDPAssociations < highCap {
                tuned.maxUDPAssociations = min(highCap, max(current.maxUDPAssociations + 1, current.maxUDPAssociations + current.maxUDPAssociations / 4))
                reasons.append("udp_association_pressure")
            } else if usage <= 0.05, current.maxUDPAssociations > target.maxUDPAssociations {
                tuned.maxUDPAssociations = max(target.maxUDPAssociations, current.maxUDPAssociations - current.maxUDPAssociations / 10)
                reasons.append("udp_association_idle")
            }
        }

        guard tuned != current else { return }
        applyLimits(tuned)
        log.info(
            "tuning daemon adjusted reason=\(reasons.joined(separator: ",")) "
                + "tcp_buffered=\(snapshot.tcpBufferedBytes) "
                + "max_tcp_buffered_bytes=\(tuned.maxTCPBufferedBytes) "
                + "udp_associations=\(snapshot.udpAssociations) "
                + "max_udp_associations=\(tuned.maxUDPAssociations) "
                + "tcp_listen_backlog=\(tuned.tcpListenBacklog) "
                + "ebpf_events=\(bpfDelta.totalEvents) "
                + "listen_overflows=\(netstatDelta.listenOverflows) "
                + "listen_drops=\(netstatDelta.listenDrops)"
        )
    }

    private func readBPFDeltas() -> BPFObserverCounters {
        guard let observer, let counters = try? observer.readCounters() else { return .zero }
        let delta = lastBPFCounters.map { counters.delta(from: $0) } ?? .zero
        lastBPFCounters = counters
        return delta
    }

    private func readNetstatDelta() -> NetstatCounters {
        guard let counters = NetstatCounters.read() else { return .zero }
        let delta = lastNetstatCounters.map { counters.delta(from: $0) } ?? .zero
        lastNetstatCounters = counters
        return delta
    }

    private func ratio(used: Int, limit: Int) -> Double {
        guard limit > 0 else { return 1 }
        return Double(max(0, used)) / Double(limit)
    }
}
