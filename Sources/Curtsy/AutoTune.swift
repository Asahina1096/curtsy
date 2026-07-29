import Foundation

struct AutoTuneSnapshot: Equatable, Sendable {
    var processorCount: Int
    var totalMemoryBytes: Int?

    init(processorCount: Int = ProcessInfo.processInfo.activeProcessorCount, totalMemoryBytes: Int? = nil) {
        self.processorCount = max(1, processorCount)
        self.totalMemoryBytes = totalMemoryBytes ?? AutoTuneSnapshot.readTotalMemoryBytes()
    }

    private static func readTotalMemoryBytes() -> Int? {
        guard let text = try? String(contentsOfFile: "/proc/meminfo", encoding: .utf8) else {
            return nil
        }
        for line in text.split(separator: "\n") where line.hasPrefix("MemTotal:") {
            let parts = line.split { $0 == " " || $0 == "\t" }
            guard parts.count >= 2, let kib = Int(parts[1]) else { return nil }
            return kib * 1_024
        }
        return nil
    }
}

struct AutoTunedLimits: Equatable, Sendable {
    var tcpListenBacklog: Int
    var maxTCPBufferedBytes: Int
    var maxUDPAssociations: Int
    var maxUDPPendingDatagrams: Int
    var maxUDPPendingBytes: Int
}

enum AutoTune {
    static let defaultMemoryBytes = 1 * 1_024 * 1_024 * 1_024

    static func workerThreads(configured: Int, snapshot: AutoTuneSnapshot = .init()) -> Int {
        precondition(configured >= 0)
        if configured > 0 { return configured }
        return min(max(1, snapshot.processorCount), 32)
    }

    static func limits(snapshot: AutoTuneSnapshot = .init()) -> AutoTunedLimits {
        let memory = snapshot.totalMemoryBytes ?? defaultMemoryBytes
        let cores = max(1, snapshot.processorCount)
        let tcpBudget = clamp(memory / 8, min: 64 * mib, max: 512 * mib)
        let udpAssociations = clamp(memory / (512 * 1_024), min: 1_024, max: 65_536)
        return AutoTunedLimits(
            tcpListenBacklog: clamp(cores * 1_024, min: 4_096, max: 65_535),
            maxTCPBufferedBytes: tcpBudget,
            maxUDPAssociations: udpAssociations,
            maxUDPPendingDatagrams: 64,
            maxUDPPendingBytes: min(max(256 * 1_024, tcpBudget / 256), 2 * mib)
        )
    }

    static func highTCPBufferBudget(snapshot: AutoTuneSnapshot = .init()) -> Int {
        let memory = snapshot.totalMemoryBytes ?? defaultMemoryBytes
        return clamp(memory / 4, min: 64 * mib, max: 2 * gib)
    }

    static func highUDPAssociationLimit(snapshot: AutoTuneSnapshot = .init()) -> Int {
        let memory = snapshot.totalMemoryBytes ?? defaultMemoryBytes
        return clamp(memory / (256 * 1_024), min: 1_024, max: 262_144)
    }

    private static let mib = 1_024 * 1_024
    private static let gib = 1_024 * mib

    private static func clamp(_ value: Int, min minimum: Int, max maximum: Int) -> Int {
        Swift.max(minimum, Swift.min(maximum, value))
    }
}
