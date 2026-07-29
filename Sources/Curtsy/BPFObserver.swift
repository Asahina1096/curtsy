import CBPFSupport
import Foundation

struct BPFObserverCounters: Equatable, Sendable {
    var tcpSendmsg: UInt64
    var tcpRecvmsg: UInt64
    var udpSendmsg: UInt64
    var udpRecvmsg: UInt64

    var totalEvents: UInt64 {
        tcpSendmsg + tcpRecvmsg + udpSendmsg + udpRecvmsg
    }

    static let zero = BPFObserverCounters(tcpSendmsg: 0, tcpRecvmsg: 0, udpSendmsg: 0, udpRecvmsg: 0)

    func delta(from previous: BPFObserverCounters) -> BPFObserverCounters {
        BPFObserverCounters(
            tcpSendmsg: tcpSendmsg >= previous.tcpSendmsg ? tcpSendmsg - previous.tcpSendmsg : 0,
            tcpRecvmsg: tcpRecvmsg >= previous.tcpRecvmsg ? tcpRecvmsg - previous.tcpRecvmsg : 0,
            udpSendmsg: udpSendmsg >= previous.udpSendmsg ? udpSendmsg - previous.udpSendmsg : 0,
            udpRecvmsg: udpRecvmsg >= previous.udpRecvmsg ? udpRecvmsg - previous.udpRecvmsg : 0
        )
    }
}

final class BPFObserver: @unchecked Sendable {
    enum ObserverError: Error, CustomStringConvertible {
        case systemCall(errorNumber: Int32, verifierLog: String = "")

        var description: String {
            switch self {
            case .systemCall(let errorNumber, let verifierLog):
                let reason = String(cString: strerror(errorNumber))
                return verifierLog.isEmpty ? reason : "\(reason); verifier=\(verifierLog)"
            }
        }
    }

    private let observer: OpaquePointer

    private init(observer: OpaquePointer) {
        self.observer = observer
    }

    static func load(processIdentifier: Int32 = getpid()) throws -> BPFObserver {
        var verifierLog = [CChar](repeating: 0, count: 256 * 1_024)
        let runtime = verifierLog.withUnsafeMutableBufferPointer { buffer in
            curtsy_bpf_observer_create(UInt32(processIdentifier), buffer.baseAddress, buffer.count)
        }
        guard let runtime else {
            let errorNumber = errno
            let message = verifierLog.withUnsafeBufferPointer { buffer in
                String(cString: buffer.baseAddress!)
            }
            throw ObserverError.systemCall(errorNumber: errorNumber, verifierLog: message)
        }
        return BPFObserver(observer: runtime)
    }

    func readCounters() throws -> BPFObserverCounters {
        var counters = curtsy_bpf_observer_counters()
        guard curtsy_bpf_observer_read(observer, &counters) == 0 else {
            throw ObserverError.systemCall(errorNumber: errno)
        }
        return BPFObserverCounters(
            tcpSendmsg: counters.tcp_sendmsg,
            tcpRecvmsg: counters.tcp_recvmsg,
            udpSendmsg: counters.udp_sendmsg,
            udpRecvmsg: counters.udp_recvmsg
        )
    }

    deinit {
        curtsy_bpf_observer_destroy(observer)
    }
}
