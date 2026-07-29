import CBPFSupport
import Glibc
import NIOConcurrencyHelpers

// Kernel-level UDP steering: paired connected UDP sockets exchange datagrams
// inside the kernel via an SK_SKB verdict program, so established
// associations no longer cross userspace. Mirrors TCPSockmapAccelerator but
// pairs raw file descriptors (the UDP relay does not use NIO channels).
final class UDPSockmapAccelerator: @unchecked Sendable {
    enum AcceleratorError: Error, CustomStringConvertible {
        case systemCall(errorNumber: Int32, verifierLog: String = "")

        var description: String {
            switch self {
            case .systemCall(let errorNumber, let verifierLog):
                let reason = String(cString: Glibc.strerror(errorNumber))
                return verifierLog.isEmpty ? reason : "\(reason); verifier=\(verifierLog)"
            }
        }
    }

    private let runtime: OpaquePointer

    private init(runtime: OpaquePointer) {
        self.runtime = runtime
    }

    // Each accelerated UDP association consumes two map entries.
    static func load(maxEntries: Int = 131_072) throws -> UDPSockmapAccelerator {
        var verifierLog = [CChar](repeating: 0, count: 256 * 1_024)
        let runtime = verifierLog.withUnsafeMutableBufferPointer { buffer in
            curtsy_udp_sockmap_create(UInt32(maxEntries), buffer.baseAddress, buffer.count)
        }
        guard let runtime else {
            let errorNumber = errno
            let message = verifierLog.withUnsafeBufferPointer { buffer in
                String(cString: buffer.baseAddress!)
            }
            throw AcceleratorError.systemCall(errorNumber: errorNumber, verifierLog: message)
        }
        return UDPSockmapAccelerator(runtime: runtime)
    }

    func pair(clientFD: Int32, upstreamFD: Int32) throws -> UDPSockmapAssociation {
        var clientCookie: UInt64 = 0
        var upstreamCookie: UInt64 = 0
        guard curtsy_sockmap_pair(
            runtime,
            clientFD,
            upstreamFD,
            &clientCookie,
            &upstreamCookie
        ) == 0 else {
            throw AcceleratorError.systemCall(errorNumber: errno)
        }
        return UDPSockmapAssociation(
            accelerator: self,
            clientCookie: clientCookie,
            upstreamCookie: upstreamCookie
        )
    }

    fileprivate func unpair(clientCookie: UInt64, upstreamCookie: UInt64) {
        curtsy_sockmap_unpair(runtime, clientCookie, upstreamCookie)
    }

    fileprivate func idleRemaining(
        clientCookie: UInt64,
        upstreamCookie: UInt64,
        timeoutNanoseconds: UInt64
    ) throws -> UInt64 {
        var remaining: UInt64 = 0
        guard curtsy_sockmap_idle_remaining_ns(
            runtime,
            clientCookie,
            upstreamCookie,
            timeoutNanoseconds,
            &remaining
        ) == 0 else {
            throw AcceleratorError.systemCall(errorNumber: errno)
        }
        return remaining
    }

    deinit {
        curtsy_sockmap_destroy(runtime)
    }
}

final class UDPSockmapAssociation: @unchecked Sendable {
    private let accelerator: UDPSockmapAccelerator
    private let clientCookie: UInt64
    private let upstreamCookie: UInt64
    private let closed = NIOLockedValueBox(false)

    fileprivate init(accelerator: UDPSockmapAccelerator, clientCookie: UInt64, upstreamCookie: UInt64) {
        self.accelerator = accelerator
        self.clientCookie = clientCookie
        self.upstreamCookie = upstreamCookie
    }

    func idleRemaining(timeoutNanoseconds: UInt64) throws -> UInt64 {
        try accelerator.idleRemaining(
            clientCookie: clientCookie,
            upstreamCookie: upstreamCookie,
            timeoutNanoseconds: timeoutNanoseconds
        )
    }

    func close() {
        let shouldUnpair = closed.withLockedValue { closed in
            guard !closed else { return false }
            closed = true
            return true
        }
        if shouldUnpair {
            accelerator.unpair(clientCookie: clientCookie, upstreamCookie: upstreamCookie)
        }
    }

    deinit {
        close()
    }
}
