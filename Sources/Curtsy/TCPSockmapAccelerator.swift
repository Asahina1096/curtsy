import CBPFSupport
import NIOConcurrencyHelpers
import NIOCore

#if os(Linux)
import Glibc
#endif

final class TCPSockmapAccelerator: @unchecked Sendable {
    enum AcceleratorError: Error, CustomStringConvertible {
        case unsupportedChannel
        case systemCall(errorNumber: Int32, verifierLog: String = "")

        var description: String {
            switch self {
            case .unsupportedChannel:
                return "channel does not expose socket options"
            case .systemCall(let errorNumber, let verifierLog):
                #if os(Linux)
                let reason = String(cString: Glibc.strerror(errorNumber))
                #else
                let reason = "not supported"
                #endif
                return verifierLog.isEmpty ? reason : "\(reason); verifier=\(verifierLog)"
            }
        }
    }

    private let runtime: OpaquePointer

    private init(runtime: OpaquePointer) {
        self.runtime = runtime
    }

    // Each proxied TCP connection consumes two map entries.
    static func load(maxEntries: Int = 131_072) throws -> TCPSockmapAccelerator? {
        #if os(Linux)
        var verifierLog = [CChar](repeating: 0, count: 256 * 1_024)
        let runtime = verifierLog.withUnsafeMutableBufferPointer { buffer in
            curtsy_sockmap_create(UInt32(maxEntries), buffer.baseAddress, buffer.count)
        }
        guard let runtime else {
            let errorNumber = errno
            let message = verifierLog.withUnsafeBufferPointer { buffer in
                String(cString: buffer.baseAddress!)
            }
            throw AcceleratorError.systemCall(errorNumber: errorNumber, verifierLog: message)
        }
        return TCPSockmapAccelerator(runtime: runtime)
        #else
        return nil
        #endif
    }

    func pair(client: Channel, upstream: Channel) -> EventLoopFuture<TCPSockmapConnection> {
        guard
            let clientProvider = client as? SocketOptionProvider,
            let upstreamProvider = upstream as? SocketOptionProvider
        else {
            return client.eventLoop.makeFailedFuture(AcceleratorError.unsupportedChannel)
        }

        let level = SocketOptionLevel(curtsy_socket_level())
        let name = SocketOptionName(curtsy_so_cookie())
        let clientCookie: EventLoopFuture<UInt64> = clientProvider.unsafeGetSocketOption(level: level, name: name)
        let upstreamCookie: EventLoopFuture<UInt64> = upstreamProvider.unsafeGetSocketOption(level: level, name: name)

        return clientCookie.and(upstreamCookie).flatMapThrowing { [self] cookies in
            guard curtsy_sockmap_pair(runtime, cookies.0, cookies.1) == 0 else {
                throw AcceleratorError.systemCall(errorNumber: errno)
            }
            return TCPSockmapConnection(
                accelerator: self,
                clientCookie: cookies.0,
                upstreamCookie: cookies.1
            )
        }
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

final class TCPSockmapConnection: @unchecked Sendable {
    private let accelerator: TCPSockmapAccelerator
    private let clientCookie: UInt64
    private let upstreamCookie: UInt64
    private let closed = NIOLockedValueBox(false)

    fileprivate init(accelerator: TCPSockmapAccelerator, clientCookie: UInt64, upstreamCookie: UInt64) {
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
