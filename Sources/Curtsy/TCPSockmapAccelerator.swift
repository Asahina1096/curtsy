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
        guard client.eventLoop === upstream.eventLoop else {
            return client.eventLoop.makeFailedFuture(AcceleratorError.unsupportedChannel)
        }

        return client.eventLoop.submit { [self] in
            try pairOnEventLoop(client: client, upstream: upstream)
        }
    }

    private func pairOnEventLoop(client: Channel, upstream: Channel) throws -> TCPSockmapConnection {
        client.eventLoop.assertInEventLoop()
        let clientTransportResult = try client.pipeline.syncOperations.withUnsafeTransportIfAvailable(
            of: NIOBSDSocket.Handle.self,
            { clientDescriptor in
                try upstream.pipeline.syncOperations.withUnsafeTransportIfAvailable(
                    of: NIOBSDSocket.Handle.self,
                    { upstreamDescriptor in
                        try makeConnection(
                            clientDescriptor: clientDescriptor,
                            upstreamDescriptor: upstreamDescriptor
                        )
                    }
                )
            }
        )
        guard
            let maybeConnection = clientTransportResult,
            let connection = maybeConnection
        else {
            throw AcceleratorError.unsupportedChannel
        }
        return connection
    }

    private func makeConnection(
        clientDescriptor: NIOBSDSocket.Handle,
        upstreamDescriptor: NIOBSDSocket.Handle
    ) throws -> TCPSockmapConnection {
        var clientCookie: UInt64 = 0
        var upstreamCookie: UInt64 = 0
        guard curtsy_sockmap_pair(
            runtime,
            Int32(clientDescriptor),
            Int32(upstreamDescriptor),
            &clientCookie,
            &upstreamCookie
        ) == 0 else {
            throw AcceleratorError.systemCall(errorNumber: errno)
        }
        return TCPSockmapConnection(
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
