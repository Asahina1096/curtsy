import CBPFSupport
import Glibc
import NIOCore

enum ReusePortSocketOptions {
    static let reusePort = ChannelOptions.Types.SocketOption(
        level: SocketOptionLevel(curtsy_socket_level()),
        name: SocketOptionName(curtsy_so_reuseport())
    )

    static let attachEBPF = ChannelOptions.Types.SocketOption(
        level: SocketOptionLevel(curtsy_socket_level()),
        name: SocketOptionName(curtsy_so_attach_reuseport_ebpf())
    )
}

final class ReusePortBPFProgram {
    enum AttachError: Error {
        case unsupportedChannel
    }

    struct LoadError: Error, CustomStringConvertible {
        let errorNumber: Int32
        let verifierLog: String

        var description: String {
            let reason = String(cString: Glibc.strerror(errorNumber))
            guard !verifierLog.isEmpty else { return reason }
            return "\(reason); verifier=\(verifierLog)"
        }
    }

    private var descriptor: Int32

    private init(descriptor: Int32) {
        self.descriptor = descriptor
    }

    static func load(workerCount: Int) throws -> ReusePortBPFProgram {
        var verifierLog = [CChar](repeating: 0, count: 64 * 1_024)
        let descriptor = verifierLog.withUnsafeMutableBufferPointer { buffer in
            curtsy_load_reuseport_bpf(UInt32(workerCount), buffer.baseAddress, buffer.count)
        }
        guard descriptor >= 0 else {
            let errorNumber = errno
            let message = verifierLog.withUnsafeBufferPointer { buffer in
                String(cString: buffer.baseAddress!)
            }
            throw LoadError(errorNumber: errorNumber, verifierLog: message)
        }
        return ReusePortBPFProgram(descriptor: descriptor)
    }

    func attach(to channel: Channel) throws {
        guard let provider = channel as? SocketOptionProvider else {
            throw AttachError.unsupportedChannel
        }
        try provider.unsafeSetSocketOption(
            level: SocketOptionLevel(curtsy_socket_level()),
            name: SocketOptionName(curtsy_so_attach_reuseport_ebpf()),
            value: descriptor
        ).wait()
    }

    func close() {
        if descriptor >= 0 {
            _ = Glibc.close(descriptor)
            descriptor = -1
        }
    }

    deinit {
        close()
    }
}
