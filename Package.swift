// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "curtsy",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "curtsy", targets: ["Curtsy"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.99.0"),
        .package(url: "https://github.com/jpsim/Yams.git", from: "6.2.2"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.9.1"),
        .package(url: "https://github.com/apple/swift-atomics.git", from: "1.3.1"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.8.2")
    ],
    targets: [
        .target(
            name: "CBPFSupport",
            path: "Sources/CBPFSupport",
            publicHeadersPath: "include"
        ),
        .executableTarget(
            name: "Curtsy",
            dependencies: [
                "CBPFSupport",
                .product(name: "Atomics", package: "swift-atomics"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
                .product(name: "Yams", package: "Yams"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "ArgumentParser", package: "swift-argument-parser")
            ]
        ),
        .testTarget(
            name: "CurtsyTests",
            dependencies: [
                "Curtsy",
                .product(name: "NIOEmbedded", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio")
            ]
        )
    ]
)
