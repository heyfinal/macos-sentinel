// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "mcguardian",
    platforms: [
        .macOS(.v12)
    ],
    products: [
        .executable(name: "mcguardian", targets: ["SentinelCLI"]),
        .library(name: "Sentinel", targets: ["Sentinel"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.2.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0")
    ],
    targets: [
        .executableTarget(
            name: "SentinelCLI",
            dependencies: [
                "Sentinel",
                .product(name: "ArgumentParser", package: "swift-argument-parser")
            ]
        ),
        .target(
            name: "Sentinel",
            dependencies: [
                .product(name: "Logging", package: "swift-log")
            ],
            resources: [
                .process("Resources")
            ]
        ),
        .testTarget(
            name: "SentinelTests",
            dependencies: ["Sentinel"]
        )
    ]
)
