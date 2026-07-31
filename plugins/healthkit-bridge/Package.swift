// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "YutingHealthkitBridge",
    platforms: [
        .iOS(.v13)
    ],
    products: [
        .library(name: "YutingHealthkitBridge", targets: ["YutingHealthkitBridge"])
    ],
    targets: [
        .target(
            name: "YutingHealthkitBridge",
            path: "ios",
            linkerSettings: [
                .linkedFramework("HealthKit")
            ]
        )
    ]
)
