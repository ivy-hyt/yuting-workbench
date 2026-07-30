// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "HealthKitBridge",
    platforms: [
        .iOS(.v13)
    ],
    products: [
        .library(name: "HealthKitBridge", targets: ["HealthKitBridge"])
    ],
    targets: [
        .target(
            name: "HealthKitBridge",
            path: "ios",
            linkerSettings: [
                .linkedFramework("HealthKit")
            ]
        )
    ]
)
