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
    dependencies: [
        .package(url: "https://github.com/ionic-team/capacitor-swift-pm.git", from: "8.0.0")
    ],
    targets: [
        .target(
            name: "YutingHealthkitBridge",
            dependencies: [
                .product(name: "Capacitor", package: "capacitor-swift-pm"),
                .product(name: "Cordova", package: "capacitor-swift-pm")
            ],
            path: "ios",
            linkerSettings: [
                .linkedFramework("HealthKit")
            ]
        )
    ]
)
