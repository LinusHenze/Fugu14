// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "jailbreakd",
    platforms: [
        .iOS(.v14),
        .macOS(.v11) // Just to test compilation, not really supported
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .executable(
            name: "jailbreakd",
            targets: ["jailbreakd"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(path: "../../Shared/KernelExploit"),
        .package(path: "../../Shared/ClosurePwn")
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .systemLibrary(name: "externalCStuff"),
        .target(name: "asmAndC"),
        .target(
            name: "jailbreakd",
            dependencies: ["KernelExploit", "externalCStuff", "asmAndC", "ClosurePwn"])
    ]
)
