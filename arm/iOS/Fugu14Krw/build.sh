set -e

swiftcArgs=(-sdk "`xcrun --sdk iphoneos --show-sdk-path`" -target arm64-apple-ios14.0 -O -framework IOKit)

swiftBuild=(swift build -c release -Xcc "-DIOS_BUILD" -Xcc -target -Xcc arm64-apple-ios14.0 -Xcc -Wno-incompatible-sysroot)
for arg in ${swiftcArgs[*]}
do
    swiftBuild+=(-Xswiftc "$arg")
done

echo Building Fugu14Krw
echo ${swiftBuild[*]}
${swiftBuild[*]}

echo Signing Fugu14Krw
codesign -s - .build/release/libFugu14Krw.dylib
