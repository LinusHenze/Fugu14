set -e

swiftcArgs=(-sdk "`xcrun --sdk iphoneos --show-sdk-path`" -target arm64-apple-ios14.0 -O -framework IOKit)

swiftBuild=(swift build -c release -Xcc "-DIOS_BUILD" -Xcc -target -Xcc arm64-apple-ios14.0 -Xcc -Wno-incompatible-sysroot)
for arg in ${swiftcArgs[*]}
do
    swiftBuild+=(-Xswiftc "$arg")
done

echo Building Fugu14Krw64
echo ${swiftBuild[*]}
${swiftBuild[*]}

mv .build/release/libFugu14Krw.dylib libFugu14Krw-64.dylib
rm -rf .build

swiftcArgs=(-sdk "`xcrun --sdk iphoneos --show-sdk-path`" -target arm64e-apple-ios14.0 -O -framework IOKit)

swiftBuild=(swift build -c release -Xcc "-DIOS_BUILD" -Xcc -target -Xcc arm64e-apple-ios14.0 -Xcc -Wno-incompatible-sysroot)
for arg in ${swiftcArgs[*]}
do
    swiftBuild+=(-Xswiftc "$arg")
done

echo Building Fugu14Krw64e
echo ${swiftBuild[*]}
${swiftBuild[*]}

mv .build/release/libFugu14Krw.dylib libFugu14Krw-64e.dylib

echo gonna make them kiss

lipo -create libFugu14Krw-64.dylib libFugu14Krw-64e.dylib --output libFugu14Krw.dylib

rm libFugu14Krw-64.dylib libFugu14Krw-64e.dylib

echo Signing Fugu14Krw
codesign -s - libFugu14Krw.dylib
