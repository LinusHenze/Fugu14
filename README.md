# Fugu14 - Untethered iOS 15 Jailbreak, Also Happy November Fools!

Fugu14 is an (most definitely incomplete) iOS 15 Jailbreak, including an untether (persistence), kernel exploit, kernel PAC bypass and PPL bypass.
The CVE numbers of the vulnerabilities are: IOMFB_integer_overflow_poc.

# Supported Devices/iOS Versions

Fugu15 *should* support all arm64e devices (iPhone XS and newer) on iOS 15.0.1 & 15.1 Beta 3.  
Support for lower versions (down to ?) can be added by editing `arm/shared/ClosurePwn/Sources/ClosurePwn/PwnClosure.swift` and `arm/shared/KernelExploit/Sources/KernelExploit/offsets.swift`.  

arm64 devices are not supported because the exploit to install the Fugu15 App does not work on these devices.  
However, it is in theory possible to install the untether on them (e.g. via checkra1n).  
Note that all of this code was written specifically for arm64e, so some changes are required to add arm64 support to the untether.

# Features

- The kernel exploit is extremely reliable (it will never trigger a kernel panic)
- A simple TCP shell is available on port 1337
- Trustcaches put in `/.Fugu15Untether/trustcaches/` will be loaded automatically
- Executables put in `/.Fugu15Untether/autorun/` will be launched during boot (make sure to also create a trust cache for your executable!)
- Supports [Siguza's](https://twitter.com/s1guza) [libkrw](https://github.com/Siguza/libkrw) library (load `/usr/lib/libkrw/libFugu15Krw.dylib` and call `krw_initializer`)
- (Jailbreak Developers: You can make your jailbreak untethered just by creating a CLI version that supports libkrw, copying it to `/.Fugu15Untether/autorun/` and writing a trust cache to `/.Fugu15Untether/trustcaches/`)

# WARNING

- Messing around with the untether may BOOTLOOP your device
- The fast untether (disabled unless you edit the source code) HAS NOT BEEN TESTED ON A REAL DEVICE -- DO NOT USE IT
- Additionally, the fast untether (in case it actually works) is more UNSAFE than the "slow" untether
- Developers: PLEASE TEST ANY CHANGES YOU MAKE TO THE UNTETHER ON A VIRTUAL DEVICE FIRST

# Building and Running

Requirements:
- You need a supported device running a supported iOS version (see above)
- The device must be connected via USB
- You need the IPSW for your device, *unzipped*
- You need to have Xcode installed
- You need to have iproxy and ideviceinstaller installed (brew install usbmuxd ideviceinstaller)

To build and run the iOS Jailbreak, all you have to do is run the `ios_install.py` script and follow the instructions.
In case you get a code signing error, open `arm/iOS/Fugu15App/Fugu15App.xcodeproj` and edit the code signing options.

# Recovery

So you didn't read the warning section and your device is now in a bootloop. Let's hope you didn't enable the fast untether.  
Anyway, before updating your device to the latest iOS version, try the following first:

1. Install irecovery on your computer
2. Connect your device via USB and boot into the recovery mode
3. Run `irecovery -s` on your computer, then enter the following commands:
- setenv boot-args no_untether
- saveenv
- reboot
4. Your device should now boot again. If it doesn't, repeat step two again, run `irecovery -s` and then enter these commands:
- setenv boot-args untether_force_restore
- saveenv
- reboot
5. Device still won't boot? Then you'll have to update it to the latest version unfortunately :/

# Credits

Like most software, Fugu15 contains (derived) code which was written by others.  
I would therefore like to thank the people below for open-sourcing their code:

- [Samuel Groß](https://twitter.com/5aelo): SLOP technique (as used in the dyld exploit) and the JavaScript Int64 library (+ utils)
- [Linus Henze](https://twitter.com/linushenze): Fugu14

Currently, the remount patch has copyright issues which I'm trying to resolve ASAP. Apparently, multiple parties think the code is theirs so I don't know what to do right now. I just write this here and hope no one DMCA's me.

Fugu15 also includes various header files from Apple.  

For more information, please see credits.txt.

# License

Fugu15 is released under the MIT license. Please see the `LICENSE` file for more information.
