#!/bin/bash

set -e

if [ "$#" -ne 2 ]; then
    echo "Usage: build_ipas.sh <path to Fugu14App.app> <path to mounted root file system>"
    exit -1
fi

if [ ! -f "./pwnify_compiled" ]; then
    echo "Couldn't find ./pwnify_compiled"
    echo "Please compile pwnify and put it into the current directory as pwnify_compiled"
    exit -1
fi

# Create IPA structure
mkdir -p Payload
rm -rf Payload/Fugu14App.app
rm -f Fugu14_Setup.ipa Fugu14_Pwn.ipa

# Build first IPA
cp -r "$1" Payload/Fugu14App.app
zip -r Fugu14_Setup.ipa Payload

# Inject Spotlight
./pwnify_compiled Payload/Fugu14App.app/Fugu14App "$2/Applications/Spotlight.app/Spotlight"

# Build second IPA
cp Fugu14_Setup.ipa Fugu14_Pwn.ipa
zip Fugu14_Pwn.ipa Payload/Fugu14App.app/Fugu14App

rm -rf Payload
