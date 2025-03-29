# Android_Dump_Dex
A Frida script for hooking Android apps on arm/arm64 devices. It intercepts android_dlopen_ext, detects popular protectors (e.g., DexProtector, Jiagu360, AppGuard), and dumps Dex files from memory for analysis.
