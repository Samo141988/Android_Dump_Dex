/*
A hook for the fork function is required when the process spawns a child
process, which may cause Frida to terminate. Return -1 only if it's necessary
to prevent further execution.
*/
(function () {
    const forkSymbol = Module.findExportByName(null, "fork");
    if (forkSymbol) {
        const safeForkHandler = new NativeCallback(() => {
            console.warn("[!] Fork intercepted - returning -1 with EPERM");
            const errno_location = Module.findExportByName(null, "__errno_location");
            if (errno_location) {
                const errnoPtr = new NativeFunction(errno_location, "pointer", [])();
                errnoPtr.writeInt(1);
            }
            return -1;
        }, 'int', []);
        Interceptor.replace(forkSymbol, safeForkHandler);
        console.warn("[+] Fork hook: ACTIVE");
    } else {
        console.warn("[-] fork() not found");
    }
})();

/* Enter your package name here */
const TARGET_PKG = "com.dexprotector.detector.envchecks";
const SAFE_DIR = `/data/data/${TARGET_PKG}/`;

function hookDlopen() {
    return new Promise((resolve, reject) => {
        try {
            let moduleName = Process.arch === "arm" ? "linker": "linker64";
            let reg = Process.arch === "arm" ? "r0": "x0";
            let hooked = false;

            Process.findModuleByName(moduleName).enumerateExports().forEach(function (sym) {
                if (sym.name.indexOf('android_dlopen_ext') >= 0) {
                    Interceptor.attach(sym.address, {
                        onEnter: function () {
                            let lib = this.context[reg].readUtf8String();
                            if (lib != null && lib != undefined) {
                                if (lib.indexOf("libdexprotector") != -1) {
                                    console.warn("\n[*] DexProtector Found : https://licelus.com");
                                    hooked = true;
                                }
                                if (lib.indexOf("libjiagu") != -1) {
                                    console.warn("\n[*] Jiagu360 Found : https://jiagu.360.cn");
                                    hooked = true;
                                }
                                if (lib.indexOf("libAppGuard") != -1) {
                                    console.warn("\n[*] AppGuard Found : http://appguard.nprotect.com");
                                    hooked = true;
                                }
                                if (lib.indexOf("libDexHelper") != -1) {
                                    console.warn("\n[*] Secneo Found : http://www.secneo.com");
                                    hooked = true;
                                }
                                if (lib.indexOf("libsecexe") != -1 || lib.indexOf("libsecmain") != -1 || lib.indexOf("libSecShell") != -1) {
                                    console.warn("\n[*] bangcle Found : https://github.com/woxihuannisja/Bangcle");
                                    hooked = true;
                                }
                                if (lib.indexOf("libprotectt") != -1 || lib.indexOf("libapp-protectt") != -1) {
                                    console.warn("\n[*] protectt Found : https://www.protectt.ai");
                                    hooked = true;
                                }
                                if (lib.indexOf("libkonyjsvm") != -1) {
                                    console.warn("\n[*] Kony Found : http://www.kony.com/");
                                    hooked = true;
                                }
                                if (lib.indexOf("libnesec") != -1) {
                                    console.warn("\n[*] yidun Found : https://dun.163.com/product/app-protect");
                                    hooked = true;
                                }
                                if (lib.indexOf("libcovault") != -1) {
                                    console.warn("\n[*] AppSealing Found : https://www.appsealing.com/");
                                    hooked = true;
                                }
                                if (lib.indexOf("libpairipcore") != -1) {
                                    console.warn("\n[*] Pairip Found : https://github.com/rednaga/APKiD/issues/329");
                                    hooked = true;
                                }
                            }
                        },
                        onLeave: function(retval) {
                            if (hooked) resolve();
                        }
                    });
                }
            });
            setTimeout(() => {
                resolve();
            }, 3000);

        } catch (e) {
            console.error("Non arm/arm64 device. Emulator ???");
            reject(e);
        }
    });
}

function ProcessDex(Buf, C, Path) {
    let DumpDex = new Uint8Array(Buf);
    let Count = C - 1;
    if (DumpDex[0] == 99 && DumpDex[1] == 100 && DumpDex[2] == 101 && DumpDex[3] == 120 && DumpDex[4] == 48 && DumpDex[5] == 48 && DumpDex[6] == 49) {
        console.warn("[*]  classes" + Count + ".dex is Detected Compact Dex (CDEX), safe to ignore.");
    } else
        if (DumpDex[0] == 0 && DumpDex[1] == 0 && DumpDex[2] == 0 && DumpDex[3] == 0 && DumpDex[7] == 0) {
        console.warn("[*] 0000000 Header. classes" + Count + ".dex is Empty header detected, possibly obfuscated Dex.");
        console.error("[Dex"+Count +"] : "+Path);
        WriteDex(Count, Buf, Path, 0);
    } else
        if (DumpDex[0] == 0 || DumpDex[0] != 100) {
        console.warn("[*] Wiped Header , classes" + Count + ".dex is Interesting Dex.");
        console.error("[Dex"+Count +"] : "+Path);
        WriteDex(Count, Buf, Path, 0);
    } else {
        WriteDex(Count, Buf, Path, 1);
    }
}
function WriteDex(Count, Buffer, Path, Flag) {
    let DexFD = new File(Path, "wb");
    DexFD.write(Buffer)
    DexFD.flush();
    DexFD.close();
    if (Flag == 0) {
        console.warn("[Dex"+Count +"] : "+Path);
    } else {
        console.log("[Dex"+Count +"] : "+Path);
    }
}
function findDefineClass(libart) {
    let addr_DefineClass = null;

    function search(target, type) {
        for (const item of target) {
            let name = item.name;
            if (name.includes("ClassLinker") &&
                name.includes("DefineClass") &&
                name.includes("Thread") &&
                name.includes("DexFile")) {
                addr_DefineClass = item.address;
                console.warn(`[*] Found DefineClass in ${type}: ${addr_DefineClass}`);
                return true;
            }
        }
        return false;
    }
    if (search(libart.enumerateSymbols(), "Symbols")) return addr_DefineClass;
    if (search(libart.enumerateImports(), "Imports")) return addr_DefineClass;
    if (search(libart.enumerateExports(), "Exports")) return addr_DefineClass;
    console.error("[*] DefineClass Symbols, Imports, and Exports not found in libart.so.");
    return null;
}
function Dump_Dex() {
    let libart = Process.findModuleByName("libart.so");
    if (!libart) {
        console.error("[*] libart.so not found.");
        return;
    }
    console.warn("[*] libart.so found at: " + libart.base);
    let addr_DefineClass = findDefineClass(libart);
    let dex_maps = {};
    let dex_count = 1;
    if (addr_DefineClass) {
        Interceptor.attach(addr_DefineClass, {
            onEnter: function(args) {
                let dex_file = args[5];
                let base = ptr(dex_file).add(Process.pointerSize).readPointer();
                let size = ptr(dex_file).add(Process.pointerSize + Process.pointerSize).readUInt();
                if (dex_maps[base] == undefined) {
                    dex_maps[base] = size;
                    let dex_dir_path = `${SAFE_DIR}`;
                    let dex_path = dex_dir_path + "classes" + dex_count + ".dex";
                    dex_count++;
                    let count_dex = dex_count;
                    let count = count_dex -1;
                    let dex_buffer = ptr(base).readByteArray(size);
                    ProcessDex(dex_buffer, dex_count, dex_path);
                }
            },
            onLeave: function(retval) {}
        });
    }
}
async function main() {
    await hookDlopen();
    console.warn("[*] Hooking finished. Proceeding to dump...");
    Dump_Dex();
}
setTimeout(main, 100);
