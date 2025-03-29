/*
Fork hook needed in case process spawn child process
which causes frida to terminate. Return -1 only when you feel need of it.
*/

const fork_ptr = Module.getExportByName(null, "fork");
const fork = new NativeFunction(fork_ptr, 'int', []);
Interceptor.replace(fork_ptr, new NativeCallback(function() {
    console.warn("Fork Found and Replaced");
    //return fork()
    return -1;
}, "int", []));

// Enter your package name here
let Pro = "com.dexprotector.detector.envchecks"

let Color = {
    RESET: "\x1b[39;49;00m",
    Black: "0;01",
    Blue: "4;01",
    Cyan: "6;01",
    Gray: "7;11",
    Green: "2;01",
    Purple: "5;01",
    Red: "1;01",
    Yellow: "3;01",
    Light: {
        Black: "0;11",
        Blue: "4;11",
        Cyan: "6;11",
        Gray: "7;01",
        Green: "2;11",
        Purple: "5;11",
        Red: "1;11",
        Yellow: "3;11"
    }
};
let LOG = function(input, kwargs) {
    kwargs = kwargs || {};
    let logLevel = kwargs['l'] || 'log',
    colorPrefix = '\x1b[3',
    colorSuffix = 'm';
    if (typeof input === 'object') input = JSON.stringify(input, null, kwargs['i'] ? 2: null);
    if (kwargs['c']) input = colorPrefix + kwargs['c'] + colorSuffix + input + Color.RESET;
    console[logLevel](input);
};

function Blue(str) { LOG(str, { c: Color.Blue }); }
function Green(str) { LOG(str, { c: Color.Green }); }
function Purple(str) { LOG(str, { c: Color.Purple }); }
function Red(str) { LOG(str, { c: Color.Red }); }
function Yellow(str) { LOG(str, { c: Color.Yellow }); }

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
            setInterval(() => {
                if (!hooked) clearInterval(); resolve();
            }, 1000);

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
        console.warn("[*]  classes" + Count + ".dex is CDex. Ignore It.");
    } else
        if (DumpDex[0] == 0 && DumpDex[1] == 0 && DumpDex[2] == 0 && DumpDex[3] == 0 && DumpDex[4] == 0 && DumpDex[5] == 0 && DumpDex[6] == 0) {
        console.warn("[*] 0000000 Header. Probably classes" + Count + ".dex is Dexprotector's Dex.");
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
                    let dex_dir_path = "/storage/emulated/0/Android/data/" + Pro + "/";
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
setImmediate(main);
