/*
Hook fork to prevent child processes from interrupting Frida
Returns -1 with errno EPERM
*/
(() => {
    const forkSymbol = Module.findExportByName(null, "fork");
    if (!forkSymbol) {
        console.warn("[-] fork() not found");
        return;
    }
    const errnoPtr = (() => {
        const errnoLocation = Module.findExportByName(null, "__errno_location");
        return errnoLocation ? new NativeFunction(errnoLocation, "pointer", [])() : null;
    })();

    const safeForkHandler = new NativeCallback(() => {
        console.warn("[!] Fork intercepted - returning -1 (EPERM)");
        if (errnoPtr) errnoPtr.writeS32(1);
        return -1;
    }, 'int', []);

    Interceptor.replace(forkSymbol, safeForkHandler);
    console.warn("[+] Fork hook: ACTIVE");
})();

/* Enter your target package name here */
const TARGET_PKG = "com.dexprotector.detector.envchecks";
const SAFE_DIR = `/data/data/${TARGET_PKG}/`;
const DETECTION_LIBRARIES = [
    { pattern: "libdexprotector", message: "DexProtector: https://licelus.com" },
    { pattern: "libjiagu", message: "Jiagu360: https://jiagu.360.cn" },
    { pattern: "libAppGuard", message: "AppGuard: http://appguard.nprotect.com" },
    { pattern: "libDexHelper", message: "Secneo: http://www.secneo.com" },
    { pattern: "libsecexe|libsecmain|libSecShell", message: "Bangcle: https://github.com/woxihuannisja/Bangcle" },
    { pattern: "libprotectt|libapp-protectt", message: "Protectt: https://www.protectt.ai" },
    { pattern: "libkonyjsvm", message: "Kony: http://www.kony.com/" },
    { pattern: "libnesec", message: "Yidun: https://dun.163.com/product/app-protect" },
    { pattern: "libcovault", message: "AppSealing: https://www.appsealing.com/" },
    { pattern: "libpairipcore", message: "Pairip: https://github.com/rednaga/APKiD/issues/329" }
];

function hookDlopen() {
    return new Promise((resolve, reject) => {
        try {
            const isArm = Process.arch === "arm" ? "linker" : "linker64";
            const reg = Process.arch === "arm" ? "r0" : "x0";
            const linker = Process.findModuleByName(isArm);

            if (!linker) {
                reject(new Error("Linker module not found"));
                return;
            }

            let resolved = false;
            const resolveOnce = () => {
                if (!resolved) {
                    resolved = true;
                    resolve();
                }
            };

            const sym = linker.enumerateExports().find(e => e.name.includes('android_dlopen_ext'));
            Interceptor.attach(sym.address, {
                onEnter(args) {
                    const libPath = this.context[reg].readUtf8String();
                    if (!libPath) return;

                    for (const { pattern, message } of DETECTION_LIBRARIES) {
                        if (new RegExp(pattern).test(libPath)) {
                            console.warn(`\n[*] Packer Detected: ${message}`);
                            resolveOnce();
                            return;
                        }
                    }
                }
            });
            setTimeout(resolveOnce, 3000);
        } catch (e) {
            reject(new Error("Unsupported architecture/emulator"));
        }
    });
}

function processDex(Buf, C, Path) {
    // Convert to Uint8Array if not already
    const DumpDex = Buf instanceof Uint8Array ? Buf : new Uint8Array(Buf);
    const Count = C - 1;
    // CDEX detection (cdex001)
    if (DumpDex[0] === 99 &&
        DumpDex[1] === 100 &&
        DumpDex[2] === 101 &&
        DumpDex[3] === 120 &&
        DumpDex[4] === 48 &&
        DumpDex[5] === 48 &&
        DumpDex[6] === 49) {
        console.warn("[*]  classes" + Count + ".dex is CDex. Ignore It.");
        return;
    }
    // Empty header detection (Dexprotector style)
    if (DumpDex[0] === 0 &&
        DumpDex[1] === 0 &&
        DumpDex[2] === 0 &&
        DumpDex[3] === 0 &&
        DumpDex[7] === 0) {
        console.warn("[*] 00000 Header. Probably classes" + Count + ".dex is Dexprotector's Dex.");
        writeDexFile(Count, Buf, Path, 0);
        return;
    }
    // Wiped or invalid header detection
    if (DumpDex[0] === 0 &&
        DumpDex[0] !== 100) {
        console.warn("[*] Wiped Header , classes" + Count + ".dex is Interesting Dex.");
        writeDexFile(Count, Buf, Path, 0);
        return;
    }
    // Default case: normal dex
    writeDexFile(Count, Buf, Path, 1);
}

function writeDexFile(count, buffer, path, isValid) {
    const file = new File(path, "wb");
    file.write(buffer);
    file.close();
    const log = isValid ? console.log : console.warn;
    log(`[Dex${count}] ${path} ${isValid ? '(valid)' : '(modified)'}`);
}

function findDefineClass(libart) {
    const matcher = /ClassLinker.*DefineClass.*Thread.*DexFile/;
    const search = (items, type) => items.find(item => matcher.test(item.name))?.address;

    return search(libart.enumerateSymbols(), 'symbols') ||
           search(libart.enumerateImports(), 'imports') ||
           search(libart.enumerateExports(), 'exports');
}

function dumpDex() {
    const libart = Process.findModuleByName("libart.so");
    if (!libart) return console.error("[!] libart.so not found");

    const defineClassAddr = findDefineClass(libart);
    console.warn("[*] DefineClass found at :", defineClassAddr);
    if (!defineClassAddr) return console.error("[!] DefineClass not found");

    const seenDex = new Set();
    let dexCount = 1;

    Interceptor.attach(defineClassAddr, {
        onEnter(args) {
            const dexFilePtr = args[5];
            const base = dexFilePtr.add(Process.pointerSize).readPointer();
            const size = dexFilePtr.add(Process.pointerSize * 2).readUInt();

            if (seenDex.has(base.toString())) return;
            seenDex.add(base.toString());

            const dexBuffer = base.readByteArray(size);
            if (!dexBuffer || dexBuffer.byteLength !== size) return;

            const path = `${SAFE_DIR}classes${dexCount}.dex`;
            processDex(dexBuffer, dexCount++, path);
        }
    });
}

async function main() {
    try {
        await hookDlopen();
        console.warn("[*] Hooking Finished. Starting dex dump...");
        dumpDex();
    } catch (e) {
        console.error(`[!] Error: ${e.message}`);
    }
}

setImmediate(main);
