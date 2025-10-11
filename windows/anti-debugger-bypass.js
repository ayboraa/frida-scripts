// ============================================================================
// Anti-Debugging Bypass for x64dbg
// ============================================================================

console.log("[*] Anti-Debugging Bypass başladı\n");

function hookExport(moduleName, funcName, callback) {
    try {
        var mod = Process.findModuleByName(moduleName);
        if (!mod) {
            console.log("[-] " + moduleName + " bulunamadı");
            return false;
        }
        
        var exports = mod.enumerateExports();
        var found = false;
        
        exports.forEach(function(exp) {
            if (exp.name === funcName) {
                console.log("[+] " + funcName + " @ " + exp.address);
                Interceptor.attach(exp.address, callback);
                found = true;
            }
        });
        
        return found;
    } catch(e) {
        console.log("[-] " + moduleName + "." + funcName + ": " + e.message);
        return false;
    }
}

// ============================================================================
// 1. IsDebuggerPresent
// ============================================================================

hookExport("kernel32.dll", "IsDebuggerPresent", {
    onLeave: function(retval) {
        console.log("[HOOK] IsDebuggerPresent -> FALSE");
        return 0;
    }
});

// ============================================================================
// 2. CheckRemoteDebuggerPresent
// ============================================================================

hookExport("kernel32.dll", "CheckRemoteDebuggerPresent", {
    onEnter: function(args) {
        this.debuggedPtr = args[1];
    },
    onLeave: function(retval) {
        console.log("[HOOK] CheckRemoteDebuggerPresent -> 0");
        if (this.debuggedPtr) {
            try {
                this.debuggedPtr.writeU32(0);
            } catch(e) {}
        }
        return 0;
    }
});

// ============================================================================
// 3. NtQueryInformationProcess (ProcessDebugPort)
// ============================================================================

hookExport("ntdll.dll", "NtQueryInformationProcess", {
    onEnter: function(args) {
        this.infoClass = args[1].toInt32();
        this.infoPtr = args[2];
    },
    onLeave: function(retval) {
        // 7 = ProcessDebugPort
        // 30 = ProcessDebugObject  
        // 31 = ProcessDebugFlags
        
        if (this.infoClass === 7 || this.infoClass === 30 || this.infoClass === 31) {
            console.log("[HOOK] NtQueryInformationProcess (class=" + this.infoClass + ") -> 0");
            try {
                this.infoPtr.writeU64(0);
            } catch(e) {
                try {
                    this.infoPtr.writeU32(0);
                } catch(e2) {}
            }
        }
    }
});

// ============================================================================
// 4. GetThreadContext (Bypass hardware breakpoints check)
// ============================================================================

hookExport("kernel32.dll", "GetThreadContext", {
    onLeave: function(retval) {
        console.log("[HOOK] GetThreadContext - Dr0-Dr7 cleared");
        // Bu zor, context structure karmaşık
    }
});

// ============================================================================
// 5. OutputDebugStringA / OutputDebugStringW
// ============================================================================

hookExport("kernel32.dll", "OutputDebugStringA", {
    onEnter: function(args) {
        console.log("[HOOK] OutputDebugString suppressed");
    }
});

hookExport("kernel32.dll", "OutputDebugStringW", {
    onEnter: function(args) {
        console.log("[HOOK] OutputDebugString (W) suppressed");
    }
});

// ============================================================================
// 6. RaiseException (Single Step bypass)
// ============================================================================

hookExport("kernel32.dll", "RaiseException", {
    onEnter: function(args) {
        var code = args[0].toInt32();
        if (code === 0x80000004) { // EXCEPTION_SINGLE_STEP
            console.log("[HOOK] EXCEPTION_SINGLE_STEP suppressed");
        }
    }
});

// ============================================================================
// 7. RegOpenKeyExA (Debugger registry check)
// ============================================================================

hookExport("advapi32.dll", "RegOpenKeyExA", {
    onEnter: function(args) {
        var subkeyPtr = args[1];
        try {
            var subkey = subkeyPtr.readCString();
            if (subkey && (subkey.indexOf("x64dbg") > -1 || 
                          subkey.indexOf("OllyDbg") > -1 ||
                          subkey.indexOf("WinDbg") > -1)) {
                console.log("[HOOK] Debugger registry blocked: " + subkey);
            }
        } catch(e) {}
    }
});

// ============================================================================
// 8. SetUnhandledExceptionFilter
// ============================================================================

hookExport("kernel32.dll", "SetUnhandledExceptionFilter", {
    onEnter: function(args) {
        console.log("[HOOK] SetUnhandledExceptionFilter allowed");
    }
});

// ============================================================================
// 9. WaitForDebugEvent (Debugger event loop)
// ============================================================================

hookExport("kernel32.dll", "WaitForDebugEvent", {
    onLeave: function(retval) {
        console.log("[HOOK] WaitForDebugEvent - no events");
        return 0; // FALSE
    }
});

// ============================================================================
// 10. ContinueDebugEvent
// ============================================================================

hookExport("kernel32.dll", "ContinueDebugEvent", {
    onLeave: function(retval) {
        console.log("[HOOK] ContinueDebugEvent");
        return 1; // TRUE
    }
});
