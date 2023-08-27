import winim/lean

proc HookTest(): void =
    Sleep(1000)

    let rPtr = VirtualAlloc( nil, 1024, MEM_COMMIT, PAGE_READWRITE)
    var oldProtection: DWORD
    VirtualProtectEx(GetCurrentProcess(), rPtr, 1024, PAGE_EXECUTE_READ, &oldProtection) # Hooked
    
    MessageBoxA(0, "VirtualProtectEx hook bypassed !", "Congrats !", 0)
    quit(0)


when isMainModule:
        HookTest()