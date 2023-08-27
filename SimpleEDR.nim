# Compile: nim c --app=lib --nomain SimpleEDR.nim

import winim/com
import std/[strutils, strformat]


type
    HookStructure = object
        sFunctionToHook : string
        pFunctionToHook : LPVOID
        pFunctionToRun  : LPVOID
        pOriginalBytes  : array[16, byte]
        pModifiedBytes  : seq[byte]
        dwOldProtection : DWORD


var 
    TRAMPOLINE_SIZE: DWORD
    uTrampoline: seq[byte]
    st: HookStructure


if defined(amd64):
    TRAMPOLINE_SIZE = 13
    uTrampoline = @[
            byte(0x49), byte(0xBA), byte(0x00), byte(0x00), byte(0x00), byte(0x00), byte(0x00), byte(0x00), byte(0x00),byte(0x00), # mov r10, pFunctionToRun
            byte(0x41), byte(0xFF),byte(0xE2)                                                                                      # jmp r10
        ]

elif defined(i386):
    TRAMPOLINE_SIZE = 7
    uTrampoline = @[
            byte(0xB8), byte(0x00), byte(0x00), byte(0x00), byte(0x00), # mov eax, pFunctionToRun
            byte(0xFF), byte(0xE0)                                      # jmp eax
        ]


proc InitializeHookStruct(sFunctionToHook: string, pFunctionToHook: LPVOID, pFunctionToRun: LPVOID, buffer: ptr HookStructure): bool=
    var
        bytesInstruction: array[16, byte]
        bytesRead: SIZE_T
        i=0

    # Filling up the struct
    buffer.sFunctionToHook  = sFunctionToHook
    buffer.pFunctionToHook  = pFunctionToHook
    buffer.pFunctionToRun   = pFunctionToRun
    buffer.pModifiedBytes   = uTrampoline

    # Save original bytes of the same size that we will overwrite (that is TRAMPOLINE_SIZE)
    # This is done to be able to do cleanups when done
    ReadProcessMemory(GetCurrentProcess(), pFunctionToHook, &bytesInstruction, TRAMPOLINE_SIZE, &bytesRead)
    while i < TRAMPOLINE_SIZE:
        buffer.pOriginalBytes[i] = bytesInstruction[i]
        i+=1
    i=0


    # Changing the protection to RWX so that we can modify the bytes
    # We are saving the old protection to the struct (to re-place it at cleanup)
    if (VirtualProtect(buffer.pFunctionToHook, TRAMPOLINE_SIZE, PAGE_EXECUTE_READWRITE, &buffer.dwOldProtection)):
        echo fmt"[+] Function to hook:              {buffer.sFunctionToHook}"
        echo fmt"[+] Address to hook:               {buffer.pFunctionToHook.repr}"
        echo fmt"[+] Address to run:                {buffer.pFunctionToRun.repr}"
        echo fmt"[+] Original protection:           {buffer.dwOldProtection}"

        write(stdout, "[+] Original bytes:                ")
        while i < TRAMPOLINE_SIZE:
            write(stdout, "\\x" & buffer.pOriginalBytes[i].toHex)
            i+=1
        i=0
        echo ""

        write(stdout, "[+] Modified bytes:                ")
        while i < TRAMPOLINE_SIZE:
            write(stdout, "\\x" & buffer.pModifiedBytes[i].toHex)
            i+=1
        i=0
        echo "\n"

        return true
    else:
        return false


proc InstallHook(buffer: ptr HookStructure): bool=
    if defined(amd64):
        var uPatch: uint64 = cast[uint64](buffer.pFunctionToRun)
        copyMem(&uTrampoline[2], &uPatch, sizeof(uPatch)) # copying the address to the offset '2' in uTrampoline

    elif defined(i386):
        var uPatch: uint32 = cast[uint32](buffer.pFunctionToRun)
        copyMem(&uTrampoline[1], &uPatch, sizeof(uPatch)) # copying the address to the offset '1' in uTrampoline

    copyMem(buffer.pFunctionToHook, addr uTrampoline[0], TRAMPOLINE_SIZE) # Placing the trampoline function - installing the hook

    echo fmt"[+] {buffer.sFunctionToHook} is now hooked !"
    return true


proc RemoveHook(buffer: ptr HookStructure): bool=
    var
        dwOldProtection: DWORD
        bytesInstruction: array[16, byte]
        bytesRead: SIZE_T
        i=0

    copyMem(buffer.pFunctionToHook, addr buffer.pOriginalBytes, TRAMPOLINE_SIZE) # Copying the original bytes over
    write(stdout, "[+] Original bytes reverted to:    ")
    ReadProcessMemory(GetCurrentProcess(), buffer.pFunctionToHook, &bytesInstruction, TRAMPOLINE_SIZE, &bytesRead)
    while i < TRAMPOLINE_SIZE:
        write(stdout, "\\x" & bytesInstruction[i].toHex)
        i+=1

    if (VirtualProtect(buffer.pFunctionToHook, TRAMPOLINE_SIZE, buffer.dwOldProtection, &dwOldProtection)): # Setting the old memory protection back to what it was before hooking
        echo "\n[+] Original memory protection back"

    echo "[+] Hook removed !"

    return true


proc myMessageBox(): void=
    MessageBoxW(0, "VirtualProtectEx Hooked ! Process killed.", "Hooked !", MB_ICONWARNING)
    
    var hProcess = OpenProcess(PROCESS_TERMINATE, false, GetCurrentProcessId())
    if TerminateProcess(hProcess, 0):
        discard
    else:
        echo "[-] Failed to terminate process"


proc NimMain() {.cdecl, importc.}


proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : BOOL {.stdcall, exportc, dynlib.} =
    NimMain()
  

    if fdwReason == DLL_PROCESS_ATTACH:
        var
            # Don't work, why ? I don't know
            #[functionToHook: string = "NtProtectVirtualMemory"
            addressToHook: LPVOID = cast[LPVOID](GetProcAddress(GetModuleHandleA("ntdll.dll"), functionToHook))]#

            functionToHook: string = "VirtualProtectEx"
            addressToHook: LPVOID = cast[LPVOID](GetProcAddress(GetModuleHandleA("kernel32.dll"), functionToHook))
            addressToRun: LPVOID = cast[LPVOID](myMessageBox)

        if(InitializeHookStruct(functionToHook, addressToHook, addressToRun, addr st)):
            discard
        else:
            echo "[-] Failed to initialize structure"
            quit(0)

        if(InstallHook(st)):
            discard
        else:
            echo fmt"[-] Failed to hook {functionToHook}"
            quit(0)


    if fdwReason == DLL_PROCESS_DETACH:
        if RemoveHook(st):
            discard
        else:
            echo "[-] Failed to remove hook"
            quit(0)

    return true