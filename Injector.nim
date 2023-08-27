import winim
import std/strformat
from os import fileExists

import std/parseopt
from strutils import parseint


var
    doc = """
SimpleEDR Injector

Usage:
    Injector.exe -d=c:\\SimpleEDR.dll [-p=ChangeMemoryProtection.exe]
    Injector.exe (-h | --help)

Options:
    -h --help           Show this screen
    -d --dll-path       Full EDR DLL path to be injected
    -p --process-name   Process name to inject EDR DLL
"""
    argCtr: int
    dllName         : string = ""
    processToInject : string = ""


 # Loop trough all arguments
for kind, key, value in getOpt():
    case kind

    # Positional arguments
    of cmdArgument:
        echo "[-] Unknown argument: ", argCtr, ": \"", key, "\""
        argCtr.inc
        quit(0)

    # Switches
    of cmdLongOption, cmdShortOption:
        case key
        of "h", "help":
            echo doc
            quit(0)
        of "d", "dll-path":
            dllName = value
        of "p", "process-name":
            processToInject = value
        else:
            echo "[-] Unknown option: ", key
            quit(0)

    of cmdEnd:
      discard


# Overload $ proc to allow string conversion of szExeFile
proc `$`(a: array[MAX_PATH, WCHAR]): string = $cast[WideCString](unsafeAddr a[0])


proc CheckEDRLoaded(dwPID: DWORD, dllName: string): bool=
    var 
        hModuleSnap = INVALID_HANDLE_VALUE
        me32        : MODULEENTRY32
        all_modules : seq[string]

    me32.dwSize = cast[DWORD](sizeof(MODULEENTRY32))
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID)
    if hModuleSnap == INVALID_HANDLE_VALUE:
        return
    defer: CloseHandle(hModuleSnap)

    if Module32First(hModuleSnap, addr me32):
        while Module32Next(hModuleSnap, addr me32):
            all_modules.add($me32.szExePath)

    for i in all_modules:
        if i == dllName:
            return true

    return false


proc InjectDLL(pid: DWORD, dllName: LPWSTR): bool=
    var
       dwSizeToWrite            : DWORD   = 512
       lpNumberOfBytesWritten   : SIZE_T
       threadId                 : DWORD

    let hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
    let pLoadLibraryW = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW")
    let pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
    WriteProcessMemory(hProcess, pAddress, dllName, dwSizeToWrite, &lpNumberOfBytesWritten)
    let hThread = CreateRemoteThread(hProcess, NULL, 0, cast[LPTHREAD_START_ROUTINE](pLoadLibraryW), pAddress,  0,  &threadId)

    defer: CloseHandle(hProcess)
    defer: CloseHandle(hThread)

    return true



proc MonitorRunningProcess(processToInject: string): void=
    var
        processSeq: seq[PROCESSENTRY32W]
        processSingle: PROCESSENTRY32
    
    let 
        hProcessSnap  = CreateToolhelp32Snapshot(0x00000002, 0)

    processSingle.dwSize = sizeof(PROCESSENTRY32).DWORD
    
    if bool(Process32First(hProcessSnap, processSingle.addr)):
        while bool(Process32Next(hProcessSnap, processSingle.addr)):
            processSeq.add(processSingle)
    CloseHandle(hProcessSnap) 

    for processSingle in processSeq:
        if $processSingle.szExeFile == processToInject:
            if CheckEDRLoaded(processSingle.th32ProcessID, dllName):
                continue
            else:
                # Inject DLL into remote process
                if InjectDLL(processSingle.th32ProcessID, winstrConverterStringToLPWSTR(dllName)):
                    echo fmt"[+] SimpleEDR injected into PID: {processSingle.th32ProcessID}"
                else:
                    echo "[-] Failed to inject SimpleEDR"


when isMainModule:
    # Check DLL path
    if fileExists(dllName):
        discard
    else:
        echo "[-] DLL path not found"
        quit(0)

    # Inject DLL into this current process
    if processToInject == "":
        if InjectDLL(GetCurrentProcessId(), winstrConverterStringToLPWSTR(dllName)):
            echo fmt"[+] SimpleEDR injected into PID: {GetCurrentProcessId()}"
            echo ""
        else:
            echo "[-] Failed to inject SimpleEDR"
            quit(0)

        Sleep(1000)
        let rPtr = VirtualAlloc( nil, 1024, MEM_COMMIT, PAGE_READWRITE)
        var oldProtection: DWORD
        VirtualProtectEx(GetCurrentProcess(), rPtr, 1024, PAGE_EXECUTE_READ, &oldProtection) # Hooked
        echo "\n[+] Protection changed to RX\n"
        quit(0)


    # Inject DLL into every processToInject process
    while true:
        MonitorRunningProcess(processToInject)
        Sleep(200)