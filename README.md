# SimpleEDR

[![Nim Version](https://img.shields.io/badge/nim-2.0.0-orange.svg)](https://nim-lang.org/)

SimpleEDR aims to simulate and explore the operation of an Endpoint Detection and Response (EDR), focusing on the API Hooking technique under the Windows environment.

One of the key features of an EDR is API Hooking, which monitors and intercepts Windows APIs calls. This technique is widely used to detect malicious behavior in real time, by observing interactions between applications and the system. SimpleEDR implements a simulation of this technique, by placing a hook on VirtualProtectEx (easily modifiable).

The aim of this project is to understand how EDRs implement this technique, and then to test different bypass methods.


# Usage
- Compilation
  - Linux
    ```
    nim --os:windows --cpu:amd64 --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc c Injector.nim
    nim --os:windows --cpu:amd64 --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc c ChangeMemoryProtection.nim
    nim --os:windows --cpu:amd64 --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc --app=lib --nomain c SimpleEDR.nim
    ```
  - Windows
    ```
    nim c NimBlackout.nim
    nim c ChangeMemoryProtection.nim
    nim c --app=lib --nomain SimpleEDR.nim
    ```
- Self-inject
  ```
  Injector.exe -d:"C:\tools\SimpleEDR\SimpleEDR.dll"
  ```
- Inject into specific process (continuous monitoring)
    - Launch Injector.exe that inject SimpleEDR.dll into specific process (in this case: ChangeMemoryProtection.exe)
      ```
      Injector.exe -d:"C:\tools\SimpleEDR\SimpleEDR.dll -p:"ChangeMemoryProtection.exe""
      ```
    - Launch specific process (in this case: ChangeMemoryProtection.exe)
      ```
      ChangeMemoryProtection.exe
      ```


# Demo
![](https://github.com/Helixo32/SimpleEDR/blob/main/DemoSimpleEDR.gif)
