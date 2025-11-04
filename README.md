# tenet_tracer

A Pin Tool for tracing instructions specifically for [tenet]
A special thank you to [hasherezade](https://github.com/hasherezade)'s [tiny_tracer](https://github.com/hasherezade/tiny_tracer) of which that tool is generously ripped from.

+ API calls, including [parameters of selected functions](https://github.com/hasherezade/tenet_tracer/wiki/Tracing-parameters-of-functions)
+ selected instructions: [RDTSC](https://c9x.me/x86/html/file_module_x86_id_278.html), [CPUID](https://c9x.me/x86/html/file_module_x86_id_45.html), [INT](https://c9x.me/x86/html/file_module_x86_id_142.html)
+ [inline system calls, including parameters of selected syscalls](https://github.com/hasherezade/tenet_tracer/wiki/Tracing-syscalls)
+ transition between sections of the traced module (helpful in finding OEP of the packed module)

Bypasses the anti-tracing check based on RDTSC.

Generates a report in a `.tag` format (which can be [loaded into other analysis tools](https://github.com/hasherezade/tenet_tracer/wiki/Using-the-TAGs-with-disassemblers-and-debuggers)):

```txt
RVA;traced event
```

i.e.

```txt
345c2;section: .text
58069;called: C:\Windows\SysWOW64\kernel32.dll.IsProcessorFeaturePresent
3976d;called: C:\Windows\SysWOW64\kernel32.dll.LoadLibraryExW
3983c;called: C:\Windows\SysWOW64\kernel32.dll.GetProcAddress
3999d;called: C:\Windows\SysWOW64\KernelBase.dll.InitializeCriticalSectionEx
398ac;called: C:\Windows\SysWOW64\KernelBase.dll.FlsAlloc
3995d;called: C:\Windows\SysWOW64\KernelBase.dll.FlsSetValue
49275;called: C:\Windows\SysWOW64\kernel32.dll.LoadLibraryExW
4934b;called: C:\Windows\SysWOW64\kernel32.dll.GetProcAddress
...
```

## 🚧 How to build

### On Windows

To compile the prepared project you need to use [Visual Studio >= 2012](https://visualstudio.microsoft.com/downloads/), but lower than 2022. It was tested with [Intel Pin 3.30](https://software.intel.com/en-us/articles/pin-a-binary-instrumentation-tool-downloads).

Clone this repo into `\source\tools` that is inside your Pin root directory. Open the project in Visual Studio and build. Detailed description available [here](https://github.com/hasherezade/tenet_tracer/wiki/Installation#on-windows).

To build with Intel Pin < 3.26 on Windows, use the appropriate legacy Visual Studio project.

## WARNINGS

+ In order for Pin to work correctly, Kernel Debugging must be **DISABLED**.
+ In [`install32_64`](./install32_64) you can find a utility that checks if Kernel Debugger is disabled (`kdb_check.exe`, [source](https://github.com/hasherezade/pe_utils/tree/master/kdb_check)), and it is used by the Tenet Tracer's `.bat` scripts. This utilty sometimes gets flagged as a malware by Windows Defender (it is a known false positive). If you encounter this issue, you may need to [exclude](https://support.microsoft.com/en-us/windows/add-an-exclusion-to-windows-security-811816c0-4dfd-af4a-47e4-c301afe13b26) the installation directory from Windows Defender scans.
+ Since the version 3.20 Pin has dropped a support for **old versions of Windows**. If you need to use the tool on Windows < 8, try to compile it with Pin 3.19.
