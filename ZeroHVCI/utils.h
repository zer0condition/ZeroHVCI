#pragma once
#define RVATOVA(_base_, _offset_) ((PUCHAR)(_base_) + (ULONG)(_offset_))

DWORD_PTR m_KernelAddr = NULL;
PVOID m_KernelImage = NULL;

bool MatchSign(PUCHAR Data, PUCHAR Sign, int Size)
{
    for (int i = 0; i < Size; i++) {
        if (Sign[i] == 0xff) {
            continue;
        }
        if (Sign[i] != Data[i]) {
            return false;
        }
    }
    return true;
}

ULONG64 GetKernelObject(ULONG TargetProcessId, HANDLE TargetHandle)
{
    NTSTATUS Status = 0;
    ULONG64 Result = 0;

    PSYSTEM_HANDLE_INFORMATION pHandleInfo = nullptr;
    ULONG ulBytes = 0;

    while ((Status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)16, pHandleInfo, ulBytes, &ulBytes)) == 0xC0000004L)
    {
        if (pHandleInfo != nullptr)
        {
            pHandleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pHandleInfo, (size_t)2 * ulBytes));
        }
        else
        {
            pHandleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size_t)2 * ulBytes));
        }
    }

    if (Status != 0) {
        goto done;
    }

    for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; i++)
    {
        if ((pHandleInfo->Handles[i].UniqueProcessId == TargetProcessId) && (pHandleInfo->Handles[i].HandleValue == reinterpret_cast<USHORT>(TargetHandle)))
        {
            Result = reinterpret_cast<ULONG64>(pHandleInfo->Handles[i].Object);
            break;
        }
    }

done:
    if (pHandleInfo != nullptr)
    {
        HeapFree(GetProcessHeap(), 0, pHandleInfo);
    }

    return Result;
}

PVOID GetSystemInformation(SYSTEM_INFORMATION_CLASS InfoClass)
{
    NTSTATUS Status = 0;
    ULONG RetSize = 0, Size = 0x100;
    PVOID Info = NULL;

    while (true) {
        RetSize = 0;

        if ((Info = LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, Size)) == NULL) {
            return NULL;
        }

        if ((Status = NtQuerySystemInformation(InfoClass, Info, Size, &RetSize)) == STATUS_INFO_LENGTH_MISMATCH) {
            LocalFree(Info);

            Size = RetSize + 0x100;
        }
        else {
            break;
        }
    }

    if (!NT_SUCCESS(Status)) {
        if (Info) {
            LocalFree(Info);
        }
        return NULL;
    }

    return Info;
}

DWORD GetThreadState(DWORD dwProcessId, DWORD dwThreadId)
{
    DWORD Ret = -1;

    PKSYSTEM_PROCESS_INFORMATION ProcessInfo =
        (PKSYSTEM_PROCESS_INFORMATION)GetSystemInformation(SystemProcessInformation);

    if (ProcessInfo) {
        PKSYSTEM_PROCESS_INFORMATION Info = ProcessInfo;

        while (true) {
            if (Info->UniqueProcessId == (HANDLE)dwProcessId) {
                for (DWORD i = 0; i < Info->NumberOfThreads; i++) {
                    if (Info->Threads[i].ClientId.UniqueThread == (HANDLE)dwThreadId) {
                        Ret = Info->Threads[i].ThreadState;
                        goto _end;
                    }
                }
                break;
            }
            if (Info->NextEntryOffset == 0) {
                break;
            }
            Info = (PKSYSTEM_PROCESS_INFORMATION)RVATOVA(Info, Info->NextEntryOffset);
        }
    _end:
        LocalFree(ProcessInfo);
    }

    return Ret;
}

PVOID GetObjectAddress(HANDLE hObject)
{
    PVOID Ret = NULL;

    PSYSTEM_HANDLE_INFORMATION HandleInfo =
        (PSYSTEM_HANDLE_INFORMATION)GetSystemInformation((SYSTEM_INFORMATION_CLASS)16);

    if (HandleInfo) {
        for (DWORD i = 0; i < HandleInfo->NumberOfHandles; i++) {
            if (HandleInfo->Handles[i].UniqueProcessId == GetCurrentProcessId() &&
                HandleInfo->Handles[i].HandleValue == (USHORT)hObject) {
                Ret = HandleInfo->Handles[i].Object;
                break;
            }
        }

        LocalFree(HandleInfo);
    }

    return Ret;
}

PVOID GetKernelModule(const char* DriverName)
{
    LPVOID driverList[1024];
    DWORD needed;

    if (EnumDeviceDrivers(driverList, sizeof(driverList), &needed)) {
        int numDrivers = needed / sizeof(LPVOID);

        // Iterate through the list of drivers.
        for (int i = 0; i < numDrivers; ++i) {
            char driverPath[MAX_PATH];
            if (GetDeviceDriverBaseNameA(driverList[i], driverPath, sizeof(driverPath))) {
                if (strcmp(driverPath, DriverName) == 0) {
                    return driverList[i];
                }
            }
        }
    }

    return 0;
}

bool GetKernelImageInfo(PVOID* pImageAddress, PDWORD pdwImageSize, char* lpszName)
{
    PRTL_PROCESS_MODULES Info = (PRTL_PROCESS_MODULES)GetSystemInformation((SYSTEM_INFORMATION_CLASS)11);
    if (Info && Info->NumberOfModules > 0) {
        PRTL_PROCESS_MODULE_INFORMATION Module = &Info->Modules[0];

        *pImageAddress = Module->ImageBase;
        *pdwImageSize = Module->ImageSize;

        strcpy_s(lpszName, MAX_PATH, (char*)(Module->FullPathName + Module->OffsetToFileName));

        LocalFree(Info);

        return true;
    }

    return false;
}

bool GetSyscallNumber(const char* lpszProcName, PDWORD pdwRet)
{
    HMODULE hImage = GetModuleHandleA("ntdll.dll");
    if (hImage == NULL) {
        return false;
    }

    PUCHAR Addr = (PUCHAR)GetProcAddress(hImage, lpszProcName);
    if (Addr == NULL) {
        return false;
    }

    if (*(Addr + 3) == 0xb8) {
        *pdwRet = *(PDWORD)(Addr + 4);
        return true;
    }

    return false;
}

DWORD LdrGetProcAddress(PVOID Image, const char* lpszName)
{
    auto pHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(RVATOVA(
        Image, reinterpret_cast<PIMAGE_DOS_HEADER>(Image)->e_lfanew));

    DWORD addr = 0;
    DWORD exportAddr = pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exportSize = pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if (exportAddr != 0) {
        auto pExport = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(RVATOVA(Image, exportAddr));

        if (pExport->AddressOfFunctions == 0 ||
            pExport->AddressOfNameOrdinals == 0 ||
            pExport->AddressOfNames == 0) {
            return 0;
        }

        auto addrOfFunctions = reinterpret_cast<PDWORD>(RVATOVA(Image, pExport->AddressOfFunctions));
        auto addrOfOrdinals = reinterpret_cast<PWORD>(RVATOVA(Image, pExport->AddressOfNameOrdinals));
        auto addrOfNames = reinterpret_cast<PDWORD>(RVATOVA(Image, pExport->AddressOfNames));

        for (DWORD i = 0; i < pExport->NumberOfNames; ++i) {
            auto exportName = reinterpret_cast<const char*>(RVATOVA(Image, addrOfNames[i]));

            if (strcmp(exportName, lpszName) == 0) {
                addr = addrOfFunctions[addrOfOrdinals[i]];
                break;
            }
        }
    }
    else {
        return 0;
    }

    if (addr != 0) {
        if (addr > exportAddr && addr < exportAddr + exportSize) {
            return 0;
        }
        return addr;
    }

    return 0;
}

bool LdrProcessRelocs(PVOID Image, PVOID NewBase)
{
    PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)RVATOVA(Image, ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

    DWORD_PTR OldBase = pHeaders->OptionalHeader.ImageBase;
    DWORD RelocAddr = pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD RelocSize = pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    if (RelocAddr == 0)
    {
        return true;
    }

    DWORD Size = 0;
    PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION)RVATOVA(Image, RelocAddr);

    while (RelocSize > Size && pRelocation->SizeOfBlock)
    {
        DWORD Num = (pRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD Rel = (PWORD)RVATOVA(pRelocation, sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < Num; i += 1)
        {
            if (Rel[i] > 0)
            {
                WORD Type = (Rel[i] & 0xF000) >> 12;

                if (Type != IMAGE_REL_BASED_DIR64 &&
                    Type != IMAGE_REL_BASED_ABSOLUTE)
                {
                    return false;
                }

                if (Type == IMAGE_REL_BASED_DIR64)
                {
                    *(PDWORD64)(RVATOVA(
                        Image,
                        pRelocation->VirtualAddress + (Rel[i] & 0x0FFF))) += (DWORD64)NewBase - OldBase;
                }
            }
        }

        pRelocation = (PIMAGE_BASE_RELOCATION)RVATOVA(pRelocation, pRelocation->SizeOfBlock);
        Size += pRelocation->SizeOfBlock;
    }

    return true;
}

bool LdrMapImage(PVOID Data, DWORD dwDataSize, PVOID* pImage, PDWORD pdwImageSize)
{
    PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)RVATOVA(Data, ((PIMAGE_DOS_HEADER)Data)->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)RVATOVA(&pHeaders->OptionalHeader, pHeaders->FileHeader.SizeOfOptionalHeader);

    DWORD dwImageSize = pHeaders->OptionalHeader.SizeOfImage;

    PVOID Image = LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, dwImageSize);

    if (Image)
    {
        ZeroMemory(Image, dwImageSize);
        CopyMemory(Image, Data, pHeaders->OptionalHeader.SizeOfHeaders);

        for (DWORD i = 0; i < pHeaders->FileHeader.NumberOfSections; i += 1)
        {
            memcpy(
                RVATOVA(Image, pSection->VirtualAddress),
                RVATOVA(Data, pSection->PointerToRawData),
                min(pSection->SizeOfRawData, pSection->Misc.VirtualSize)
            );

            pSection += 1;
        }

        *pImage = Image;
        *pdwImageSize = dwImageSize;

        return true;
    }

    return false;
}

bool ReadFromFile(HANDLE hFile, PVOID* pData, PDWORD pdwDataSize)
{
    bool bRet = FALSE;

    DWORD dwDataSizeHigh = 0;
    DWORD dwDataSize = GetFileSize(hFile, &dwDataSizeHigh);

    if (dwDataSize > 0)
    {
        if (dwDataSizeHigh != 0)
        {
            return false;
        }

        PVOID Data = LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, dwDataSize);

        if (Data)
        {
            DWORD dwReaded = 0;

            SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

            if (ReadFile(hFile, Data, dwDataSize, &dwReaded, NULL))
            {
                *pData = Data;
                *pdwDataSize = dwDataSize;

                bRet = true;
            }
            else
            {
                LocalFree(Data);
            }
        }
    }

    return bRet;
}

bool ReadFromFile(LPCSTR lpszFileName, PVOID* pData, PDWORD pdwDataSize)
{
    bool bRet = false;

    HANDLE hFile = CreateFileA(
        lpszFileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL
    );

    if (hFile != INVALID_HANDLE_VALUE)
    {
        if (pData == NULL || pdwDataSize == NULL)
        {
            bRet = true;
        }
        else
        {
            bRet = ReadFromFile(hFile, pData, pdwDataSize);
        }

        CloseHandle(hFile);
    }

    return bRet;
}

void* GetKernelProcAddress(const char* procName)
{
    if (!m_KernelImage || !m_KernelAddr) {
        return nullptr;
    }

    DWORD offset = LdrGetProcAddress(m_KernelImage, procName);
    if (offset) {
        return RVATOVA(m_KernelAddr, offset);
    }

    return nullptr;
}

void* GetKernelZwProcAddress(const char* procName)
{
    void* addr = nullptr;
    DWORD syscallNumber = 0;

    if (!m_KernelImage || !m_KernelAddr) {
        return nullptr;
    }

    if (!GetSyscallNumber(procName, &syscallNumber)) {
        return nullptr;
    }

    auto headers = reinterpret_cast<PIMAGE_NT_HEADERS>(
        RVATOVA(m_KernelImage, reinterpret_cast<PIMAGE_DOS_HEADER>(m_KernelImage)->e_lfanew)
        );
    auto section = reinterpret_cast<PIMAGE_SECTION_HEADER>(
        RVATOVA(&headers->OptionalHeader, headers->FileHeader.SizeOfOptionalHeader)
        );

    for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            !(section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)) {

            for (DWORD n = 0; n < section->Misc.VirtualSize - 0x100; ++n) {
                DWORD ptr = section->VirtualAddress + n;
                UCHAR sign[] = {
                    0x48, 0x8B, 0xC4, // mov rax, rsp
                    0xFA,             // cli
                    0x48, 0x83, 0xEC, 0x10, // sub rsp, 10h
                    0x50,             // push rax
                    0x9C,             // pushfq
                    0x6A, 0x10,       // push 10h
                    0x48, 0x8D, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, // lea rax, KiServiceLinkage
                    0x50,             // push rax
                    0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, XXXXXXXX
                    0xE9, 0xFF, 0xFF, 0xFF, 0xFF  // jmp KiServiceInternal
                };

                *reinterpret_cast<PDWORD>(sign + 0x15) = syscallNumber;

                if (MatchSign(RVATOVA(m_KernelImage, ptr), sign, sizeof(sign) - 1)) {
                    addr = RVATOVA(m_KernelAddr, ptr);
                }
            }
        }

        ++section;
    }

    return addr;
}
