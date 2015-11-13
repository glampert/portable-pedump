
// ================================================================================================
// -*- C++ -*-
// File: portable_pe_dump.cpp
// Author: Guilherme R. Lampert
// Created on: 10/11/15
// Brief: A portable tool to dump textual information about Microsoft Portable Executable files.
//
// Source code licensed under the MIT license.
// Copyright (C) 2015 Guilherme R. Lampert
//
// This software is provided "as is" without express or implied
// warranties. You may freely copy and compile this source into
// applications you distribute provided that this copyright text
// is included in the resulting source code.
// ================================================================================================

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <ctime>

#include <iostream>
#include <iomanip>
#include <memory>
#include <string>
#include <vector>
#include <utility>

// isatty() only needed if colored text output is desired.
#ifdef COLOR_PRINT
    // For isatty()/fileno()
    #if defined(__APPLE__) || defined(__linux__) || defined(__unix__)
        #include <unistd.h>
    #elif defined(_WIN32)
        #include <io.h>
        // Damn Windows with your silly underscores...
        #ifndef isatty
            #define isatty _isatty
        #endif // isatty
        #ifndef fileno
            #define fileno _fileno
        #endif // fileno
    #endif // Apple/Win/Linux
#endif // COLOR_PRINT

// ========================================================
//
// Portable Executable file structures, adapted
// from the originals found on the Window API / WinNT.h.
//
// SHOUT-CASE is a real eye sore, so I've renamed them and
// commented the original names found on MS documentation
// at the top of each structure.
//
// PE references/documentation:
// - https://msdn.microsoft.com/en-us/library/ms809762.aspx
// - https://en.wikipedia.org/wiki/Portable_Executable
// - http://www.sunshine2k.de/reversing/tuts/tut_rvait.htm
//
// Source code of the original Win32 PEDUMP by Matt Pietrek:
// - http://www.wheaty.net/downloads.htm
//
// ========================================================
namespace pe
{

static const std::uint16_t DOSSignature = 0x5A4D;     // "MZ"
static const std::uint32_t NTSignature  = 0x00004550; // "PE\0\0"

static const std::uint32_t ImageMaxSectionNameLength = 8;
static const std::uint32_t ImageMaxDirectoryEntries  = 16;

#pragma pack(push, 1)

// AKA IMAGE_DATA_DIRECTORY
struct ImageDataDirectory
{
    std::uint32_t virtualAddress;
    std::uint32_t sizeInBytes;
};

// AKA IMAGE_FILE_HEADER
struct ImageFileHeader
{
    std::uint16_t machine;
    std::uint16_t numberOfSections;
    std::uint32_t timeDateStamp;
    std::uint32_t pointerToSymbolTable;
    std::uint32_t numberOfSymbols;
    std::uint16_t sizeOfOptionalHeader;
    std::uint16_t characteristics;
};

// AKA IMAGE_OPTIONAL_HEADER
struct ImageOptionalHeader
{
    // Standard fields
    std::uint16_t magic;
    std::uint8_t  majorLinkerVersion;
    std::uint8_t  minorLinkerVersion;
    std::uint32_t sizeOfCode;
    std::uint32_t sizeOfInitializedData;
    std::uint32_t sizeOfUninitializedData;
    std::uint32_t addressOfEntryPoint;
    std::uint32_t baseOfCode;
    std::uint32_t baseOfData;

    // NT additional fields
    std::uint32_t imageBase;
    std::uint32_t sectionAlignment;
    std::uint32_t fileAlignment;
    std::uint16_t majorOperatingSystemVersion;
    std::uint16_t minorOperatingSystemVersion;
    std::uint16_t majorImageVersion;
    std::uint16_t minorImageVersion;
    std::uint16_t majorSubsystemVersion;
    std::uint16_t minorSubsystemVersion;
    std::uint32_t reserved1;
    std::uint32_t sizeOfImage;
    std::uint32_t sizeOfHeaders;
    std::uint32_t checksum;
    std::uint16_t subsystem;
    std::uint16_t dllCharacteristics;
    std::uint32_t sizeOfStackReserve;
    std::uint32_t sizeOfStackCommit;
    std::uint32_t sizeOfHeapReserve;
    std::uint32_t sizeOfHeapCommit;
    std::uint32_t loaderFlags;
    std::uint32_t numberOfRvaAndSizes;
    ImageDataDirectory dataDirectory[ImageMaxDirectoryEntries];
};

// AKA IMAGE_NT_HEADERS
struct ImageNTHeader
{
    std::uint32_t       signature;
    ImageFileHeader     fileHeader;
    ImageOptionalHeader optionalHeader;
};

// AKA IMAGE_SECTION_HEADER
struct ImageSectionHeader
{
    // Section name, like ".text"; NOT NUL-terminated!
    char name[ImageMaxSectionNameLength];

    union
    {
        std::uint32_t physicalAddress;
        std::uint32_t virtualSize;
    } misc;

    std::uint32_t virtualAddress;
    std::uint32_t sizeOfRawData;
    std::uint32_t pointerToRawData;
    std::uint32_t pointerToRelocations;
    std::uint32_t pointerToLinenumbers;
    std::uint16_t numberOfRelocations;
    std::uint16_t numberOfLinenumbers;
    std::uint32_t characteristics;
};

// AKA IMAGE_EXPORT_DIRECTORY
struct ImageExportDirectory
{
    std::uint32_t characteristics;
    std::uint32_t timeDateStamp;
    std::uint16_t majorVersion;
    std::uint16_t minorVersion;
    std::uint32_t nameRVA; // RVA to NUL-terminated name of the PE (like "KERNEL32.DLL")
    std::uint32_t ordinalBase;
    std::uint32_t numberOfFunctions;
    std::uint32_t numberOfNames;

    // Relative Virtual Addresses from base of image
    std::uint32_t addressOfFunctions;
    std::uint32_t addressOfNames;
    std::uint32_t addressOfNameOrdinals;
};

// AKA IMAGE_IMPORT_DESCRIPTOR
struct ImageImportDescriptor
{
    std::uint32_t impByNameRVA;   // RVA to the array of ImageImportByName entries for this DLL
    std::uint32_t timeDateStamp;  // Timestamp of the whole file repeated here
    std::uint32_t forwarderChain; // -1 if no forwarders
    std::uint32_t nameRVA;        // RVA to a NUL-terminated ASCII string containing the imported DLL's name.
    std::uint32_t firstThunkRVA;  // RVA to IAT (if bound this IAT has actual addresses)
};

// AKA IMAGE_THUNK_DATA
struct ImageThunkData
{
    union
    {
        std::uint32_t forwarderString;
        std::uint32_t function;
        std::uint32_t ordinal;
        std::uint32_t addressOfData;
    } u1;
};

// AKA IMAGE_IMPORT_BY_NAME
struct ImageImportByName
{
    std::uint16_t ordinalHint;
    char funcName[1]; // Actually reinterpreted as a NUL-terminated string.
};

// AKA IMAGE_DOS_HEADER (DOS .EXE header kept for historical reasons; no longer used)
struct ImageDOSHeader
{
    std::uint16_t e_magic;    // Magic number
    std::uint16_t e_cblp;     // Bytes on last page of file
    std::uint16_t e_cp;       // Pages in file
    std::uint16_t e_crlc;     // Relocations
    std::uint16_t e_cparhdr;  // Size of header in paragraphs
    std::uint16_t e_minalloc; // Minimum extra paragraphs needed
    std::uint16_t e_maxalloc; // Maximum extra paragraphs needed
    std::uint16_t e_ss;       // Initial (relative) SS value
    std::uint16_t e_sp;       // Initial SP value
    std::uint16_t e_csum;     // Checksum
    std::uint16_t e_ip;       // Initial IP value
    std::uint16_t e_cs;       // Initial (relative) CS value
    std::uint16_t e_lfarlc;   // File address of relocation table
    std::uint16_t e_ovno;     // Overlay number
    std::uint16_t e_res[4];   // Reserved words
    std::uint16_t e_oemid;    // OEM identifier (for e_oeminfo)
    std::uint16_t e_oeminfo;  // OEM information (e_oemid specific)
    std::uint16_t e_res2[10]; // Reserved words
    std::uint32_t e_lfanew;   // File address of new EXE header (IMAGE_NT_HEADERS)
};

#pragma pack(pop)

} // namespace pe {}

// ========================================================
// Colored text printing on the terminal:
// ========================================================

namespace color
{

static inline bool canColorPrint()
{
#ifdef COLOR_PRINT
    return isatty(fileno(stdout));
#else // !COLOR_PRINT
    return false;
#endif // COLOR_PRINT
}

// ANSI color codes:
static inline const char * restore() { return canColorPrint() ? "\033[0;1m"  : ""; }
static inline const char * red()     { return canColorPrint() ? "\033[31;1m" : ""; }
static inline const char * green()   { return canColorPrint() ? "\033[32;1m" : ""; }
static inline const char * yellow()  { return canColorPrint() ? "\033[33;1m" : ""; }
static inline const char * blue()    { return canColorPrint() ? "\033[34;1m" : ""; }
static inline const char * magenta() { return canColorPrint() ? "\033[35;1m" : ""; }
static inline const char * cyan()    { return canColorPrint() ? "\033[36;1m" : ""; }
static inline const char * white()   { return canColorPrint() ? "\033[37;1m" : ""; }

} // namespace color {}

// ========================================================

// Defined in cxx_demangle.cpp
extern std::string demangle(const char * mangledName, bool baseNameOnly);

// ========================================================

static bool queryFileSize(const char * filename, std::size_t & sizeInBytes)
{
    FILE * fileIn = std::fopen(filename, "rb");
    if (fileIn == nullptr)
    {
        std::cerr << color::red() << "Unable to open \"" << filename
                  << "\": " << std::strerror(errno) << color::restore() << "\n";
        return false;
    }

    // More or less portable way of getting the file size,
    // but SEEK_END is not guaranteed to be supported everywhere.
    // Realistically though, it is available on all mainstream platforms.
    std::fseek(fileIn, 0, SEEK_END);
    const long fileLength = std::ftell(fileIn);
    if (fileLength < 0)
    {
        std::cerr << color::red() << "Unable to get length of file \""
                  << filename << "\"!" << color::restore() << "\n";
        std::fclose(fileIn);
        return false;
    }

    sizeInBytes = fileLength;
    std::fclose(fileIn);
    return true;
}

static std::unique_ptr<std::uint8_t[]> loadFile(const char * filename, std::size_t & sizeInBytes)
{
    std::size_t fileLength = 0;
    if (!queryFileSize(filename, fileLength) || fileLength == 0)
    {
        return nullptr;
    }

    FILE * fileIn = std::fopen(filename, "rb");
    if (fileIn == nullptr)
    {
        std::cerr << color::red() << "Unable to open \"" << filename << "\": "
                  << std::strerror(errno) << color::restore() << "\n";
        return nullptr;
    }

    std::unique_ptr<std::uint8_t[]> data{ new std::uint8_t[fileLength] };
    if (std::fread(data.get(), sizeof(std::uint8_t), fileLength, fileIn) != fileLength)
    {
        std::cerr << color::red() << "Partial fread() in loadFile()!" << color::restore() << "\n";
        std::fclose(fileIn);
        return nullptr;
    }

    sizeInBytes = fileLength;
    std::fclose(fileIn);
    return data;
}

static inline std::string toHexa(std::uint32_t val, int pad = 0)
{
    char buffer[128];
    if (pad > 0)
    {
        std::sprintf(buffer, "0x%0*X", pad, val);
    }
    else
    {
        std::sprintf(buffer, "0x%X", val);
    }
    return buffer;
}

static inline std::string sectionName(const char * name)
{
    char buffer[128];
    // Paint the name red if printing to a terminal.
    std::sprintf(buffer, "%s %-8.8s %s", color::red(), name, color::restore());
    return buffer;
}

static inline std::string truncate(std::string str, std::size_t maxLen = 60)
{
    if (str.length() > maxLen)
    {
        str = str.substr(0, maxLen - 4);
        str += "...";
    }
    return str;
}

static inline const pe::ImageSectionHeader * getFirstSection(const pe::ImageNTHeader * ntheader)
{
    #define PE_FIELD_OFFSET(type, field) ((std::uintptr_t)&(((const type *)0)->field))
    return reinterpret_cast<const pe::ImageSectionHeader *>(
            reinterpret_cast<std::uintptr_t>(ntheader) +
            PE_FIELD_OFFSET(pe::ImageNTHeader, optionalHeader) +
            ntheader->fileHeader.sizeOfOptionalHeader);
    #undef PE_FIELD_OFFSET
}

static const pe::ImageSectionHeader * findRVASection(std::uint32_t rva, const pe::ImageNTHeader * ntHeaderPtr)
{
    const pe::ImageSectionHeader * sectionPtr = getFirstSection(ntHeaderPtr);
    const std::uint32_t numSections = ntHeaderPtr->fileHeader.numberOfSections;

    for (std::uint32_t s = 0; s < numSections; ++s, ++sectionPtr)
    {
        // Is the RVA within this section?
        if (rva >= sectionPtr->virtualAddress &&
            rva < (sectionPtr->virtualAddress + sectionPtr->misc.virtualSize))
        {
            return sectionPtr;
        }
    }
    return nullptr;
}

static void dumpExportsSection(const pe::ImageDOSHeader * dosHeaderPtr, const pe::ImageNTHeader * ntHeaderPtr)
{
    //
    // Following is based on 'impdef.c', which can be found here:
    //   https://code.google.com/p/ulib-win/source/browse/trunk/demo/pe/impdef.c
    //
    // Also relevant:
    //   http://stackoverflow.com/questions/2975639/resolving-rvas-for-import-and-export-tables-within-a-pe-file
    //

    // 64bit PEs are a whole different story. I don't support them at the moment.
    if (ntHeaderPtr->optionalHeader.numberOfRvaAndSizes == 0)
    {
        std::cout << "\n" << color::yellow() << "Can't list exports! Number of RVAs is zero. "
                  << "PE is either corrupted or this is an unsupported 64-bits PE!"
                  << color::restore() << "\n";
        return;
    }

    // Index of the exports directory (first one):
    const int DirEntryExports = 0;
    const pe::ImageDataDirectory * dataDirs = ntHeaderPtr->optionalHeader.dataDirectory;

    // RVA = Relative Virtual Address
    const auto exportsStartRVA = dataDirs[DirEntryExports].virtualAddress;
    const auto exportsEndRVA   = exportsStartRVA + dataDirs[DirEntryExports].sizeInBytes;

    // Get the IMAGE_SECTION_HEADER that contains the exports.
    // This is usually the ".edata" section, but doesn't have to be.
    const pe::ImageSectionHeader * sectHeader = findRVASection(exportsStartRVA, ntHeaderPtr);
    if (sectHeader == nullptr)
    {
        std::cout << "\n" << color::yellow() << "No exports found." << color::restore() << "\n";
        return;
    }

    const auto delta     = sectHeader->virtualAddress - sectHeader->pointerToRawData;
    const auto base      = reinterpret_cast<std::uintptr_t>(dosHeaderPtr);
    const auto exportDir = reinterpret_cast<const pe::ImageExportDirectory *>(base + (exportsStartRVA - delta));

    const std::uintptr_t addrOrdinals  = base + (exportDir->addressOfNameOrdinals - delta);
    const std::uintptr_t addrFunctions = base + (exportDir->addressOfFunctions    - delta);
    const std::uintptr_t addrNames     = base + (exportDir->addressOfNames        - delta);

    const auto ordinals  = reinterpret_cast<const std::uint16_t *>(addrOrdinals);
    const auto functions = reinterpret_cast<const std::uint32_t *>(addrFunctions);
    const auto names     = reinterpret_cast<const std::uint32_t *>(addrNames);

    std::cout << "\n";
    std::cout << color::yellow() << "------------------------------------------------------------\n";
    std::cout << color::yellow() << "            Listing exports from " << sectionName(sectHeader->name) << "\n";
    std::cout << color::yellow() << "------------------------------------------------------------\n";
    std::cout << "\n" << color::restore();
    std::cout << "PE Name...........: " << reinterpret_cast<const char *>(base + (exportDir->nameRVA - delta)) << "\n";
    std::cout << "Num of functions..: " << exportDir->numberOfFunctions << "\n";
    std::cout << "Num of names......: " << exportDir->numberOfNames << "\n";
    std::cout << "Ordinal base......: " << exportDir->ordinalBase << "\n";
    std::cout << "\n";

    struct FName
    {
        std::string ord;
        std::string mangled;
        std::string demangled;
    };

    // We store the names first, then sort and print.
    FName tempName;
    std::vector<FName> funcNames;

    for (std::uint32_t i = 0; i < exportDir->numberOfFunctions; ++i)
    {
        const auto entryPointRVA = functions[i];
        if (entryPointRVA == 0)
        {
            // Skip over gaps in exported function ordinals
            // (the entry-point is 0 for these functions).
            continue;
        }

        // See if this function has an associated name exported for it.
        for (std::uint32_t j = 0; j < exportDir->numberOfNames; ++j)
        {
            if (ordinals[j] == i)
            {
                const char * mangledName = reinterpret_cast<const char *>(base + (names[j] - delta));
                tempName.ord = toHexa(ordinals[j], 3) + " ";
                tempName.mangled = truncate(mangledName);
                tempName.demangled = demangle(mangledName, true);
                funcNames.emplace_back(std::move(tempName));
            }
        }

        // Is it a forwarder? If so, the entry point RVA is inside the
        // ".edata" section, and is an RVA to the DllName.EntryPointName
        if ((entryPointRVA >= exportsStartRVA) && (entryPointRVA <= exportsEndRVA))
        {
            const char * mangledName = reinterpret_cast<const char *>(base + (entryPointRVA - delta));
            tempName.ord = "FWD ";
            tempName.mangled = truncate(mangledName);
            tempName.demangled = demangle(mangledName, true);
            funcNames.emplace_back(std::move(tempName));
        }
    }

    // Sort alphabetically by the demangle name.
    std::sort(std::begin(funcNames), std::end(funcNames),
        [](const FName & a, const FName & b)
        {
            return a.demangled < b.demangled;
        }
    );

    // Find padding needed to align the first name column:
    std::size_t longestName = 1;
    for (const auto & fn : funcNames)
    {
        if (fn.demangled.length() > longestName)
        {
            longestName = fn.demangled.length();
        }
    }

    // Print three columns, first with the ordinal, second
    // with the demangled name, third with the mangled value.
    std::cout << std::left << std::setw(longestName / 3 + 3) << "Ordn. ";
    std::cout << std::left << std::setw(longestName) << "Func name ";
    std::cout << std::left << std::setw(1) << "Mangled name ";
    std::cout << "\n";
    std::cout << std::left << std::setw(longestName / 3 + 3) << "----- ";
    std::cout << std::left << std::setw(longestName) << "--------- ";
    std::cout << std::left << std::setw(1) << "------------ ";
    std::cout << "\n";

    for (const auto & fn : funcNames)
    {
        // Ordn.
        // -----
        std::cout << fn.ord << " ";

        // Func Name
        // ---------
        std::cout << color::yellow();
        std::cout << std::left << std::setw(longestName);
        std::cout << fn.demangled << "  ";

        // Mangled name
        // ------------
        std::cout << color::red() << fn.mangled << color::restore() << "\n";
    }

    std::cout << funcNames.size() << " exports located and resolved.\n";
}

static inline std::uintptr_t addrFromRVA(std::uint32_t rva, const pe::ImageNTHeader * pNTHeader, std::uintptr_t imageBase)
{
    const auto sectHeader = findRVASection(rva, pNTHeader);
    if (sectHeader == nullptr)
    {
        return 0;
    }
    const auto delta = (sectHeader->virtualAddress - sectHeader->pointerToRawData);
    return imageBase + rva - delta;
}

static inline const pe::ImageThunkData * toThunkPtr(std::uintptr_t ptr)
{
    return reinterpret_cast<const pe::ImageThunkData *>(ptr);
}

static inline bool isNullImportDescriptor(const pe::ImageImportDescriptor & impDesc)
{
    // An import descriptor with all fields set to zero terminates the array of ImageImportDescriptors.
    // It would have been much simpler to just add a count field somewhere, wouldn't it?
    // This layout was probably designed by a Microsoft intern :P
    static const pe::ImageImportDescriptor nullImpDesc{};
    return std::memcmp(&impDesc, &nullImpDesc, sizeof(nullImpDesc)) == 0;
}

static void dumpImportsSection(const pe::ImageDOSHeader * dosHeaderPtr, const pe::ImageNTHeader * ntHeaderPtr)
{
    // Index of the imports directory (second one):
    const int DirEntryImports = 1;
    const pe::ImageDataDirectory * dataDirs = ntHeaderPtr->optionalHeader.dataDirectory;

    // RVA = Relative Virtual Address
    const auto importsStartRVA = dataDirs[DirEntryImports].virtualAddress;

    // Get the IMAGE_SECTION_HEADER that contains the imports.
    // Usually the ".idata" section, but not necessarily.
    const pe::ImageSectionHeader * sectHeader = findRVASection(importsStartRVA, ntHeaderPtr);
    if (sectHeader == nullptr)
    {
        std::cout << "\n" << color::yellow() << "No imports found." << color::restore() << "\n";
        return;
    }

    const auto delta = sectHeader->virtualAddress - sectHeader->pointerToRawData;
    const auto base = reinterpret_cast<std::uintptr_t>(dosHeaderPtr);
    const auto importDesc = reinterpret_cast<const pe::ImageImportDescriptor *>(base + (importsStartRVA - delta));

    std::cout << "\n";
    std::cout << color::yellow() << "------------------------------------------------------------\n";
    std::cout << color::yellow() << "            Listing imports from " << sectionName(sectHeader->name) << "\n";
    std::cout << color::yellow() << "------------------------------------------------------------\n";
    std::cout << color::restore() << "\n";

    //
    // List of all DLLs for quick conference:
    //
    std::cout << "--------------------\n";
    std::cout << "  External modules\n";
    std::cout << "--------------------\n";

    int i;
    std::cout << "\n";
    for (i = 0; !isNullImportDescriptor(importDesc[i]); ++i)
    {
        const char * dllName = reinterpret_cast<const char *>(base + (importDesc[i].nameRVA - delta));
        std::cout << color::cyan() << "  " << dllName << "\n";
    }
    std::cout << color::restore() << "\n";

    std::cout << "---------------------\n";
    std::cout << "  Ordn.   Func name\n";
    std::cout << "---------------------\n\n";

    //
    // Print each module name again followed
    // by its referenced symbols/functions
    //
    int symbolsTotal = 0;
    for (i = 0; !isNullImportDescriptor(importDesc[i]); ++i)
    {
        const char * dllName = reinterpret_cast<const char *>(base + (importDesc[i].nameRVA - delta));
        std::cout << color::red() << dllName << color::restore() << "\n";

        std::uintptr_t thunk    = importDesc[i].impByNameRVA;
        std::uintptr_t thunkIAT = importDesc[i].firstThunkRVA; // IAT = Import Address Table

        if (thunk == 0) // No impByNameRVA field?
        {
            // Must have a non-zero firstThunkRVA field then.
            thunk = thunkIAT;
            if (thunk == 0)
            {
                std::cout << "Bad IAT! Skipping imports for " << dllName << "...\n";
                continue;
            }
        }

        // Adjust the pointer to where the tables are in memory:
        thunk = addrFromRVA(thunk, ntHeaderPtr, base);
        if (thunk == 0)
        {
            std::cout << "Can't find IAT! Skipping imports for " << dllName << "...\n";
            continue;
        }

        thunkIAT = addrFromRVA(thunkIAT, ntHeaderPtr, base);

        // A zeroed-out thunk indicates the end of the list.
        for (;;)
        {
            if (toThunkPtr(thunk)->u1.addressOfData == 0)
            {
                break;
            }

            if (toThunkPtr(thunk)->u1.ordinal & 0x80000000) // IMAGE_ORDINAL_FLAG
            {
                std::cout << "  " << toHexa(toThunkPtr(thunk)->u1.ordinal & 0xFFFF, 4);
                std::cout << color::yellow() << "  ???" << color::restore();
                // Name apparently not available...
                // If we'd try to force printing addressOfData anyways,
                // it would hit some invalid memory location.
            }
            else
            {
                const auto addrImportName = addrFromRVA(toThunkPtr(thunk)->u1.addressOfData, ntHeaderPtr, base);
                const auto importNamePtr  = reinterpret_cast<const pe::ImageImportByName *>(addrImportName);

                std::cout << "  " << toHexa(importNamePtr->ordinalHint, 4);
                std::cout << "  " << color::yellow() << demangle(importNamePtr->funcName, true) << color::restore();
            }

            std::cout << "\n";

            // Advance to next thunk
            thunk    += sizeof(pe::ImageThunkData);
            thunkIAT += sizeof(pe::ImageThunkData);

            ++symbolsTotal;
        }

        std::cout << "\n";
    }

    std::cout << i << " dependencies located and resolved, with "
              << symbolsTotal << " symbols total.\n";
}

static inline std::string hexDWord(std::uint32_t dw)
{
    union Swap
    {
        std::uint32_t u32;
        std::uint8_t b8[4];
    };

    // Swap so it displays as expected (Big-endian-like)
    Swap a, b;
    a.u32 = dw;
    b.b8[0] = a.b8[3];
    b.b8[1] = a.b8[2];
    b.b8[2] = a.b8[1];
    b.b8[3] = a.b8[0];

    char buffer[128];
    std::sprintf(buffer, "%08X ", b.u32);
    return buffer;
}

static void dumpDOSJunk(const pe::ImageDOSHeader * dosHeaderPtr)
{
    // From 0 to the start of the new header.
    const auto dosStubSizeInBytes  = dosHeaderPtr->e_lfanew;
    const auto dosStubSizeInDWords = dosStubSizeInBytes / 4;

    auto asciiPtr = reinterpret_cast<const char *>(dosHeaderPtr);
    auto dwordPtr = reinterpret_cast<const std::uint32_t *>(dosHeaderPtr);

    std::cout << "\n";
    std::cout << color::yellow() << "------------------------------------------------------------\n";
    std::cout << color::yellow() << "            IMAGE_DOS_HEADER and DOS stub" << "\n";
    std::cout << color::yellow() << "------------------------------------------------------------\n";
    std::cout << color::restore() << "\n";

    //
    // Simple hexadecimal dump of the header + DOS stub data,
    // paired by the ASCII representation of the printable characters.
    //
    const std::uint32_t MaxCols = 6;
    std::uint32_t i = 0, j = 0;

    for (; i < dosStubSizeInDWords; ++i, ++j, ++dwordPtr)
    {
        if (j == MaxCols)
        {
            std::cout << color::cyan() << "| ";
            for (std::uint32_t k = 0; k < j * 4; ++k, ++asciiPtr)
            {
                std::cout << (std::isprint(*asciiPtr) ? *asciiPtr : ' ');
            }
            std::cout << " |\n" << color::restore();
            j = 0;
        }
        std::cout << hexDWord(*dwordPtr);
    }

    if (j <= MaxCols) // Last residual line
    {
        for (i = j; i < MaxCols; ++i) // Pad with blank spaces to fill a row
        {
            std::cout << "         ";
        }

        std::cout << color::cyan() << "| ";
        for (std::uint32_t k = 0; k < j * 4; ++k, ++asciiPtr)
        {
            std::cout << (std::isprint(*asciiPtr) ? *asciiPtr : ' ');
        }
        int diff = (MaxCols - j) * 4;
        if (diff > 0)
        {
            while (diff--) { std::cout << ' '; } // Pad the ascii block to the right
        }
        std::cout << " |\n" << color::restore();
    }
}

static std::string sectionCharacteristics(std::uint32_t characteristics)
{
    std::string str;

    // This tests just a small subset of the large group of flag described by MSDN:
    //  https://msdn.microsoft.com/en-us/library/windows/desktop/ms680341(v=vs.85).aspx
    if (characteristics & 0x00000020)
    {
        str += "CODE"; // IMAGE_SCN_CNT_CODE
    }
    if (characteristics & 0x00000040)
    {
        if (!str.empty()) { str += " | "; }
        str += "INITIALIZED_DATA"; // IMAGE_SCN_CNT_INITIALIZED_DATA
    }
    if (characteristics & 0x00000080)
    {
        if (!str.empty()) { str += " | "; }
        str += "UNINITIALIZED_DATA"; // IMAGE_SCN_CNT_UNINITIALIZED_DATA
    }
    if (characteristics & 0x00000200)
    {
        if (!str.empty()) { str += " | "; }
        str += "LINKER_INFO"; // IMAGE_SCN_LNK_INFO
    }
    if (characteristics & 0x02000000)
    {
        if (!str.empty()) { str += " | "; }
        str += "MEM_DISCARDABLE"; // IMAGE_SCN_MEM_DISCARDABLE
    }
    if (characteristics & 0x10000000)
    {
        if (!str.empty()) { str += " | "; }
        str += "MEM_SHARED"; // IMAGE_SCN_MEM_SHARED
    }
    if (characteristics & 0x20000000)
    {
        if (!str.empty()) { str += " | "; }
        str += "MEM_EXECUTE"; // IMAGE_SCN_MEM_EXECUTE
    }
    if (characteristics & 0x40000000)
    {
        if (!str.empty()) { str += " | "; }
        str += "MEM_READ"; // IMAGE_SCN_MEM_READ
    }
    if (characteristics & 0x80000000)
    {
        if (!str.empty()) { str += " | "; }
        str += "MEM_WRITE"; // IMAGE_SCN_MEM_WRITE
    }

    if (str.empty()) { str += "0"; }

    // Pain the flags string as magenta if printing to a terminal.
    return color::magenta() + str + color::restore();
}

static void dumpSectionHeaders(const pe::ImageNTHeader * ntHeaderPtr)
{
    //
    // Common section names:
    //  .text  -> program code
    //  .data  -> initialized global data
    //  .bss   -> uninitialized static data
    //  .rsrc  -> program resources, if any
    //  .crt   -> MSVC C/C++ runtime library
    //  .tls   -> thread local storage if the program uses any
    //  .idata -> imports from other DLLs
    //  .edata -> exported functions/exports table
    //  .rdata -> read-only data, strings; might also store debug information & exports
    //  .reloc -> relocation table if the loaded needs to fixup the base addr
    //

    std::cout << "\n";
    std::cout << color::yellow() << "------------------------------------------------------------\n";
    std::cout << color::yellow() << "            IMAGE_SECTION_HEADERS" << "\n";
    std::cout << color::yellow() << "------------------------------------------------------------\n";
    std::cout << color::restore() << "\n";

    const pe::ImageSectionHeader * sectionPtr = getFirstSection(ntHeaderPtr);
    const std::uint32_t numSections = ntHeaderPtr->fileHeader.numberOfSections;

    std::cout << "Number       Name       Flags        Flag strings\n";
    std::cout << "------       ----       -----        ------------\n";
    for (std::uint32_t s = 0; s < numSections; ++s, ++sectionPtr)
    {
        std::cout << "Section " << s << ": " << sectionName(sectionPtr->name)
                  << toHexa(sectionPtr->characteristics) << "  ( "
                  << sectionCharacteristics(sectionPtr->characteristics) << " )" << "\n";
    }

    std::cout << numSections << " sections listed.\n";
}

static std::string fileHeaderMachine(std::uint32_t id)
{
    // Value found on MSDN: https://msdn.microsoft.com/en-us/library/ms809762.aspx
    switch (id)
    {
    case 0x14D  : return "INTEL_I860";
    case 0x14C  : return "INTEL_I386";
    case 0x162  : return "MIPS R3000";
    case 0x166  : return "MIPS R4000";
    case 0x183  : return "DEC_ALPHA_AXP";
    case 0x8664 : return "WIN_64"; // Partially supported by this tool.
    default     : return "UNKNOWN";
    } // switch (id)
}

static std::string fileHeaderCharacteristics(std::uint32_t characteristics)
{
    std::string str;
    if (characteristics & 0x0001)
    {
        str += "NO_RELOC "; // There are no relocations in this file
    }
    if (characteristics & 0x0002)
    {
        str += "EXE "; // File is an executable image (not a OBJ or LIB)
    }
    if (characteristics & 0x2000)
    {
        str += "DLL "; // File is a dynamic-link library, not a program
    }
    return !str.empty() ? str : str += "0";
}

static std::string optionalHeaderSubsystem(std::uint32_t subsystem)
{
    switch (subsystem)
    {
    case 1  : return "NATIVE";      // Device drivers
    case 2  : return "WINDOWS_GUI"; // GUI applications (DLLs included)
    case 3  : return "WINDOWS_CUI"; // Console/command-line
    case 5  : return "OS2_CUI";     // OS/2 legacy
    case 7  : return "POSIX_CUI";   // POSIX ???
    default : return "UNKNOWN";
    } // switch (subsystem)
}

static std::string optionalHeaderDLLCharacteristics(std::uint32_t characteristics)
{
    // According to this:
    //  https://msdn.microsoft.com/en-us/library/ms809762.aspx
    //
    // DllCharacteristics defines:
    // A set of flags indicating under which circumstances a DLL's initialization
    // function (such as DllMain) will be called. This value appears to always be set to 0,
    // yet the operating system still calls the DLL initialization function for all four events.

    std::string str;
    if (characteristics & 1)
    {
        str += "Call on load; ";
    }
    if (characteristics & 2)
    {
        str += "Call on thread term; ";
    }
    if (characteristics & 4)
    {
        str += "Call on thread start; ";
    }
    if (characteristics & 8)
    {
        str += "Call on exit; ";
    }
    return !str.empty() ? str : str += "0";
}

static void dumpNTHeaders(const pe::ImageNTHeader * ntHeaderPtr)
{
    std::cout << "\n";
    std::cout << color::yellow() << "------------------------------------------------------------\n";
    std::cout << color::yellow() << "            NT Headers" << "\n";
    std::cout << color::yellow() << "------------------------------------------------------------\n";
    std::cout << color::restore() << "\n";

    const auto & fileHeader     = ntHeaderPtr->fileHeader;
    const auto & optionalHeader = ntHeaderPtr->optionalHeader;

    // Apparently this timestamp is "the number of seconds since December 31st, 1969",
    // so it is should be compatible with time_t. Might be off by a few hours, but what of it...
    const std::time_t timestamp = fileHeader.timeDateStamp;

    std::cout << "---- IMAGE_FILE_HEADER ----" << "\n";
    std::cout << "Machine architecture.....: " << fileHeaderMachine(fileHeader.machine) << "\n";
    std::cout << "Number of sections.......: " << fileHeader.numberOfSections << "\n";
    std::cout << "Timestamp................: " << toHexa(timestamp) << " => " << std::ctime(&timestamp); // ctime already terminated with a newline.
    std::cout << "Pointer to symbol table..: " << fileHeader.pointerToSymbolTable << "\n";
    std::cout << "Number of symbols........: " << fileHeader.numberOfSymbols << "\n";
    std::cout << "Optional header size.....: " << fileHeader.sizeOfOptionalHeader << "\n";
    std::cout << "Image characteristics....: " << fileHeaderCharacteristics(fileHeader.characteristics) << "\n";
    std::cout << "\n";
    std::cout << "---- IMAGE_OPTIONAL_HEADER ----" << "\n";
    std::cout << "Magic....................: " << toHexa(optionalHeader.magic) << "\n";
    std::cout << "Code size................: " << optionalHeader.sizeOfCode << "\n";
    std::cout << "Initialized data size....: " << optionalHeader.sizeOfInitializedData << "\n";
    std::cout << "Uninitialized data size..: " << optionalHeader.sizeOfUninitializedData << "\n";
    std::cout << "Number of RVAs and sizes.: " << optionalHeader.numberOfRvaAndSizes << "\n";
    std::cout << "Address of entry point...: " << toHexa(optionalHeader.addressOfEntryPoint) << "\n";
    std::cout << "Subsystem................: " << optionalHeaderSubsystem(optionalHeader.subsystem) << "\n";
    std::cout << "DLL Characteristics......: " << optionalHeaderDLLCharacteristics(optionalHeader.dllCharacteristics) << "\n";
}

struct ProgramFlags
{
    bool printHelpAndExit       = false; // -h/--help
    bool flagDumpNTHeaders      = false; // -n/--nthdr
    bool flagDumpSectionHeaders = false; // -s/--sections
    bool flagDumpDOSJunk        = false; // -d/--doshdr
    bool flagDumpExportsSection = false; // -e/--exports
    bool flagDumpImportsSection = false; // -i/--imports

    bool anyFlagSet() const
    {
        return (printHelpAndExit       ||
                flagDumpNTHeaders      ||
                flagDumpSectionHeaders ||
                flagDumpDOSJunk        ||
                flagDumpExportsSection ||
                flagDumpImportsSection);
    }
};

static ProgramFlags processCmdLine(int argc, const char * argv[])
{
    ProgramFlags prog;

    // argv[0] is the program name and argv[1] should be the PE file or a -h/--help flag.
    for (int i = 1; i < argc; ++i)
    {
        if (argv[i][0] != '-')
        {
            continue; // Not a flag.
        }

        if (std::strcmp(argv[i], "-h") == 0 || std::strcmp(argv[i], "--help") == 0)
        {
            // Just print the help text and bail.
            prog.printHelpAndExit = true;
            break;
        }

        if (std::strcmp(argv[i], "-a") == 0 || std::strcmp(argv[i], "--all") == 0)
        {
            // Shorthand flag to enable all output.
            prog.flagDumpNTHeaders      = true;
            prog.flagDumpSectionHeaders = true;
            prog.flagDumpDOSJunk        = true;
            prog.flagDumpExportsSection = true;
            prog.flagDumpImportsSection = true;
            break;
        }

        // These are all optional:
        if (std::strcmp(argv[i], "-n") == 0 || std::strcmp(argv[i], "--nthdr") == 0)
        {
            prog.flagDumpNTHeaders = true;
        }
        else if (std::strcmp(argv[i], "-s") == 0 || std::strcmp(argv[i], "--sections") == 0)
        {
            prog.flagDumpSectionHeaders = true;
        }
        else if (std::strcmp(argv[i], "-d") == 0 || std::strcmp(argv[i], "--doshdr") == 0)
        {
            prog.flagDumpDOSJunk = true;
        }
        else if (std::strcmp(argv[i], "-e") == 0 || std::strcmp(argv[i], "--exports") == 0)
        {
            prog.flagDumpExportsSection = true;
        }
        else if (std::strcmp(argv[i], "-i") == 0 || std::strcmp(argv[i], "--imports") == 0)
        {
            prog.flagDumpImportsSection = true;
        }
    }

    return prog;
}

static void printHelpText(const char * progName)
{
    std::cout << "\n"
        << "Usage:\n"
        << " $ " << progName << " <filename> [options]\n"
        << " Prints information about a Win32 Portable Executable (PE) file.\n"
        << " PE files are usually ended with the extensions: DLL, EXE, SYS, EFI, among others.\n"
        << " Options are:\n"
        << "  -h, --help      Prints this message and exits.\n"
        << "  -n, --nthdr     Prints the IMAGE_FILE_HEADER and IMAGE_OPTIONAL_HEADER.\n"
        << "  -d, --doshdr    Prints the IMAGE_DOS_HEADER and an hexadecimal dump of the DOS stub.\n"
        << "  -s, --sections  Prints a short summary of each PE section.\n"
        << "  -e, --exports   Prints a list of all exported symbols. Names undecorated if possible.\n"
        << "  -i, --imports   Prints a list of all imported dependencies. Names undecorated if possible.\n"
        << "  -a, --all       Shorthand option to enable all of the above (except -h/--help, of course).\n"
        << "\n"
        << "Created by Guilherme R. Lampert, " << __DATE__ << ".\n";
}

int main(int argc, const char * argv[])
{
    if (argc <= 1)
    {
        printHelpText(argv[0]);
        return EXIT_FAILURE;
    }

    const ProgramFlags prog = processCmdLine(argc, argv);
    if (prog.printHelpAndExit)
    {
        printHelpText(argv[0]);
        return EXIT_SUCCESS; // Just -h/--help is fine and not an error.
    }

    const char * filename = argv[1];
    if (*filename == '\0' || *filename == '-') // Check for a flag in the wrong place/empty string...
    {
        std::cerr << color::red() << "Invalid filename \""
                  << filename << "\"!" << color::restore() << "\n";
        return EXIT_FAILURE;
    }

    std::size_t fileLength = 0;
    auto fileContents = loadFile(filename, fileLength);
    if (fileContents == nullptr)
    {
        return EXIT_FAILURE;
    }

    std::cout << "\n";
    std::cout << "PE: " << filename << "\n";
    std::cout << "File size in bytes: " << fileLength << "\n";

    const auto dosHeaderPtr =
        reinterpret_cast<const pe::ImageDOSHeader *>(fileContents.get());

    const auto ntHeaderPtr =
        reinterpret_cast<const pe::ImageNTHeader *>(fileContents.get() + dosHeaderPtr->e_lfanew);

    // Validate the DOS header, expected id='MZ'
    if (dosHeaderPtr->e_magic != pe::DOSSignature)
    {
        union
        {
            std::uint16_t u16;
            char c8[2];
        } split;

        split.u16 = dosHeaderPtr->e_magic;
        const char sig[] = { split.c8[0], split.c8[1], '\0' };

        std::cerr << color::red() << "Bad PE DOS signature! Expected \'MZ\', got \'"
                  << sig << "\'!" << color::restore() << "\n";
        return EXIT_FAILURE;
    }

    // Validate the NT header, expected id='PE'
    if (ntHeaderPtr->signature != pe::NTSignature)
    {
        union
        {
            std::uint32_t u32;
            char c8[4];
        } split;

        split.u32 = ntHeaderPtr->signature;
        const char sig[] = { split.c8[0], split.c8[1], split.c8[2], split.c8[3], '\0' };

        std::cerr << color::red() << "Bad PE NT signature! Expected \'PE\', got \'"
                  << sig << "\'!" << color::restore() << "\n";
        return EXIT_FAILURE;
    }

    std::cout << "File is a valid Windows Portable Executable!\n";

    if (!prog.anyFlagSet())
    {
        std::cout << "Run " << argv[0] << " again with -h or --help to get a list of available options.\n";
    }

    if (prog.flagDumpNTHeaders)
    {
        dumpNTHeaders(ntHeaderPtr);
    }
    if (prog.flagDumpDOSJunk)
    {
        dumpDOSJunk(dosHeaderPtr);
    }
    if (prog.flagDumpSectionHeaders)
    {
        dumpSectionHeaders(ntHeaderPtr);
    }
    if (prog.flagDumpExportsSection)
    {
        dumpExportsSection(dosHeaderPtr, ntHeaderPtr);
    }
    if (prog.flagDumpImportsSection)
    {
        dumpImportsSection(dosHeaderPtr, ntHeaderPtr);
    }

    std::cout << "\n";
}
