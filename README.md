
# Portable PE dump

A simple command line tool to dump textual information about Microsoft's Portable Executables (PEs).
Supports 32-bits PEs and partially supports 64-bits ones, but currently no imports/exports for 64-bits PEs.

It can dump:

- DOS header & DOS stub data
- NT headers (AKA the PE header)
- A list of all sections with flags
- A list of all exports (32-bits only)
- A list of all imports (32-bits only)

The aim of this tool is on portability, so that it can be built on systems
other than Windows. To achieve that, no system specific libraries are used,
so symbol name demangling is hand-rolled and not very accurate, but good
enough for most cases.

It should build on any Unix-based system with no hassle, but I've only tested it
on Mac OSX. A Windows build should also be easy, just a matter of creating a VS
project for the two source files (`portable_pe_dump.cpp` and `cxx_demangle.cpp`).

# Build & Run

To build, you can use the provided `Makefile` or directly via the command line, since
the whole project consists of only a pair of files. **Requires a C++11 compiler**.

Running the output `ppedump` will print the available options:

<pre>
Usage:
 $ ./ppedump filename [options]
 Prints information about a Win32 Portable Executable (PE) file.
 PE files are usually ended with the extensions: DLL, EXE, SYS, EFI, among others.
 Options are:
  -h, --help      Prints this message and exits.
  -n, --nthdr     Prints the IMAGE_FILE_HEADER and IMAGE_OPTIONAL_HEADER.
  -d, --doshdr    Prints the IMAGE_DOS_HEADER and an hexadecimal dump of the DOS stub.
  -s, --sections  Prints a short summary of each PE section.
  -e, --exports   Prints a list of all exported symbols. Names undecorated if possible.
  -i, --imports   Prints a list of all imported dependencies. Names undecorated if possible.
  -a, --all       Shorthand option to enable all of the above (except -h/--help, of course).
</pre>

Here's a sample of what the output looks like when called with the `--all` option:

<pre>
./ppedump Storm.dll --all

PE: Storm.dll
File size in bytes: 339968
File is a valid Windows Portable Executable!

------------------------------------------------------------
            NT Headers
------------------------------------------------------------

---- IMAGE_FILE_HEADER ----
Machine architecture.....: INTEL_I386
Number of sections.......: 5
Timestamp................: 0x4D83B8D2 => Fri Mar 18 16:56:02 2011
Pointer to symbol table..: 0
Number of symbols........: 0
Optional header size.....: 224
Image characteristics....: EXE DLL

---- IMAGE_OPTIONAL_HEADER ----
Magic....................: 0x10B
Code size................: 262144
Initialized data size....: 73728
Uninitialized data size..: 0
Number of RVAs and sizes.: 16
Address of entry point...: 0x33610
Subsystem................: WINDOWS_GUI
DLL Characteristics......: 0

------------------------------------------------------------
            IMAGE_DOS_HEADER and DOS stub
------------------------------------------------------------

4D5A9000 03000000 04000000 FFFF0000 B8000000 00000000 | MZ                       |
40000000 00000000 00000000 00000000 00000000 00000000 | @                        |
00000000 00000000 00000000 10010000 0E1FBA0E 00B409CD |                          |
21B8014C CD215468 69732070 726F6772 616D2063 616E6E6F | !  L !This program canno |
74206265 2072756E 20696E20 444F5320 6D6F6465 2E0D0D0A | t be run in DOS mode.    |
24000000 00000000 25F1AE3E 6190C06D 6190C06D 6190C06D | $       %  >a  ma  ma  m |
35B3F06D 6B90C06D 6190C06D 6390C06D A29F9D6D 6D90C06D | 5  mk  ma  mc  m   mm  m |
6190C16D 6D91C06D 4656BB6D 6290C06D F654BE6D 6090C06D | a  mm  mFV mb  m T m`  m |
4656AD6D 6C90C06D 4656BD6D 6B90C06D 4656AE6D 5090C06D | FV ml  mFV mk  mFV mP  m |
4656BA6D 6090C06D 4656BC6D 6090C06D 4656B86D 6090C06D | FV m`  mFV m`  mFV m`  m |
52696368 6190C06D 00000000 00000000 00000000 00000000 | Richa  m                 |
00000000 00000000                                     |                          |

------------------------------------------------------------
            IMAGE_SECTION_HEADERS
------------------------------------------------------------

Number       Name       Flags        Flag strings
------       ----       -----        ------------
Section 0:  .text    0x60000020  ( CODE | MEM_EXECUTE | MEM_READ )
Section 1:  .rdata   0x40000040  ( INITIALIZED_DATA | MEM_READ )
Section 2:  .data    0xC0000040  ( INITIALIZED_DATA | MEM_READ | MEM_WRITE )
Section 3:  .rsrc    0x40000040  ( INITIALIZED_DATA | MEM_READ )
Section 4:  .reloc   0x42000040  ( INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ )
5 sections listed.

------------------------------------------------------------
            Listing exports from  .rdata
------------------------------------------------------------

PE Name...........: Storm.dll
Num of functions..: 814
Num of names......: 53
Ordinal base......: 101

Ordn.          Func name                           Mangled name
-----          ---------                           ------------
0x01F  CDebugSCritSect::CDebugSCritSect()    ??0CDebugSCritSect@@QAE@XZ
0x039  CDebugSCritSect::Enter()              ?Enter@CDebugSCritSect@@QAEXPBDK@Z
0x041  CDebugSCritSect::Leave()              ?Leave@CDebugSCritSect@@QAEXPBDK@Z
0x02D  CDebugSCritSect::~CDebugSCritSect()   ??1CDebugSCritSect@@QAE@XZ
0x028  CDebugSRWLock::CDebugSRWLock()        ??0CDebugSRWLock@@QAE@XZ
0x03A  CDebugSRWLock::Enter()                ?Enter@CDebugSRWLock@@QAEXHPBDK@Z
0x042  CDebugSRWLock::Leave()                ?Leave@CDebugSRWLock@@QAEXHPBDK@Z
0x02E  CDebugSRWLock::~CDebugSRWLock()       ??1CDebugSRWLock@@QAE@XZ
0x029  CSRWLock::CSRWLock()                  ??0CSRWLock@@QAE@XZ
0x03B  CSRWLock::Enter()                     ?Enter@CSRWLock@@QAEXH@Z
0x043  CSRWLock::Leave()                     ?Leave@CSRWLock@@QAEXH@Z
0x02F  CSRWLock::~CSRWLock()                 ??1CSRWLock@@QAE@XZ
0x04C  SCreateThread()                       ?SCreateThread@@YIPAXP6GIPAX@Z0PAI0PAD@Z
0x03C  SCritSect::Enter()                    ?Enter@SCritSect@@QAEXXZ
0x044  SCritSect::Leave()                    ?Leave@SCritSect@@QAEXXZ
0x02A  SCritSect::SCritSect()                ??0SCritSect@@QAE@XZ
0x030  SCritSect::~SCritSect()               ??1SCritSect@@QAE@XZ
0x04A  SEvent::Reset()                       ?Reset@SEvent@@QAEHXZ
0x02B  SEvent::SEvent()                      ??0SEvent@@QAE@HH@Z
0x057  SEvent::Set()                         ?Set@SEvent@@QAEHXZ

[more lines omitted for brevity]
...

------------------------------------------------------------
            Listing imports from  .rdata
------------------------------------------------------------

--------------------
  External modules
--------------------

  MSVCR80.dll
  VERSION.dll
  KERNEL32.dll
  USER32.dll
  GDI32.dll
  comdlg32.dll
  ADVAPI32.dll

---------------------
  Ordn.   Func name
---------------------

MSVCR80.dll
  0x0036  type_info::_type_info_dtor_internal_method()
  0x0153  crt_debugger_hook()
  0x053A  memset()
  0x006D  _CppXcptFilter()
  0x0113  adjust_fdiv()
  0x011D  amsg_exit()
  0x0211  initterm_e()
  0x0210  initterm()
  0x0173  encoded_null()
  0x04F4  free()
  0x0293  malloc_crt()
  0x017B  except_handler4_common()
  0x0043  terminate()
  0x0168  decode_pointer()
  0x0328  onexit()
  0x0282  lock()
  0x0172  encode_pointer()
  0x0099  _dllonexit()
  0x03F3  unlock()
  0x04E1  ferror()
  0x03AC  strlwr()
  0x0377  snprintf()
  0x055E  strchr()
  0x050E  isdigit()
  0x058E  vsprintf()
  0x04EA  fopen()
  0x04DF  fclose()
  0x04FA  fseek()
  0x04FC  ftell()
  0x0192  fileno()
  0x01B9  fstat64i32()
  0x04F2  fread()
  0x0538  memmove()
  0x01C2  fullpath()
  0x0583  toupper()
  0x0417  vsnprintf()
  0x056E  strpbrk()
  0x05AF  wcstombs()
  0x0551  setlocale()
  0x039E  stat64i32()
  0x03C4  strupr()
  0x0339  purecall()
  0x056A  strncmp()
  0x03B2  strnicmp()
  0x0571  strstr()
  0x0575  strtol()
  0x0576  strtoul()
  0x03A8  stricmp()
  0x0536  memcpy()
  0x0076  _CxxFrameHandler3()
  0x0545  qsort()
  0x056B  strncpy()
  0x056F  strrchr()
  0x0556  sprintf()
  0x0512  isprint()
  0x008F  _clean_type_info_names_internal()
  0x04D4  calloc()

VERSION.dll
  0x0001  GetFileVersionInfoSizeA()
  0x0000  GetFileVersionInfoA()
  0x000A  VerQueryValueA()

KERNEL32.dll
  0x036E  UnhandledExceptionFilter()
  0x02D2  ResumeThread()
  0x01DB  GetThreadPriority()
  0x0385  VirtualLock()
  0x038A  VirtualUnlock()
  0x0066  CreateProcessA()
  0x01C8  GetSystemTime()
  0x035B  SystemTimeToFileTime()
  0x0383  VirtualFree()
  0x0381  VirtualAlloc()
  0x00EE  FlushFileBuffers()
  0x038E  WaitForMultipleObjects()

[more lines omitted for brevity]
...
</pre>

# License

This project's source code is released under the [MIT License](http://opensource.org/licenses/MIT).


