
// ================================================================================================
// -*- C++ -*-
// File: cxx_demangle.cpp
// Author: Guilherme R. Lampert
// Created on: 11/11/15
// Brief: MSFT Visual C++ name demangling. Uses a hand-rolled implementation for Unix-based systems.
//
// Source code licensed under the MIT license.
// Copyright (C) 2015 Guilherme R. Lampert
//
// This software is provided "as is" without express or implied
// warranties. You may freely copy and compile this source into
// applications you distribute provided that this copyright text
// is included in the resulting source code.
// ================================================================================================

#include <cctype>
#include <string>
#include <map>

/*
-------------------------------------
Portable C++ function name demangling
-------------------------------------

Visual Studio C++ compiler unsurprisingly uses a custom C++ name mangling
scheme for exported symbols in DLLs and executables, so the __cxa_demangle
function from GCC/Clang is useless.

    #include <cxxabi.h>

    int result = 0;
    std::string str;
    char * demangledName = abi::__cxa_demangle(mangledName, nullptr, nullptr, &result);
    if (demangledName == nullptr || result != 0)
    {
        str = mangledName; // Failed, return original.
    }
    else
    {
        str = demangledName; // Okay.
    }
    std::free(demangledName);
    return str;

From the resources presented here <http://www.kegel.com/mangle.html> we can
write a simple demangler for the MSFT compiler as a fallback when trying to
undecorate symbols on a non-Windows environment. On Windows we can just use
UnDecorateSymbolName() from the WinAPI.

This implementation is probably flawed in several aspects, but should be able
to undecorate the most common method and function names. It will obviously
break if the naming scheme is ever changed. Names that cannot be demangled
are simply returned unchanged. C names that are not mangled are also returned
unchanged (except for a leading underscore that might be removed).

UPDATE
 Even more detailed info found in the following pages:
  http://www.geoffchappell.com/studies/msvc/language/decoration/functions.htm
  http://www.geoffchappell.com/studies/msvc/language/decoration/name.htm
  http://mearie.org/documents/mscmangle/

-------------------------------------
*/

static std::string getCallConv(const char code)
{
    static const std::map<char, std::string> callConvs{
        { 'A', "__cdecl   " },
        { 'I', "__fastcall" },
        { 'E', "__thiscall" },
        { 'G', "__stdcall " }
    };
    auto iter = callConvs.find(code);
    return (iter != std::end(callConvs)) ? iter->second : "";
}

static std::string getTypeName(const char code)
{
    static const std::map<char, std::string> types{
        { 'C', "signed char   " },
        { 'D', "char          " },
        { 'E', "unsigned char " },
        { 'F', "short         " },
        { 'G', "unsigned short" },
        { 'H', "int           " },
        { 'I', "unsigned int  " },
        { 'J', "long          " },
        { 'K', "unsigned long " },
        { 'M', "float         " },
        { 'N', "double        " },
        { 'O', "long double   " },
        // These are just placeholders. A better demangler
        // would replace them with the actual type names.
        { 'P', "void*         " },
        { 'Q', "void[]        " },
        { 'U', "struct*       " },
        { 'V', "class*        " },
        { 'X', "void          " },
        { 'Z', "...           " }
    };
    auto iter = types.find(code);
    return (iter != std::end(types)) ? iter->second : "";
}

std::string demangle(const char * mangledName, const bool baseNameOnly)
{
    std::string demangledName;
    const char * ptr = mangledName;

    if (ptr == nullptr || *ptr == '\0')
    {
        return demangledName;
    }

    // MSFT C++ names always start with a question mark.
    if (*ptr != '?')
    {
        // Assume a C function with the default underscore prefix,
        // returning the original name minus the underscore. It might
        // also contain more name decoration at the end, so ignore
        // anything after the first '@' character.
        if (*ptr == '_')
        {
            for (++ptr; *ptr != '\0' && *ptr != '@'; ++ptr)
            {
                demangledName.push_back(*ptr);
            }
        }
        else
        {
            demangledName = ptr;
        }
        return demangledName + "()";
    }

    // Skip over the first '?'
    ++ptr;

    std::string funcName;
    std::string className;
    std::string callConv;
    std::string retType;

    // Now copy until an '@' or the end of the string to extract the function name:
    for (; *ptr != '\0' && *ptr != '@'; ++ptr)
    {
        funcName.push_back(*ptr);
    }

    // Same for the class name that follows if present:
    if (*ptr == '@')
    {
        for (++ptr; *ptr != '\0' && *ptr != '@'; ++ptr)
        {
            className.push_back(*ptr);
        }

        // Trailing '@'s after class name.
        for (; *ptr == '@' && *ptr != '\0'; ++ptr)
        {
        }
    }

    // NOTE: Parameter list info is available but it's not being handled!
    if (!className.empty())
    {
        // A special member function: operators or constructor/destructor
        // (from a nested subclass... I'm no 100% sure if that's it, but looks like it...)
        if (funcName.length() >= 2 && funcName[0] == '?')
        {
            if (funcName[1] == '0') // Constructor
            {
                funcName = funcName.substr(2);
                demangledName = className + "::" + funcName + "::" + funcName + "()";
            }
            else if (funcName[1] == '1') // Destructor
            {
                funcName = funcName.substr(2);
                demangledName = className + "::" + funcName + "::~" + funcName + "()";
            }
            else if (funcName[1] == '4') // operator =
            {
                demangledName = className + "::" + funcName.substr(2) + "::operator=()";
            }
            else // The rest is currently ignored, but there's one for each num until 9 + A to Z.
            {
                std::size_t i;
                for (i = 0; i < funcName.length(); ++i)
                {
                    if (funcName[i] != '?' && funcName[i] != '_' && std::isalpha(funcName[i]))
                    {
                        break;
                    }
                }
                demangledName = className + "::" + funcName.substr(i) + "::???";
            }
        }
        else
        {
            // Apparently this is a template class...
            if (className.length() >= 2 && className[0] == '?' && className[1] == '$')
            {
                className = className.substr(2);
                className += "<T>";
            }

            if (!baseNameOnly) // Just the Class::Method() part?
            {
                // 'Q' should follow the '@' that separated a class name. Apparently meaningless.
                // 'S'/'2' I'm not sure... Does it mean a static class method???
                for (; *ptr != '\0' && (*ptr == 'Q' || *ptr == 'S' || *ptr == '2'); ++ptr)
                {
                }
                callConv += getCallConv(*ptr++);

                // The '_' is a qualifier for "extended types", whatever that means.
                // It might precede the return type character.
                if (*ptr == '_')
                {
                    ++ptr;
                }
                retType += getTypeName(*ptr++);

                if (!callConv.empty())
                {
                    callConv += " ";
                }
                if (!retType.empty())
                {
                    retType += " ";
                }
            }
            demangledName = retType + callConv + className + "::" + funcName + "()";
        }
    }
    else
    {
        // A special member function: operators or constructor/destructor
        if (funcName.length() >= 2 && funcName[0] == '?')
        {
            if (funcName[1] == '0') // Constructor
            {
                funcName = funcName.substr(2);
                demangledName = funcName + "::" + funcName + "()";
            }
            else if (funcName[1] == '1') // Destructor
            {
                funcName = funcName.substr(2);
                demangledName = funcName + "::~" + funcName + "()";
            }
            else if (funcName[1] == '4') // operator =
            {
                demangledName = funcName.substr(2) + "::operator=()";
            }
            else // The rest is currently ignored, but there's one for each num until 9 + A to Z.
            {
                std::size_t i;
                for (i = 0; i < funcName.length(); ++i)
                {
                    if (funcName[i] != '?' && funcName[i] != '_' && std::isalpha(funcName[i]))
                    {
                        break;
                    }
                }
                demangledName = className + "::" + funcName.substr(i) + "::???";
            }
        }
        else
        {
            if (!baseNameOnly) // Just the Function() part?
            {
                // 'Y' should follow the '@'.
                // Probably just to differentiate from a class method...
                if (*ptr == 'Y')
                {
                    ++ptr;
                }
                callConv += getCallConv(*ptr++);

                if (*ptr == '_')
                {
                    ++ptr;
                }
                retType += getTypeName(*ptr++);

                if (!callConv.empty())
                {
                    callConv += " ";
                }
                if (!retType.empty())
                {
                    retType += " ";
                }
            }
            demangledName = retType + callConv + funcName + "()";
        }
    }

    return demangledName;
}
