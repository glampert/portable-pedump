
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
#include <algorithm>
#include <unordered_map>

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

namespace
{

enum MangledIds
{
    ConstructorId    = '0',
    DestructorId     = '1',
    OperatorAssignId = '4'
    // The rest is currently unimplemented, but there's
    // one for each number from 0 to 9 + A to Z letters.
};

std::string getCallConv(const char code)
{
    static const std::unordered_map<char, std::string> callConvs{
        { 'A', "__cdecl   " },
        { 'I', "__fastcall" },
        { 'E', "__thiscall" },
        { 'G', "__stdcall " }
    };
    auto iter = callConvs.find(code);
    return (iter != std::end(callConvs)) ? iter->second : "";
}

std::string getTypeName(const char code)
{
    static const std::unordered_map<char, std::string> types{
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
        // The following are just placeholders. A better demangler
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

// A start/end range of iterators for our substrings.
template<class Iter>
struct Range
{
    Iter start;
    Iter end;
};

using CStrRange = Range<std::string::const_iterator>;

template<class Iter>
std::string makeStr(const Range<Iter> & r)
{
    return std::string(r.start, r.end);
}

template<class Iter>
int length(const Range<Iter> & r)
{
    return static_cast<int>(std::distance(r.start, r.end));
}

template<class Iter>
bool endOfNameSection(const Range<Iter> & r, Iter theEnd)
{
    // "@@" terminates all names.
    if (r.end  == theEnd ||  (r.end + 1) == theEnd) { return true; }
    if (*r.end == '@'    && *(r.end + 1) == '@')    { return true; }
    return false;
}

template<class Iter>
Range<Iter> extractSubName(Iter start, Iter end)
{
    // Return new range of extract name + iterator to where it ended.
    return { start, std::find(start, end, '@') };
}

template<class Iter>
std::string demangleCFunc(const Range<Iter> & rMangled)
{
    //
    // Assume a C function with the default underscore prefix,
    // returning the original name minus the underscore. It might
    // also contain more name decoration at the end, so ignore
    // anything after the first '@' character. Some unusual symbols
    // (probably global variables) appear to also start with an at-sign.
    // We can treat those like a C function as well.
    //
    auto nameStart = (*rMangled.start == '_' || *rMangled.start == '@') ?
                     (rMangled.start + 1) : rMangled.start;

    return makeStr(extractSubName(nameStart, rMangled.end)) + "()";
}

template<class Iter>
std::string demangleClass(const Range<Iter> & rClassName, const Range<Iter> & rFuncName,
                          Iter mangledNameEnd, const bool baseNameOnly)
{
    std::string className;
    std::string callConv;
    std::string retType;

    // Apparently this is a template class...
    if (length(rClassName) >= 2 && *rClassName.start == '?' && *(rClassName.start + 1) == '$')
    {
        className.assign(rClassName.start + 2, rClassName.end);
        className += "<T>";
    }
    else
    {
        className = makeStr(rClassName);
    }

    // Just the Class::Method() part?
    if (!baseNameOnly)
    {
        // 'Q' should follow the '@' that separated a class name.
        // 'S'/'2' I'm not sure... Does it mean a static class method? Ignored for now.
        auto iter = std::find_if(rClassName.end, mangledNameEnd,
                                 [](const char c) { return !(c == '@' || c == 'Q' ||
                                                             c == 'S' || c == '2'); });

        if (iter != mangledNameEnd)
        {
            callConv = getCallConv(*iter++);

            // The '_' is a qualifier for "extended types", which we don't
            // currently handle. It might precede the return type character.
            if (*iter == '_') { ++iter; }
            retType = getTypeName(*iter++);

            if (!callConv.empty()) { callConv += " "; }
            if (!retType.empty())  { retType  += " "; }
        }
    }

    return retType + callConv + className + "::" + makeStr(rFuncName) + "()";
}

template<class Iter>
std::string demangleCppFunc(const Range<Iter> & rFuncName, Iter mangledNameEnd,
                            const bool baseNameOnly)
{
    std::string callConv;
    std::string retType;

    // Just the Function() part?
    if (!baseNameOnly)
    {
        // 'Y' should follow the '@'s after a function name.
        // It probably serves the purpose of differentiating
        // it from a class method.
        auto iter = std::find_if(rFuncName.end, mangledNameEnd,
                                 [](const char c) { return !(c == '@' || c == 'Y'); });

        if (iter != mangledNameEnd)
        {
            callConv = getCallConv(*iter++);

            // The '_' is a qualifier for "extended types", which we don't
            // currently handle. It might precede the return type character.
            if (*iter == '_') { iter++; }
            retType = getTypeName(*iter++);

            if (!callConv.empty()) { callConv += " "; }
            if (!retType.empty())  { retType  += " "; }
        }
    }

    return retType + callConv + makeStr(rFuncName) + "()";
}

template<class Iter>
std::string demangleSpecial(const Range<Iter> & rFuncName, const Range<Iter> & rClassName)
{
    std::string demangledName;
    std::string className, funcName;

    const bool hasClassName = (length(rClassName) > 0);
    const int  c0 = *(rFuncName.start + 1); // Number that follows a question mark char

    className.assign(rClassName.start, rClassName.end);
    funcName.assign(rFuncName.start + 2, rFuncName.end);

    switch (c0)
    {
    case ConstructorId :
        demangledName = hasClassName ?
            (className + "::" + funcName + "::" + funcName + "()") :
            (funcName  + "::" + funcName + "()");
        break;

    case DestructorId :
        demangledName = hasClassName ?
            (className + "::"  + funcName + "::~" + funcName + "()") :
            (funcName  + "::~" + funcName + "()");
        break;

    case OperatorAssignId :
        demangledName = hasClassName ?
            (className + "::" + funcName + "::operator=()") :
            (funcName  + "::operator=()");
        break;

    default : // Unhandled
        {
            std::size_t i;
            for (i = 0; i < funcName.length(); ++i)
            {
                if (funcName[i] != '_' && std::isalpha(funcName[i]))
                {
                    break;
                }
            }
            demangledName = className + "::" + funcName.substr(i) + "::???";
        }
        break;
    } // switch (c0)

    return demangledName;
}

} // namespace {}

// ========================================================
// demangle() - Microsoft C++ name demangling entry point
//
//  Remarks:
//   - Parameter list info is available but it is not
//     being handled right now.
//   - You can also get the return type and calling
//     convention by passing false for 'baseNameOnly'.
// ========================================================

std::string demangle(const std::string & mangledName, const bool baseNameOnly)
{
    if (mangledName.empty())
    {
        return mangledName;
    }

    CStrRange rMangled{ mangledName.cbegin(), mangledName.cend() };

    // MSFT C++ names always start with a question mark.
    if (*rMangled.start != '?')
    {
        return demangleCFunc(rMangled);
    }

    // Default initialized to the end of the input string.
    CStrRange rClassName    { rMangled.end, rMangled.end };
    CStrRange rNamespaceName{ rMangled.end, rMangled.end };

    // Function name until the first '@' or end of the string.
    // +1 to skip over the first '?' character.
    CStrRange rFuncName = extractSubName(rMangled.start + 1, rMangled.end);

    // Same for the class name that follows if present:
    if (!endOfNameSection(rFuncName, rMangled.end))
    {
        rClassName = extractSubName(rFuncName.end + 1, rMangled.end);
    }

    // And a namespace might also be available, but only
    // if there aren't two consecutive at-signs following.
    if (!endOfNameSection(rClassName, rMangled.end))
    {
        rNamespaceName = extractSubName(rClassName.end + 1, rMangled.end);
    }

    std::string demangledName;
    if (length(rFuncName) >= 2 && *rFuncName.start == '?')
    {
        // A special member function: operators or constructor/destructor
        demangledName = demangleSpecial(rFuncName, rClassName);
    }
    else
    {
        demangledName = (length(rClassName) > 0) ?
                demangleClass(rClassName, rFuncName, rMangled.end, baseNameOnly) :
                demangleCppFunc(rFuncName, rMangled.end, baseNameOnly);
    }

    if (length(rNamespaceName) > 0)
    {
        return makeStr(rNamespaceName) + "::" + demangledName;
    }
    else
    {
        return demangledName;
    }
}
