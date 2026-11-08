// SPDX-License-Identifier: LGPL-2.1-or-later
// Older desktop packages declare the MSA client in xboxservices.config.
// Only use a sibling declaration for the same title, never infer an identity.
#pragma once
#include "Configuration.h"
#include <charconv>
#include <cmath>
#include <cstring>
#include <cwchar>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace nexus
{
inline HRESULT ParseLegacyServiceClient( const char *bytes, SIZE_T size, UINT32 expectedTitle,
                                        std::string &client )
{
    IJsonValueStatics *factory = nullptr;
    IJsonValue *value = nullptr, *title = nullptr;
    IJsonObject *object = nullptr;
    HSTRING name = nullptr, json = nullptr, key = nullptr, id = nullptr, titleText = nullptr;
    std::wstring wide;
    UINT32 length = 0, parsedTitle = 0;
    const WCHAR *text;
    DOUBLE number;
    HRESULT hr, com;
    client.clear();
    client.reserve(16);
    if ( !bytes || !size || size > 65536 || !expectedTitle ) return E_INVALIDARG;
    int count = MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, bytes, size, nullptr, 0 );
    if ( !count ) return E_INVALIDARG;
    wide.resize( count );
    if ( MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, bytes, size, wide.data(), count ) != count )
        return E_INVALIDARG;
    com = CoInitializeEx( nullptr, COINIT_MULTITHREADED );
    if ( FAILED( com ) && com != RPC_E_CHANGED_MODE ) return com;
    if ( FAILED( hr = WindowsCreateString( RuntimeClass_Windows_Data_Json_JsonValue,
                         wcslen( RuntimeClass_Windows_Data_Json_JsonValue ), &name ) ) ||
         FAILED( hr = WindowsCreateString( wide.data(), count, &json ) ) ||
         FAILED( hr = RoGetActivationFactory( name, __uuidof( IJsonValueStatics ), (void **)&factory ) ) ||
         FAILED( hr = factory->Parse( json, &value ) ) || FAILED( hr = value->GetObject( &object ) ) ||
         FAILED( hr = WindowsCreateString( L"ClientId", 8, &key ) ) ) goto done;
    hr = object->GetNamedString( key, &id );
    if ( hr == WEB_E_JSON_VALUE_NOT_FOUND ) { hr = S_FALSE; goto done; }
    if ( FAILED( hr ) ) goto done;
    text = WindowsGetStringRawBuffer( id, &length );
    if ( length != 16 ) { hr = E_INVALIDARG; goto done; }
    {
        bool nonzero = false;
        for ( UINT32 i = 0; i < length; ++i )
        {
            if ( !((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'A' && text[i] <= 'F') ||
                   (text[i] >= 'a' && text[i] <= 'f')) ) { hr = E_INVALIDARG; goto done; }
            nonzero |= text[i] != '0';
        }
        if ( !nonzero ) { hr = E_INVALIDARG; goto done; }
    }
    WindowsDeleteString( key ); key = nullptr;
    if ( FAILED( hr = WindowsCreateString( L"TitleId", 7, &key ) ) ||
         FAILED( hr = object->GetNamedValue( key, &title ) ) ) goto done;
    hr = title->GetNumber( &number );
    if ( SUCCEEDED( hr ) )
    {
        if ( !std::isfinite( number ) || number <= 0 || number > MAXDWORD || std::floor( number ) != number )
        { hr = E_INVALIDARG; goto done; }
        parsedTitle = (UINT32)number;
    }
    else
    {
        if ( FAILED( hr = title->GetString( &titleText ) ) ) goto done;
        UINT32 n;
        const WCHAR *raw = WindowsGetStringRawBuffer( titleText, &n );
        char ascii[11];
        if ( !n || n >= sizeof(ascii) ) { hr = E_INVALIDARG; goto done; }
        for ( UINT32 i = 0; i < n; ++i )
        {
            if ( raw[i] > 127 ) { hr = E_INVALIDARG; goto done; }
            ascii[i] = (char)raw[i];
        }
        std::string_view input( ascii, n );
        int base = 10;
        if ( input.starts_with("0x") || input.starts_with("0X") ) { input.remove_prefix(2); base = 16; }
        auto result = std::from_chars( input.data(), input.data()+input.size(), parsedTitle, base );
        if ( base == 10 && (result.ec != std::errc{} || result.ptr != input.data()+input.size()) )
            result = std::from_chars( input.data(), input.data()+input.size(), parsedTitle, 16 );
        if ( result.ec != std::errc{} || result.ptr != input.data()+input.size() || !parsedTitle )
        { hr = E_INVALIDARG; goto done; }
    }
    if ( parsedTitle != expectedTitle ) { hr = E_INVALIDARG; goto done; }
    for ( UINT32 i = 0; i < length; ++i ) client.push_back( (char)text[i] );
    hr = S_OK;
done:
    if ( title ) title->Release();
    if ( object ) object->Release();
    if ( value ) value->Release();
    if ( factory ) factory->Release();
    WindowsDeleteString(name); WindowsDeleteString(json); WindowsDeleteString(key);
    WindowsDeleteString(id); WindowsDeleteString(titleText);
    if ( SUCCEEDED(com) ) CoUninitialize();
    return hr;
}

/* A manifest executable name is a package-relative path. It may contain
 * subdirectories, but never an absolute path, an empty, "." or ".." component,
 * a drive, a wildcard or a control character. */
inline bool ValidDeclaredExecutable( std::wstring_view name ) noexcept
{
    if ( name.empty() || name.size() > 32768 ) return false;
    if ( name.front() == L'\\' || name.front() == L'/' ) return false;
    size_t start = 0;
    for ( ;; )
    {
        size_t end = name.find_first_of( L"\\/", start );
        if ( end == std::wstring_view::npos ) end = name.size();
        auto part = name.substr( start, end - start );
        if ( part.empty() || part == L"." || part == L".." ||
             part.find_first_of( L":<>\"|?*" ) != std::wstring_view::npos )
            return false;
        for ( wchar_t c : part )
            if ( c < 0x20 ) return false;
        if ( end == name.size() ) break;
        start = end + 1;
    }
    return true;
}

inline bool DeclaredExecutablePath( const GameConfiguration &config, std::wstring_view name,
                                    std::wstring &path )
{
    if ( !ValidDeclaredExecutable( name ) || config.directory.empty() ) return false;
    std::wstring result = config.directory;
    if ( result.back() != L'\\' && result.back() != L'/' ) result.push_back( L'\\' );
    for ( wchar_t c : name ) result.push_back( c == L'/' ? L'\\' : c );
    if ( result.size() >= 32768 ) return false;
    path = std::move( result );
    return true;
}

/* The manifest declares the package-relative executable paths. Return the
 * directory of the declaration that names the currently running module. No
 * other directory is inferred, searched or read. */
inline HRESULT DeclaredExecutableDirectory( const GameConfiguration &config, const WCHAR *modulePath,
                                            std::wstring &directory )
{
    directory.clear();
    if ( !modulePath || !*modulePath || config.directory.empty() ) return S_OK;
    bool matched = false;
    for ( const auto &list : config.game.children )
    {
        if ( list.name != "ExecutableList" ) continue;
        for ( const auto &executable : list.children )
        {
            if ( executable.name != "Executable" ) continue;
            std::wstring name, path;
            if ( FAILED( ToUtf16( executable.attribute( "Name" ), name ) ) ||
                 !DeclaredExecutablePath( config, name, path ) )
                continue;
            if ( _wcsicmp( path.c_str(), modulePath ) ) continue;
            auto slash = path.find_last_of( L"\\/" );
            std::wstring candidate = slash == std::wstring::npos ? config.directory : path.substr( 0, slash );
            if ( !matched )
            {
                directory = std::move( candidate );
                matched = true;
            }
            else if ( _wcsicmp( directory.c_str(), candidate.c_str() ) )
                return E_INVALIDARG;
        }
    }
    return S_OK;
}

inline HRESULT ReadLegacyClientFile( const std::wstring &path, UINT32 expectedTitle, std::string &client,
                                     bool &present )
{
    client.clear();
    present = false;
    HANDLE file = CreateFileW( path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, nullptr );
    if ( file == INVALID_HANDLE_VALUE )
    {
        DWORD error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ? S_OK : HRESULT_FROM_WIN32( error );
    }
    present = true;
    std::string bytes( 65536, '\0' );
    LARGE_INTEGER size;
    DWORD read = 0;
    HRESULT hr = E_INVALIDARG;
    if ( GetFileType( file ) == FILE_TYPE_DISK && GetFileSizeEx( file, &size ) && size.QuadPart > 0 &&
         size.QuadPart <= 65536 )
    {
        bytes.resize( static_cast<size_t>( size.QuadPart ) );
        if ( ReadFile( file, bytes.data(), static_cast<DWORD>( bytes.size() ), &read, nullptr ) &&
             read == bytes.size() )
            hr = S_OK;
    }
    CloseHandle( file );
    if ( FAILED( hr ) ) return hr;
    hr = ParseLegacyServiceClient( bytes.data(), bytes.size(), expectedTitle, client );
    if ( hr == S_FALSE )
    {
        client.clear();
        return S_OK;
    }
    return hr;
}

/* Load a legacy client from the manifest directory and, only when the manifest
 * declares the running executable in a subdirectory, from that executable's
 * directory. Both locations are package-owned and title-matched. A present but
 * malformed file, or two different valid clients, fails closed. */
inline HRESULT LoadLegacyServiceClientForModule( GameConfiguration &config, const WCHAR *modulePath )
{
    if ( !config.msaAppId.empty() || config.game.attribute( "configVersion" ) != "0" || config.directory.empty() )
        return S_OK;
    std::vector<std::wstring> directories;
    directories.push_back( config.directory );
    std::wstring executableDirectory;
    HRESULT hr = DeclaredExecutableDirectory( config, modulePath, executableDirectory );
    if ( FAILED( hr ) ) return hr;
    if ( !executableDirectory.empty() && _wcsicmp( executableDirectory.c_str(), config.directory.c_str() ) )
        directories.push_back( std::move( executableDirectory ) );
    bool found = false;
    std::string chosen;
    for ( const auto &directory : directories )
    {
        std::string client;
        bool present = false;
        hr = ReadLegacyClientFile( directory + L"\\xboxservices.config", config.titleId, client, present );
        if ( FAILED( hr ) ) return hr;
        if ( !present || client.empty() ) continue;
        if ( !found )
        {
            chosen = client;
            found = true;
        }
        else if ( _stricmp( chosen.c_str(), client.c_str() ) )
            return E_INVALIDARG;
    }
    if ( found )
    {
        config.msaAppId = std::move( chosen );
        config.msaAppIdSource = MsaAppIdSource::Legacy;
    }
    return S_OK;
}

inline HRESULT LoadLegacyServiceClient( GameConfiguration &config )
{
    if ( !config.msaAppId.empty() || config.game.attribute( "configVersion" ) != "0" || config.directory.empty() )
        return S_OK;
    WCHAR modulePath[32768];
    DWORD length = GetModuleFileNameW( nullptr, modulePath, ARRAYSIZE( modulePath ) );
    if ( !length || length >= ARRAYSIZE( modulePath ) ) modulePath[0] = 0;
    return LoadLegacyServiceClientForModule( config, modulePath );
}
}
