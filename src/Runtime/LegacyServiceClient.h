// SPDX-License-Identifier: LGPL-2.1-or-later
// Older desktop packages declare the MSA client in xboxservices.config.
// Only use a sibling declaration for the same title, never infer an identity.
#pragma once
#include "Configuration.h"
#include <charconv>
#include <cmath>
#include <string>
#include <string_view>

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

inline HRESULT LoadLegacyServiceClient( GameConfiguration &config )
{
    // Inline configurations have no trusted sibling directory. Explicit modern
    // declarations always win, including when a legacy file is malformed.
    if ( !config.msaAppId.empty() || config.game.attribute("configVersion") != "0" || config.directory.empty() )
        return S_OK;
    const auto path = config.directory + L"\\xboxservices.config";
    std::string bytes(65536, '\0');
    HANDLE file = CreateFileW( path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, nullptr );
    if ( file == INVALID_HANDLE_VALUE )
    {
        DWORD error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ? S_OK : HRESULT_FROM_WIN32(error);
    }
    LARGE_INTEGER size;
    DWORD read = 0;
    HRESULT hr = E_INVALIDARG;
    if ( GetFileType(file) == FILE_TYPE_DISK && GetFileSizeEx(file,&size) && size.QuadPart > 0 && size.QuadPart <= 65536 )
    {
        bytes.resize( (size_t)size.QuadPart );
        if ( ReadFile(file,bytes.data(),(DWORD)bytes.size(),&read,nullptr) && read == bytes.size() ) hr = S_OK;
    }
    CloseHandle(file);
    if ( FAILED(hr) ) return hr;
    std::string client;
    hr = ParseLegacyServiceClient(bytes.data(),bytes.size(),config.titleId,client);
    if ( hr == S_OK )
    {
        config.msaAppId = std::move(client);
        config.msaAppIdSource = MsaAppIdSource::Legacy;
    }
    return hr == S_FALSE ? S_OK : hr;
}
}
