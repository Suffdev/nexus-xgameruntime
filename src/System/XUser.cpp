/*
 * Xbox Game runtime Library
 *  GDK Component: System API -> XUser
 *
 * Copyright 2026 Olivia Ryan
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "User/XUserImpl.h"
#include "User/Presence.h"
#include "User/OfflineIdentity.h"
#include "../Runtime/Configuration.h"
#include <afunix.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "../HttpClient.h"

#include <atomic>
#include <new>
#include <type_traits>
#include <cmath>

static WCHAR *WineGetDosFileName( const char *path )
{
    using Convert = WCHAR *( CDECL * )( const char * );
    auto module = GetModuleHandleW( L"kernel32.dll" );
    auto convert = module ? reinterpret_cast<Convert>( GetProcAddress( module, "wine_get_dos_file_name" ) ) : nullptr;
    return convert ? convert( path ) : nullptr;
}

static const char *GetMsaAppId()
{
    const auto *config = nexus::GetGameConfiguration();
    return config && !config->msaAppId.empty() ? config->msaAppId.c_str() : nullptr;
}
static const char *GetStoreId()
{
    const auto *config = nexus::GetGameConfiguration();
    return config && !config->storeId.empty() ? config->storeId.c_str() : nullptr;
}

static BOOLEAN GetFullTrust()
{
    const auto *config = nexus::GetGameConfiguration();
    return config && config->fullTrust;
}

static bool GetLegacyFullTrust()
{
    const auto *config = nexus::GetGameConfiguration();
    return config && nexus::UsesLegacyFullTrust( *config );
}

#include "User/Privileges.h"

static const WCHAR *ACCEPT_JSON[] = { L"application/json", NULL };

static HRESULT parse_json( const char *json, SIZE_T jsonLen, IJsonObject **object )
{
    static const WCHAR *name = RuntimeClass_Windows_Data_Json_JsonValue;
    IJsonValueStatics *statics;
    HSTRING_HEADER header;
    IJsonValue *value;
    UINT32 wJsonLen;
    HSTRING string;
    WCHAR *wJson;
    HRESULT hr;

    if ( !object ) return E_POINTER;
    *object = nullptr;
    if ( !json || !jsonLen || jsonLen > 4 * 1024 * 1024 ) return E_INVALIDARG;
    if ( !( wJsonLen = MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, json, jsonLen, NULL, 0 ) ) )
        return HRESULT_FROM_WIN32( GetLastError() );
    if ( FAILED( hr = WindowsCreateStringReference( name, wcslen( name ), &header, &string ) ) ) return hr;
    if ( FAILED( hr = RoGetActivationFactory( string, __uuidof( IJsonValueStatics ), ( void ** )&statics ) ) )
        return hr;
    if ( !( wJson =
                static_cast<std::remove_reference_t<decltype( wJson )>>( calloc( wJsonLen + 1, sizeof( WCHAR ) ) ) ) )
    {
        ( statics )->Release();
        return E_OUTOFMEMORY;
    }

    if ( !MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, json, jsonLen, wJson, wJsonLen ) ) goto error;
    if ( FAILED( hr = WindowsCreateStringReference( wJson, wJsonLen, &header, &string ) ) ) goto cleanup;
    if ( FAILED( hr = ( statics )->Parse( string, &value ) ) ) goto cleanup;
    hr = ( value )->GetObject( object );
    ( value )->Release();
    goto cleanup;

error:
    hr = HRESULT_FROM_WIN32( GetLastError() );
cleanup:
    ( statics )->Release();
    free( wJson );
    return hr;
}

/* Identity metadata is optional and never controls authentication success. */
#include "User/AccountMetadata.h"
#include "User/AuthRejectionMetadata.h"
#include "User/TokenEndpoint.h"

/* Private opt-in diagnostics: numeric metadata only, never credentials or URLs.
 * The caller must pre-create the private file; bounded to 32 KiB. */
static void auth_metadata( const char *phase, XUserHandle user, HRESULT hr, DWORD status, BOOL requested_title,
                           BOOL actual_title )
{
    static SRWLOCK lock = SRWLOCK_INIT;
    DWORD saved_error = GetLastError(), length, written;
    char path[MAX_PATH], line[256];
    LARGE_INTEGER size, end;
    HANDLE file;
    unsigned int i;
    static const char *const phases[] = { "sisu",
                                          "resolve-privilege",
                                          "get-token-complete",
                                          "get-token-begin",
                                          "xsts",
                                          "xsts-begin",
                                          "privilege-identity-claim",
                                          "privilege-permissions-claim",
                                          "store-license",
                                          "store-license-begin",
                                          "store-license-size",
                                          "store-license-result",
                                          "store-entitled-result",
                                          "store-addon-license-result",
                                          "store-entitled-receipt",
                                          "store-entitled-inventory",
                                          "store-entitled-metadata",
                                          "init-default-begin",
                                          "init-default-end",
                                          "init-default-parse",
                                          "init-tickets-begin",
                                          "init-tickets-end",
                                          "init-device-begin",
                                          "init-device-end",
                                          "init-sisu-begin",
                                          "init-sisu-end",
                                          "init-current-begin",
                                          "init-current-end",
                                          "init-current-parse",
                                          "init-worker-begin",
                                          "init-attempt-begin",
                                          "init-attempt-end",
                                          "init-retry",
                                          "init-complete",
                                          "user-add-begin",
                                          "user-local-init",
                                          "user-add-complete" };

    length = GetEnvironmentVariableA( "XUSER_AUTH_METADATA_LOG", path, sizeof( path ) );
    if ( !length || length >= sizeof( path ) ) goto done;
    if ( !phase ) goto done;
    for ( i = 0; i < ARRAY_SIZE( phases ); ++i )
        if ( !strcmp( phase, phases[i] ) ) break;
    if ( i == ARRAY_SIZE( phases ) ) goto done;
    length = snprintf( line, sizeof( line ),
                       "AUTH_META phase=%s hr=%08lx http=%lu device=%u user=%u title=%u requested_title=%u "
                       "actual_title=%u tick=%lu thread=%lu\n",
                       phase, ( unsigned long )( UINT32 )hr, ( unsigned long )status, !!( user && user->deviceToken ),
                       !!( user && user->userToken ), !!( user && user->titleToken ), !!requested_title, !!actual_title,
                       ( unsigned long )GetTickCount(), ( unsigned long )GetCurrentThreadId() );
    if ( length >= sizeof( line ) ) goto done;
    AcquireSRWLockExclusive( &lock );
    file = CreateFileA( path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
    if ( file != INVALID_HANDLE_VALUE )
    {
        if ( GetFileType( file ) == FILE_TYPE_DISK && GetFileSizeEx( file, &size ) && size.QuadPart + length <= 32768 )
        {
            end.QuadPart = 0;
            if ( SetFilePointerEx( file, end, NULL, FILE_END ) ) WriteFile( file, line, length, &written, NULL );
        }
        CloseHandle( file );
    }
    ReleaseSRWLockExclusive( &lock );
done:
    SetLastError( saved_error );
}

ULONG WINAPI XUser::AddRef()
{
    auto *impl = this;
    ULONG ref = InterlockedIncrement( &impl->ref );

    return ref;
}

ULONG WINAPI XUser::Release()
{
    auto *impl = this;
    ULONG ref = InterlockedDecrement( &impl->ref );

    if ( !ref )
    {
        if ( impl->key ) BCryptDestroyKey( impl->key );
        if ( impl->signingAlgorithm ) BCryptCloseAlgorithmProvider( impl->signingAlgorithm, 0 );
        if ( impl->proofKey ) free( impl->proofKey );
        if ( impl->userToken ) free( impl->userToken );
        free( impl->deviceToken );
        free( impl->titleToken );
        free( impl->deviceAuth );
        free( impl->deviceAuthAudience );
        if ( impl->policies ) free( impl->policies );
        if ( impl->endpoints )
        {
            for ( UINT32 i = 0; i < impl->endpointsLen; i++ )
            {
                WindowsDeleteString( impl->endpoints[i].protocol );
                WindowsDeleteString( impl->endpoints[i].host );
                WindowsDeleteString( impl->endpoints[i].path );
                WindowsDeleteString( impl->endpoints[i].relyingParty );
                WindowsDeleteString( impl->endpoints[i].tokenType );
            }
            free( impl->endpoints );
        }
        DeleteCriticalSection( &impl->deviceAuthSection );
        delete impl;
    }
    return ref;
}

#define XODUS_XML_MAGIC 0x58445358
#define XODUS_MSA_TOKEN_REQUEST 3

static HRESULT xodus_socket_path( char *path, SIZE_T size )
{
    char unixPath[MAX_PATH];
    WCHAR *dosPath;
    DWORD len;

    if ( !( len = GetEnvironmentVariableA( "XODUS_SOCKET", unixPath, sizeof( unixPath ) ) ) ||
         len >= sizeof( unixPath ) )
    {
        if ( !( len = GetEnvironmentVariableA( "WINE_HOST_XDG_RUNTIME_DIR", unixPath, sizeof( unixPath ) ) ) ||
             len >= sizeof( unixPath ) )
            len = GetEnvironmentVariableA( "XDG_RUNTIME_DIR", unixPath, sizeof( unixPath ) );
        if ( !len || len + strlen( "/xodus.sock" ) >= sizeof( unixPath ) )
            return HRESULT_FROM_WIN32( ERROR_ENVVAR_NOT_FOUND );
        strcat( unixPath, "/xodus.sock" );
    }

    if ( !( dosPath = WineGetDosFileName( unixPath ) ) ) return HRESULT_FROM_WIN32( ERROR_PATH_NOT_FOUND );
    len = WideCharToMultiByte( CP_ACP, 0, dosPath, -1, path, size, NULL, NULL );
    HeapFree( GetProcessHeap(), 0, dosPath );
    return len ? S_OK : HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER );
}

static BOOL xodus_send( SOCKET s, const char *data, int size )
{
    int sent;

    while ( size > 0 )
    {
        if ( ( sent = send( s, data, size, 0 ) ) <= 0 ) return FALSE;
        data += sent;
        size -= sent;
    }
    return TRUE;
}

static BOOL xodus_recv( SOCKET s, char *data, int size )
{
    int received;

    while ( size > 0 )
    {
        if ( ( received = recv( s, data, size, 0 ) ) <= 0 ) return FALSE;
        data += received;
        size -= received;
    }
    return TRUE;
}

static HRESULT xodus_request( UINT16 type, const char *body, UINT16 size, char **response, UINT16 *responseSize )
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    UINT32 magic = XODUS_XML_MAGIC;
    struct sockaddr_in bridge = { 0 };
    UINT16 responseType;
    SOCKET s = INVALID_SOCKET;
    char bridgePort[8], bridgeKey[65], *end;
    char header[8];
    DWORD portLen, keyLen;
    unsigned long port;
    BOOL useBridge;
    WSADATA wsa;
    HRESULT hr;

    portLen = GetEnvironmentVariableA( "XODUS_BRIDGE_PORT", bridgePort, sizeof( bridgePort ) );
    keyLen = GetEnvironmentVariableA( "XODUS_BRIDGE_KEY", bridgeKey, sizeof( bridgeKey ) );
    useBridge = portLen || keyLen;
    if ( useBridge )
    {
        if ( !portLen || portLen >= sizeof( bridgePort ) || keyLen != 64 ) return E_INVALIDARG;
        port = strtoul( bridgePort, &end, 10 );
        if ( *end || !port || port > 65535 ) return E_INVALIDARG;
        bridge.sin_family = AF_INET;
        bridge.sin_port = htons( ( USHORT )port );
        bridge.sin_addr.s_addr = htonl( 0x7f000001 );
    }
    else if ( FAILED( hr = xodus_socket_path( addr.sun_path, sizeof( addr.sun_path ) ) ) )
        return hr;
    if ( WSAStartup( MAKEWORD( 2, 2 ), &wsa ) ) return E_FAIL;

    memcpy( header, &magic, 4 );
    memcpy( header + 4, &type, 2 );
    memcpy( header + 6, &size, 2 );

    if ( useBridge )
    {
        if ( ( s = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP ) ) == INVALID_SOCKET ) goto error;
        if ( type == 5 )
        {
            DWORD timeout = 95000;
            if ( setsockopt( s, SOL_SOCKET, SO_RCVTIMEO, ( char * )&timeout, sizeof( timeout ) ) ||
                 setsockopt( s, SOL_SOCKET, SO_SNDTIMEO, ( char * )&timeout, sizeof( timeout ) ) )
                goto error;
        }
        if ( connect( s, ( struct sockaddr * )&bridge, sizeof( bridge ) ) ) goto error;
        if ( !xodus_send( s, bridgeKey, 64 ) ) goto error;
    }
    else
    {
        if ( ( s = socket( AF_UNIX, SOCK_STREAM, 0 ) ) == INVALID_SOCKET ) goto error;
        if ( type == 5 )
        {
            DWORD timeout = 95000;
            if ( setsockopt( s, SOL_SOCKET, SO_RCVTIMEO, ( char * )&timeout, sizeof( timeout ) ) ||
                 setsockopt( s, SOL_SOCKET, SO_SNDTIMEO, ( char * )&timeout, sizeof( timeout ) ) )
                goto error;
        }
        if ( connect( s, ( struct sockaddr * )&addr, sizeof( addr ) ) ) goto error;
    }
    if ( !xodus_send( s, header, sizeof( header ) ) || !xodus_send( s, body, size ) ) goto error;
    if ( !xodus_recv( s, header, sizeof( header ) ) ) goto error;

    memcpy( &responseType, header + 4, 2 );
    memcpy( responseSize, header + 6, 2 );
    if ( memcmp( header, &magic, 4 ) || responseType != type + 1 || !*responseSize )
    {
        hr = E_UNEXPECTED;
        goto done;
    }
    if ( !( *response =
                static_cast<std::remove_reference_t<decltype( *response )>>( calloc( 1, *responseSize + 1 ) ) ) )
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    if ( !xodus_recv( s, *response, *responseSize ) )
    {
        free( *response );
        *response = NULL;
        goto error;
    }
    hr = S_OK;
    goto done;

error:
    hr = HRESULT_FROM_WIN32( WSAGetLastError() );
    if ( SUCCEEDED( hr ) ) hr = E_FAIL;
done:
    if ( s != INVALID_SOCKET ) closesocket( s );
    WSACleanup();
    return hr;
}

class DefaultUserTransport final : public UserTransport
{
public:
    HRESULT Backend( UINT16 type, const char *body, UINT16 size, char **response, UINT16 *responseSize ) override
    {
        return xodus_request( type, body, size, response, responseSize );
    }
    HRESULT Http( const WCHAR *method, const WCHAR *url, char *body, const WCHAR *headers, const WCHAR **accept,
                  BYTE **response, SIZE_T *responseSize ) override
    {
        return http_request( method, url, body, headers, accept, response, responseSize );
    }
    HRESULT HttpRaw( const WCHAR *method, const WCHAR *url, const WCHAR *headers, const void *body, DWORD bodySize,
                     DWORD *status, BYTE **response, SIZE_T *responseSize ) override
    {
        return http_request_raw( method, url, headers, body, bodySize, status, response, responseSize );
    }
};

UserTransport &GetUserTransport() noexcept
{
    static DefaultUserTransport transport;
    return transport;
}

static char *xml_child_content( xmlNodePtr root, const char *name )
{
    xmlNodePtr child;
    xmlChar *content;
    char *value;

    for ( child = root ? root->children : NULL; child; child = child->next )
    {
        if ( child->type != XML_ELEMENT_NODE || strcmp( ( const char * )child->name, name ) ) continue;
        if ( !( content = xmlNodeGetContent( child ) ) ) return NULL;
        value = strdup( ( const char * )content );
        xmlFree( content );
        return value;
    }
    return NULL;
}

HRESULT xodus_store_package_updates_xml( const char *request, SIZE_T request_size, char **response, UINT16 *size )
{
    if ( !request || !request_size || request_size > 0xffff || !response || !size ) return E_INVALIDARG;
    *response = NULL;
    *size = 0;
    return xodus_request( 9, request, request_size, response, size );
}

HRESULT xodus_store_license_body( const char **product_ids, SIZE_T count, const char *nonce, char **body )
{
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlChar *xml = NULL;
    int size;
    SIZE_T i;

    *body = NULL;
    if ( !GetStoreId() || !*GetStoreId() ) return E_GAME_MISSING_GAME_CONFIG;
    if ( !( doc = xmlNewDoc( BAD_CAST "1.0" ) ) ) return E_OUTOFMEMORY;
    root = xmlNewNode( NULL, BAD_CAST "StoreLicenseTokenRequest" );
    if ( !root )
    {
        xmlFreeDoc( doc );
        return E_OUTOFMEMORY;
    }
    xmlDocSetRootElement( doc, root );
    xmlNewTextChild( root, NULL, BAD_CAST "ParentProductId", BAD_CAST GetStoreId() );
    for ( i = 0; i < count; i++ )
        xmlNewTextChild( root, NULL, BAD_CAST "ProductId", BAD_CAST product_ids[i] );
    xmlNewTextChild( root, NULL, BAD_CAST "CustomDeveloperString", BAD_CAST nonce );
    xmlDocDumpMemory( doc, &xml, &size );
    xmlFreeDoc( doc );
    if ( !xml ) return E_OUTOFMEMORY;
    if ( size <= 0 || size > 0xffff )
    {
        xmlFree( xml );
        return E_INVALIDARG;
    }
    *body = strdup( ( char * )xml );
    xmlFree( xml );
    return *body ? S_OK : E_OUTOFMEMORY;
}

void xodus_store_license_note( const char *phase, HRESULT hr )
{
    auth_metadata( phase, NULL, hr, 0, FALSE, FALSE );
}

HRESULT xodus_store_license_xml( const char *request, SIZE_T request_size, char **token )
{
    char *response = NULL, *code = NULL, *end;
    UINT16 response_size = 0;
    xmlDocPtr doc = NULL;
    xmlNodePtr root;
    HRESULT hr;
    unsigned long value;

    *token = NULL;
    if ( request_size > 0xffff ) return E_INVALIDARG;
    /* Request 5 returns only a genuine Microsoft licensing token, request 6.
     * Older services cannot provide it and must fail, never fabricate success. */
    if ( FAILED( hr = xodus_request( 5, request, request_size, &response, &response_size ) ) ) goto cleanup;
    if ( !( doc = xmlReadMemory( response, response_size, NULL, NULL, XML_PARSE_NONET ) ) )
    {
        hr = E_UNEXPECTED;
        goto cleanup;
    }
    root = xmlDocGetRootElement( doc );
    if ( !root || strcmp( ( char * )root->name, "StoreLicenseTokenResponse" ) ||
         !( code = xml_child_content( root, "Hresult" ) ) )
    {
        hr = E_UNEXPECTED;
        goto cleanup;
    }
    value = strtoul( code, &end, 10 );
    if ( !*code || *end )
    {
        hr = E_UNEXPECTED;
        goto cleanup;
    }
    hr = ( HRESULT )( UINT32 )value;
    if ( SUCCEEDED( hr ) )
    {
        *token = xml_child_content( root, "Token" );
        if ( !*token || !**token )
        {
            free( *token );
            *token = NULL;
            hr = E_UNEXPECTED;
        }
    }
cleanup:
    auth_metadata( "store-license", NULL, hr, 0, FALSE, FALSE );
    if ( doc ) xmlFreeDoc( doc );
    if ( response )
    {
        SecureZeroMemory( response, response_size );
        free( response );
    }
    free( code );
    return hr;
}

#include "User/Tickets.h"

static HRESULT device_auth( XUserHandle user, const char *deviceTicket, char **deviceToken )
{
    static const char requestTemplate[] = "{\"RelyingParty\":\"http://"
                                          "auth.xboxlive.com\",\"TokenType\":\"JWT\",\"Properties\":{\"AuthMethod\":"
                                          "\"RPS\",\"SiteName\":\"user.auth.xboxlive.com\",\"ProofKey\":";
    SIZE_T size = ARRAY_SIZE( requestTemplate ) + strlen( user->proofKey ) + strlen( ",\"RpsTicket\":\"\"}}" ) +
                  strlen( deviceTicket );
    WCHAR header[116] = { 'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', ':', ' ' };
    IJsonObject *object = NULL;
    const WCHAR *tokenBuffer;
    HSTRING token = NULL;
    BYTE *buffer = NULL;
    char signature[104];
    HRESULT hr;
    char *body;

    if ( !( body = static_cast<std::remove_reference_t<decltype( body )>>( calloc( 1, size ) ) ) ) return E_OUTOFMEMORY;
    strcpy( body, requestTemplate );
    strcat( body, user->proofKey );
    strcat( body, ",\"RpsTicket\":\"" );
    strcat( body, deviceTicket );
    strcat( body, "\"}}" );
    if ( FAILED( hr = ( user )->GetSignature( 1, "POST", "https://device.auth.xboxlive.com/device/authenticate", "",
                                              size - 1, body, signature ) ) )
        goto cleanup;
    if ( !MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, signature, 104, header + 11, 104 ) ) goto error;
    if ( FAILED( hr = user->transport.Http( L"POST", L"https://device.auth.xboxlive.com/device/authenticate", body,
                                            header, ACCEPT_JSON, &buffer, &size ) ) )
        goto cleanup;
    if ( FAILED( hr = parse_json( ( char * )buffer, size, &object ) ) ) goto cleanup;
    if ( FAILED( hr = get_json_string( object, L"Token", &token ) ) ) goto cleanup;
    tokenBuffer = WindowsGetStringRawBuffer( token, NULL );
    if ( !( size = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, tokenBuffer, -1, NULL, 0, NULL, NULL ) ) )
        goto error;
    if ( !( *deviceToken = static_cast<std::remove_reference_t<decltype( *deviceToken )>>( calloc( 1, size ) ) ) )
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }
    if ( !WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, tokenBuffer, -1, *deviceToken, size, NULL, NULL ) )
        goto error;
    goto cleanup;

error:
    hr = HRESULT_FROM_WIN32( GetLastError() );
cleanup:
    if ( FAILED( hr ) && *deviceToken ) free( *deviceToken );
    if ( object ) ( object )->Release();
    if ( token ) WindowsDeleteString( token );
    if ( buffer ) free( buffer );
    free( body );
    return hr;
}

static HRESULT xsts_authorize( XUserHandle user, const char *relyingParty, BOOL title, char **auth );
static HRESULT xsts_authorize_privilege( XUserHandle user, const char *relyingParty, BOOL title, char **auth,
                                         XUserPrivilege privilege, BOOLEAN *granted, bool presence = false );
static char *hstring_to_utf8( HSTRING string );
static WCHAR *utf8_to_wide( const char *string );

static HRESULT sisu_auth( XUserHandle user, const char *userTicket, const char *deviceToken, WCHAR **auth )
{
    static const char requestTemplate[] = "{\"Sandbox\":\"RETAIL\",\"UseModernGamertag\":true,\"DeviceToken\":\"";
    SIZE_T size = ARRAY_SIZE( requestTemplate ) + strlen( deviceToken ) + strlen( "\",\"AccessToken\":\"\"}" ) +
                  strlen( userTicket );
    HSTRING authToken = NULL, gtg = NULL, mgs = NULL, mgt = NULL, umg = NULL, userToken = NULL, xid = NULL,
            titleToken = NULL, age = NULL;
    IJsonObject *authObject = NULL, *claims = NULL, *identity = NULL, *object = NULL, *userObject = NULL,
                *titleObject = NULL;
    WCHAR header[116] = { 'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', ':', ' ' };
    char *body, signature[104];
    const WCHAR *stringBuffer;
    IJsonArray *xui = NULL;
    BYTE *buffer = NULL;
    HRESULT hr;

    if ( !( body = static_cast<std::remove_reference_t<decltype( body )>>( calloc( 1, size ) ) ) ) return E_OUTOFMEMORY;
    strcpy( body, requestTemplate );
    strcat( body, deviceToken );
    strcat( body, "\",\"AccessToken\":\"" );
    strcat( body, userTicket );
    strcat( body, "\"}" );
    if ( FAILED( hr = ( user )->GetSignature( 1, "POST", "https://sisu.xboxlive.com/authorize", "", size - 1, body,
                                              signature ) ) )
        goto cleanup;
    if ( !MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, signature, 104, header + 11, 104 ) ) goto error;
    if ( FAILED( hr = user->transport.Http( L"POST", L"https://sisu.xboxlive.com/authorize", body, header, ACCEPT_JSON,
                                            &buffer, &size ) ) )
        goto cleanup;

    if ( FAILED( hr = parse_json( ( char * )buffer, size, &object ) ) ) goto cleanup;
    if ( FAILED( hr = get_json_object( object, L"UserToken", &userObject ) ) ) goto cleanup;
    if ( FAILED( hr = get_json_string( userObject, L"Token", &userToken ) ) ) goto cleanup;
    stringBuffer = WindowsGetStringRawBuffer( userToken, NULL );
    if ( !( size = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, stringBuffer, -1, NULL, 0, NULL, NULL ) ) )
        goto error;
    if ( !( user->userToken = static_cast<std::remove_reference_t<decltype( user->userToken )>>( calloc( 1, size ) ) ) )
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }
    if ( !WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, stringBuffer, -1, user->userToken, size, NULL, NULL ) )
        goto error;
    if ( SUCCEEDED( get_json_object( object, L"TitleToken", &titleObject ) ) &&
         SUCCEEDED( get_json_string( titleObject, L"Token", &titleToken ) ) )
    {
        free( user->titleToken );
        user->titleToken = hstring_to_utf8( titleToken );
    }
    if ( FAILED( hr = get_json_object( object, L"AuthorizationToken", &authObject ) ) ) goto cleanup;
    if ( FAILED( hr = get_json_object( authObject, L"DisplayClaims", &claims ) ) ) goto cleanup;
    if ( FAILED( hr = get_json_array( claims, L"xui", &xui ) ) ) goto cleanup;
    if ( FAILED( hr = ( xui )->GetObjectAt( 0, &identity ) ) ) goto cleanup;
    if ( FAILED( hr = get_json_string( identity, L"xid", &xid ) ) ) goto cleanup;
    {
        UINT32 length;
        UINT64 parsed = 0;
        stringBuffer = WindowsGetStringRawBuffer( xid, &length );
        if ( !length || length > 20 )
        {
            hr = E_UNEXPECTED;
            goto cleanup;
        }
        for ( UINT32 i = 0; i < length; ++i )
        {
            if ( stringBuffer[i] < '0' || stringBuffer[i] > '9' ||
                 parsed > ( ~UINT64( 0 ) - ( stringBuffer[i] - '0' ) ) / 10 )
            {
                hr = E_UNEXPECTED;
                goto cleanup;
            }
            parsed = parsed * 10 + stringBuffer[i] - '0';
        }
        if ( !parsed )
        {
            hr = E_UNEXPECTED;
            goto cleanup;
        }
        user->xuid = parsed;
    }
    user->age_group = XUserAgeGroup::Unknown;
    if ( SUCCEEDED( get_json_string( identity, L"agg", &age ) ) )
    {
        stringBuffer = WindowsGetStringRawBuffer( age, NULL );
        if ( !wcscmp( stringBuffer, L"Child" ) )
            user->age_group = XUserAgeGroup::Child;
        else if ( !wcscmp( stringBuffer, L"Teen" ) )
            user->age_group = XUserAgeGroup::Teen;
        else if ( !wcscmp( stringBuffer, L"Adult" ) )
            user->age_group = XUserAgeGroup::Adult;
    }
    if ( FAILED( hr = get_json_string( identity, L"gtg", &gtg ) ) ) goto cleanup;
    stringBuffer = WindowsGetStringRawBuffer( gtg, NULL );
    if ( !WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, stringBuffer, -1, user->gamertag, 16, NULL, NULL ) )
        goto error;
    if ( FAILED( hr = get_json_string( identity, L"mgt", &mgt ) ) ) goto cleanup;
    stringBuffer = WindowsGetStringRawBuffer( mgt, NULL );
    if ( !WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, stringBuffer, -1, user->modernGamertag, 97, NULL, NULL ) )
        goto error;
    if ( SUCCEEDED( hr = get_json_string( identity, L"mgs", &mgs ) ) )
    {
        stringBuffer = WindowsGetStringRawBuffer( mgs, NULL );
        if ( !WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, stringBuffer, -1, user->modernGamertagSuffix, 15,
                                   NULL, NULL ) )
            goto error;
    }
    else if ( hr != WEB_E_JSON_VALUE_NOT_FOUND )
        goto cleanup;
    if ( FAILED( hr = get_json_string( identity, L"umg", &umg ) ) ) goto cleanup;
    stringBuffer = WindowsGetStringRawBuffer( umg, NULL );
    if ( !WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, stringBuffer, -1, user->uniqueModernGamertag, 101, NULL,
                               NULL ) )
        goto error;
    if ( FAILED( hr = get_json_string( authObject, L"Token", &authToken ) ) ) goto cleanup;
    stringBuffer = WindowsGetStringRawBuffer( authToken, NULL );
    if ( !( *auth = static_cast<std::remove_reference_t<decltype( *auth )>>(
                calloc( wcslen( L"Authorization: XBL3.0 x=-;" ) + wcslen( stringBuffer ) + 1, sizeof( WCHAR ) ) ) ) )
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }
    wcscpy( *auth, L"Authorization: XBL3.0 x=-;" );
    wcscat( *auth, stringBuffer );
    goto cleanup;

error:
    hr = HRESULT_FROM_WIN32( GetLastError() );
cleanup:
    auth_metadata( "sisu", user, hr, 0, TRUE, !!user->titleToken );
    if ( authObject ) ( authObject )->Release();
    if ( userObject ) ( userObject )->Release();
    if ( titleObject ) ( titleObject )->Release();
    if ( titleToken ) WindowsDeleteString( titleToken );
    if ( authToken ) WindowsDeleteString( authToken );
    if ( userToken ) WindowsDeleteString( userToken );
    if ( identity ) ( identity )->Release();
    if ( claims ) ( claims )->Release();
    if ( object ) ( object )->Release();
    if ( gtg ) WindowsDeleteString( gtg );
    if ( mgs ) WindowsDeleteString( mgs );
    if ( mgt ) WindowsDeleteString( mgt );
    if ( umg ) WindowsDeleteString( umg );
    if ( xid ) WindowsDeleteString( xid );
    if ( age ) WindowsDeleteString( age );
    if ( xui ) ( xui )->Release();
    if ( buffer ) free( buffer );
    free( body );
    return hr;
}

HRESULT XUser::LoadEndpoints( const BYTE *buffer, SIZE_T size )
{
    XUser *user = this;
    IJsonObject *payload = NULL, *tmpObject = NULL;
    IJsonArray *jsonEndpoints = NULL, *jsonPolicies = NULL;
    IVector_IJsonValue *jsonEndpointsVector = NULL, *jsonPoliciesVector = NULL;
    struct policy *policyCursor = NULL;
    struct endpoint *endpointCursor = NULL;
    DOUBLE jsonNumber;
    UINT32 arraySize;
    HSTRING hostType = NULL;
    const WCHAR *hostTypeRaw = NULL;
    HRESULT hr = S_OK;

    if ( FAILED( hr = parse_json( ( char * )buffer, size, &payload ) ) ) return hr;
    if ( FAILED( hr = get_json_array( payload, L"EndPoints", &jsonEndpoints ) ) ) goto cleanup;
    if ( FAILED( get_json_array( payload, L"SignaturePolicies", &jsonPolicies ) ) ) jsonPolicies = NULL;

    if ( jsonPolicies )
    {
        if ( FAILED( hr = ( jsonPolicies )
                              ->QueryInterface( __uuidof( IVector_IJsonValue ), ( void ** )&jsonPoliciesVector ) ) )
            goto cleanup;
        if ( FAILED( hr = ( jsonPoliciesVector )->get_Size( &arraySize ) ) ) goto cleanup;

        if ( arraySize > 8192 - user->policiesLen )
        {
            hr = E_INVALIDARG;
            goto cleanup;
        }
        if ( !( policyCursor = static_cast<std::remove_reference_t<decltype( policyCursor )>>(
                    realloc( user->policies, sizeof( struct policy ) * ( user->policiesLen + arraySize ) ) ) ) &&
             arraySize )
        {
            hr = E_OUTOFMEMORY;
            goto cleanup;
        }
        user->policies = policyCursor;
        policyCursor = user->policies ? user->policies + user->policiesLen : nullptr;
        user->policiesLen = user->policiesLen + arraySize;

        for ( UINT32 i = 0; i < arraySize; i++ )
        {
            if ( FAILED( hr = ( jsonPolicies )->GetObjectAt( i, &tmpObject ) ) ) goto cleanup;

            if ( FAILED( hr = get_json_number( tmpObject, L"Version", &jsonNumber ) ) ) goto cleanup;
            if ( !std::isfinite( jsonNumber ) || jsonNumber < 0 || jsonNumber > MAXDWORD ||
                 std::floor( jsonNumber ) != jsonNumber )
            {
                hr = E_INVALIDARG;
                goto cleanup;
            }
            ( *( policyCursor + i ) ).version = ( UINT32 )jsonNumber;
            if ( FAILED( hr = get_json_number( tmpObject, L"MaxBodyBytes", &jsonNumber ) ) ) goto cleanup;
            if ( !std::isfinite( jsonNumber ) || jsonNumber < 0 || jsonNumber > MAXDWORD ||
                 std::floor( jsonNumber ) != jsonNumber )
            {
                hr = E_INVALIDARG;
                goto cleanup;
            }
            ( *( policyCursor + i ) ).maxBodyBytes = ( UINT32 )jsonNumber;

            ( tmpObject )->Release();
            tmpObject = NULL;
        }
    }

    if ( FAILED( hr = ( jsonEndpoints )
                          ->QueryInterface( __uuidof( IVector_IJsonValue ), ( void ** )&jsonEndpointsVector ) ) )
        goto cleanup;
    if ( FAILED( hr = ( jsonEndpointsVector )->get_Size( &arraySize ) ) ) goto cleanup;

    if ( arraySize > 8192 - user->endpointsLen )
    {
        hr = E_INVALIDARG;
        goto cleanup;
    }
    if ( !( endpointCursor = static_cast<std::remove_reference_t<decltype( endpointCursor )>>(
                realloc( user->endpoints, sizeof( struct endpoint ) * ( user->endpointsLen + arraySize ) ) ) ) &&
         arraySize )
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }
    user->endpoints = endpointCursor;
    // Reallocation can move endpoint records. Restore only self-owned policy
    // pointers, never dereference a pointer into a previously reallocated array.
    for ( UINT32 i = 0; i < user->endpointsLen; ++i )
        if ( user->endpoints[i].policy ) user->endpoints[i].policy = &user->endpoints[i].policyValue;
    endpointCursor = user->endpoints ? user->endpoints + user->endpointsLen : nullptr;
    user->endpointsLen = user->endpointsLen + arraySize;
    if ( arraySize ) memset( endpointCursor, 0, sizeof( struct endpoint ) * arraySize );

    for ( UINT32 i = 0; i < arraySize; i++ )
    {
        if ( FAILED( hr = ( jsonEndpoints )->GetObjectAt( i, &tmpObject ) ) ) goto cleanup;

        if ( FAILED( hr = get_json_string( tmpObject, L"Protocol", &( endpointCursor + i )->protocol ) ) ) goto cleanup;
        if ( FAILED( hr = get_json_string( tmpObject, L"Host", &( endpointCursor + i )->host ) ) ) goto cleanup;
        if ( FAILED( get_json_string( tmpObject, L"Path", &( endpointCursor + i )->path ) ) )
            ( endpointCursor + i )->path = NULL;

        if ( FAILED( get_json_string( tmpObject, L"RelyingParty", &( endpointCursor + i )->relyingParty ) ) )
            ( endpointCursor + i )->relyingParty = NULL;
        if ( FAILED( get_json_string( tmpObject, L"TokenType", &( endpointCursor + i )->tokenType ) ) )
            ( endpointCursor + i )->tokenType = NULL;
        hr = get_json_number( tmpObject, L"SignaturePolicyIndex", &jsonNumber );
        if ( SUCCEEDED( hr ) )
        {
            if ( !std::isfinite( jsonNumber ) || jsonNumber < 0 || std::floor( jsonNumber ) != jsonNumber ||
                 !policyCursor || jsonNumber >= ( user->policiesLen - ( policyCursor - user->policies ) ) )
            {
                hr = E_INVALIDARG;
                goto cleanup;
            }
            ( endpointCursor + i )->policyValue = policyCursor[( UINT32 )jsonNumber];
            ( endpointCursor + i )->policy = &( endpointCursor + i )->policyValue;
        }
        else if ( hr == WEB_E_JSON_VALUE_NOT_FOUND )
        {
            ( endpointCursor + i )->policy = nullptr;
            hr = S_OK;
        }
        else
            goto cleanup;
        if ( SUCCEEDED( get_json_string( tmpObject, L"HostType", &hostType ) ) )
        {
            hostTypeRaw = WindowsGetStringRawBuffer( hostType, NULL );
            ( endpointCursor + i )->wildcard = wcscmp( hostTypeRaw, L"wildcard" ) == 0;
            WindowsDeleteString( hostType );
            hostType = NULL;
        }
        else
        {
            ( endpointCursor + i )->wildcard = FALSE;
        }

        ( tmpObject )->Release();
        tmpObject = NULL;
    }

cleanup:
    if ( jsonPoliciesVector ) ( jsonPoliciesVector )->Release();
    if ( jsonEndpointsVector ) ( jsonEndpointsVector )->Release();
    if ( jsonEndpoints ) ( jsonEndpoints )->Release();
    if ( tmpObject ) ( tmpObject )->Release();
    if ( jsonPolicies ) ( jsonPolicies )->Release();
    if ( payload ) ( payload )->Release();

    return hr;
}

HRESULT WINAPI XUser::Initialize( const XUserAddOptions options )
{
    static char proofKeyTemplate[] = "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kty\":\"EC\",\"use\":\"sig\",\"x\":\"";
    static const SIZE_T proofKeySize = ARRAY_SIZE( proofKeyTemplate ) + sizeof( "\",\"y\":\"\"}" ) + 85;
    BYTE blob[sizeof( BCRYPT_ECCKEY_BLOB ) + 64];
    char *x, *y;
    auto *impl = this;
    NTSTATUS status;
    ULONG dummy;
    HRESULT hr;

    ( void )options;

    /* generate signing key pair and convert public key to jwk */
    if ( !NT_SUCCESS( status = BCryptOpenAlgorithmProvider( &impl->signingAlgorithm, BCRYPT_ECDSA_P256_ALGORITHM,
                                                            nullptr, 0 ) ) )
        return HRESULT_FROM_NT( status );
    if ( !NT_SUCCESS( status = BCryptGenerateKeyPair( impl->signingAlgorithm, &impl->key, 256, 0 ) ) )
        return HRESULT_FROM_NT( status );
    if ( !NT_SUCCESS( status = BCryptFinalizeKeyPair( impl->key, 0 ) ) ) return HRESULT_FROM_NT( status );
    if ( !NT_SUCCESS( status =
                          BCryptExportKey( impl->key, NULL, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof( blob ), &dummy, 0 ) ) )
        return HRESULT_FROM_NT( status );
    if ( !( impl->proofKey =
                static_cast<std::remove_reference_t<decltype( impl->proofKey )>>( calloc( 1, proofKeySize ) ) ) )
        return E_OUTOFMEMORY;
    x = impl->proofKey + ARRAY_SIZE( proofKeyTemplate ) - 1;
    y = x + 43 + strlen( "\",\"y\":\"" );
    strcpy( impl->proofKey, proofKeyTemplate );
    if ( FAILED( hr = encode_base64_url( 32, blob + sizeof( BCRYPT_ECCKEY_BLOB ), 43, x, FALSE ) ) ) return hr;
    strcat( impl->proofKey, "\",\"y\":\"" );
    if ( FAILED( hr = encode_base64_url( 32, blob + sizeof( BCRYPT_ECCKEY_BLOB ) + 32, 43, y, FALSE ) ) ) return hr;
    strcat( impl->proofKey, "\"}" );

    InitializeConditionVariable( &impl->initCv );
    impl->initDone = 0;
    impl->initResult = E_PENDING;
    return S_OK;
}

/* The endpoint/device/SISU handshake can take minutes on a cold token cache.
 * Titles time out sign-in while XUserAddAsync sits in DoWork for that long,
 * so it runs on a background thread; consumers wait through user_wait_init. */
HRESULT XUser::InitializeNetwork( XUserAddOptions options )
{
    XUser *user = this;
    ResetNetworkState();
    BYTE *currentBuffer = NULL, *defaultBuffer = NULL;
    char *deviceTicket = NULL, *deviceToken = NULL, *userTicket = NULL;
    struct XUser *impl = user;
    WCHAR *auth = NULL;
    SIZE_T size, defaultSize = 0;
    HRESULT hr;

    /* The launcher already found Microsoft unreachable; fail as the network would. */
    if ( nexus::user::ForcedOffline() ) return HRESULT_FROM_WIN32( ERROR_WINHTTP_CANNOT_CONNECT );
    auth_metadata( "init-default-begin", user, E_PENDING, 0, FALSE, FALSE );
    hr = user->transport.Http( L"GET", L"https://title.mgt.xboxlive.com/titles/default/endpoints?type=1", NULL, NULL,
                               ACCEPT_JSON, &defaultBuffer, &defaultSize );
    auth_metadata( "init-default-end", user, hr, 0, FALSE, FALSE );
    if ( FAILED( hr ) ) return hr;
    if ( cancelled )
    {
        hr = E_ABORT;
        goto cleanup;
    }
    hr = impl->LoadEndpoints( defaultBuffer, defaultSize );
    auth_metadata( "init-default-parse", user, hr, 0, FALSE, FALSE );
    if ( FAILED( hr ) ) goto cleanup;
    if ( cancelled )
    {
        hr = E_ABORT;
        goto cleanup;
    }
    auth_metadata( "init-tickets-begin", user, E_PENDING, 0, FALSE, FALSE );
    hr = get_rps_tickets( user, options & XUserAddOptions::AddDefaultUserAllowingUI, &userTicket, &deviceTicket,
                          impl->xbox_msa_id, impl->store_msa_id );
    auth_metadata( "init-tickets-end", user, hr, 0, FALSE, FALSE );
    if ( FAILED( hr ) ) goto cleanup;
    if ( cancelled )
    {
        hr = E_ABORT;
        goto cleanup;
    }
    auth_metadata( "init-device-begin", user, E_PENDING, 0, FALSE, FALSE );
    hr = device_auth( impl, deviceTicket, &deviceToken );
    auth_metadata( "init-device-end", user, hr, 0, FALSE, FALSE );
    if ( FAILED( hr ) ) goto cleanup;
    if ( cancelled )
    {
        hr = E_ABORT;
        goto cleanup;
    }
    free( impl->deviceToken );
    if ( !( impl->deviceToken = strdup( deviceToken ) ) )
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }
    auth_metadata( "init-sisu-begin", user, E_PENDING, 0, TRUE, FALSE );
    hr = sisu_auth( impl, userTicket, deviceToken, &auth );
    auth_metadata( "init-sisu-end", user, hr, 0, TRUE, !!user->titleToken );
    if ( FAILED( hr ) ) goto cleanup;
    if ( cancelled )
    {
        hr = E_ABORT;
        goto cleanup;
    }
    auth_metadata( "init-current-begin", user, E_PENDING, 0, FALSE, FALSE );
    hr = user->transport.Http( L"GET", L"https://title.mgt.xboxlive.com/titles/current/endpoints", NULL, auth,
                               ACCEPT_JSON, &currentBuffer, &size );
    auth_metadata( "init-current-end", user, hr, 0, FALSE, FALSE );
    if ( FAILED( hr ) ) goto cleanup;
    if ( cancelled )
    {
        hr = E_ABORT;
        goto cleanup;
    }
    hr = impl->LoadEndpoints( currentBuffer, size );
    auth_metadata( "init-current-parse", user, hr, 0, FALSE, FALSE );
    if ( FAILED( hr ) ) goto cleanup;
    if ( cancelled )
    {
        hr = E_ABORT;
        goto cleanup;
    }
    impl->RememberOfflineIdentity( defaultBuffer, defaultSize, currentBuffer, size );

cleanup:
    if ( currentBuffer ) free( currentBuffer );
    if ( defaultBuffer ) free( defaultBuffer );
    if ( deviceTicket ) free( deviceTicket );
    if ( deviceToken ) free( deviceToken );
    if ( userTicket ) free( userTicket );
    if ( auth ) free( auth );
    return hr;
}

void XUser::ResetNetworkState() noexcept
{
    free( userToken );
    userToken = nullptr;
    free( deviceToken );
    deviceToken = nullptr;
    free( titleToken );
    titleToken = nullptr;
    free( deviceAuth );
    deviceAuth = nullptr;
    free( deviceAuthAudience );
    deviceAuthAudience = nullptr;
    deviceAuthTime = 0;
    offline = false;
    privilegesKnown = FALSE;
    privilegesCheckedAt = 0;
    memset( grantedPrivileges, 0, sizeof( grantedPrivileges ) );
    xuid = 0;
    xbox_msa_id[0] = store_msa_id[0] = 0;
    age_group = XUserAgeGroup::Unknown;
    gamertag[0] = modernGamertag[0] = modernGamertagSuffix[0] = uniqueModernGamertag[0] = 0;
    for ( UINT32 i = 0; i < endpointsLen; ++i )
    {
        WindowsDeleteString( endpoints[i].protocol );
        WindowsDeleteString( endpoints[i].host );
        WindowsDeleteString( endpoints[i].path );
        WindowsDeleteString( endpoints[i].relyingParty );
        WindowsDeleteString( endpoints[i].tokenType );
    }
    free( endpoints );
    endpoints = nullptr;
    endpointsLen = 0;
    free( policies );
    policies = nullptr;
    policiesLen = 0;
}

/* After a complete network sign-in: keep the identity only when the backend
 * says Microsoft issued this device an offline lease on this launch; remove
 * it when offline play is not (or no longer) granted. */
void XUser::RememberOfflineIdentity( const BYTE *defaults, SIZE_T defaultsSize, const BYTE *current,
                                     SIZE_T currentSize ) noexcept
{
    try
    {
        const auto mode = nexus::user::ReadOfflineIdentityMode();
        const auto store = nexus::user::OfflineIdentityStore::ForAccount();
        if ( !store || mode == nexus::user::OfflineIdentityMode::Use ) return;
        if ( mode == nexus::user::OfflineIdentityMode::None )
        {
            store->Remove();
            return;
        }
        nexus::user::OfflineIdentity identity{ xuid, static_cast<unsigned>( age_group ), nexus::user::FileTimeNow(),
                                               gamertag, modernGamertag, modernGamertagSuffix, uniqueModernGamertag };
        if ( !store->Save( identity, std::string_view( reinterpret_cast<const char *>( defaults ), defaultsSize ),
                           std::string_view( reinterpret_cast<const char *>( current ), currentSize ) ) )
            WARN( "offline identity not stored.\n" );
    }
    catch ( ... )
    {
        WARN( "offline identity not stored.\n" );
    }
}

/* Microsoft unreachable on a launch the backend runs on a validated offline
 * license: complete the sign-in from the cached identity. Every other failure
 * stands. */
HRESULT XUser::SignInOffline( HRESULT failure ) noexcept
{
    if ( !nexus::user::IsConnectivityFailure( failure ) ||
         nexus::user::ReadOfflineIdentityMode() != nexus::user::OfflineIdentityMode::Use )
        return failure;
    try
    {
        const auto store = nexus::user::OfflineIdentityStore::ForAccount();
        nexus::user::OfflineIdentity identity;
        std::string defaults, current;
        if ( !store || !store->Load( nexus::user::FileTimeNow(), identity, defaults, current ) ) return failure;
        ResetNetworkState();
        if ( FAILED( LoadEndpoints( reinterpret_cast<const BYTE *>( defaults.data() ), defaults.size() ) ) ||
             FAILED( LoadEndpoints( reinterpret_cast<const BYTE *>( current.data() ), current.size() ) ) )
        {
            ResetNetworkState();
            return failure;
        }
        xuid = identity.xuid;
        age_group = static_cast<XUserAgeGroup>( identity.ageGroup );
        lstrcpynA( gamertag, identity.gamertag.c_str(), sizeof( gamertag ) );
        lstrcpynA( modernGamertag, identity.modernGamertag.c_str(), sizeof( modernGamertag ) );
        lstrcpynA( modernGamertagSuffix, identity.modernGamertagSuffix.c_str(), sizeof( modernGamertagSuffix ) );
        lstrcpynA( uniqueModernGamertag, identity.uniqueModernGamertag.c_str(), sizeof( uniqueModernGamertag ) );
        offline = true;
        WARN( "Microsoft is unreachable (hr %#lx); continuing with the cached offline identity.\n", failure );
        return S_OK;
    }
    catch ( ... )
    {
        ResetNetworkState();
        return failure;
    }
}

static void set_signed_in_user( struct XUser *user );

struct XUserAddContext
{
    std::atomic<ULONG> refs{ 1 };
    std::atomic<bool> completed{ false };
    SRWLOCK lock{};
    UserTransport *transport{};
    XUserAddOptions options{};
    XUserHandle user{};
    XAsyncBlock *async{};
    void AddRef() noexcept
    {
        ++refs;
    }
    void Release() noexcept
    {
        if ( --refs == 0 )
        {
            if ( user ) user->Release();
            delete this;
        }
    }
    void Complete( IXThreadingImpl *threading, HRESULT result )
    {
        bool expected = false;
        if ( !completed.compare_exchange_strong( expected, true ) ) return;
        AcquireSRWLockExclusive( &lock );
        if ( user )
        {
            if ( result == E_ABORT ) user->cancelled = true;
            EnterCriticalSection( &user->deviceAuthSection );
            user->initResult = result;
            user->initDone = 1;
            LeaveCriticalSection( &user->deviceAuthSection );
            WakeAllConditionVariable( &user->initCv );
            if ( SUCCEEDED( result ) )
            {
                account_metadata_publish( user->xuid, user->xbox_msa_id, user->store_msa_id );
                set_signed_in_user( user );
            }
        }
        ReleaseSRWLockExclusive( &lock );
        auth_metadata( "init-complete", user, result, 0, FALSE, FALSE );
        // Completion may free/reuse the title's block. The losing worker must
        // never access it after cancellation wins the terminal-state race.
        threading->XAsyncComplete( async, result, SUCCEEDED( result ) ? sizeof( XUserHandle ) : 0 );
    }
};
struct UserAddContextRef
{
    XUserAddContext *context;
    explicit UserAddContextRef( XUserAddContext *context ) : context( context )
    {
        context->AddRef();
    }
    ~UserAddContextRef()
    {
        context->Release();
    }
};
static SRWLOCK signInWorkerLock = SRWLOCK_INIT;
static CONDITION_VARIABLE signInWorkerCv = CONDITION_VARIABLE_INIT;
static ULONG signInWorkerCount = 0;
static thread_local bool isSignInWorker = false;
static void ChangeSignInWorkers( bool add )
{
    AcquireSRWLockExclusive( &signInWorkerLock );
    if ( add )
        ++signInWorkerCount;
    else
        --signInWorkerCount;
    WakeAllConditionVariable( &signInWorkerCv );
    ReleaseSRWLockExclusive( &signInWorkerLock );
}
HRESULT WaitForUserSignInWorkers( DWORD timeout ) noexcept
{
    if ( isSignInWorker ) return HRESULT_FROM_WIN32( ERROR_BUSY );
    const auto start = GetTickCount64();
    AcquireSRWLockExclusive( &signInWorkerLock );
    while ( signInWorkerCount )
    {
        const auto elapsed = GetTickCount64() - start;
        if ( elapsed >= timeout || !SleepConditionVariableSRW( &signInWorkerCv, &signInWorkerLock,
                                                               static_cast<DWORD>( timeout - elapsed ), 0 ) )
        {
            ReleaseSRWLockExclusive( &signInWorkerLock );
            return HRESULT_FROM_WIN32( ERROR_TIMEOUT );
        }
    }
    ReleaseSRWLockExclusive( &signInWorkerLock );
    return S_OK;
}
struct UserNetworkInit
{
    XUserHandle user;
    XUserAddContext *context;
    IXThreadingImpl *threading;
};
static DWORD WINAPI UserNetworkInitThread( void *arg )
{
    auto init = static_cast<UserNetworkInit *>( arg );
    auto user = init->user;
    auto context = init->context;
    auto threading = init->threading;
    delete init;
    isSignInWorker = true;
    const auto com = CoInitializeEx( nullptr, COINIT_MULTITHREADED );
    HRESULT hr = FAILED( com ) ? com : E_ABORT;
    auth_metadata( "init-worker-begin", user, E_PENDING, 0, FALSE, FALSE );
    for ( unsigned attempt = 0; attempt < 5 && !user->cancelled && SUCCEEDED( com ); ++attempt )
    {
        auth_metadata( "init-attempt-begin", user, E_PENDING, 0, FALSE, FALSE );
        hr = user->InitializeNetwork( context->options );
        auth_metadata( "init-attempt-end", user, hr, 0, FALSE, FALSE );
        if ( SUCCEEDED( hr ) || user->cancelled ) break;
        /* An unreachable Microsoft on an offline-licensed launch is not a
         * start race: the cached identity takes over without the retry waits. */
        if ( nexus::user::IsConnectivityFailure( hr ) &&
             nexus::user::ReadOfflineIdentityMode() == nexus::user::OfflineIdentityMode::Use )
            break;
        if ( attempt < 4 )
        {
            auth_metadata( "init-retry", user, hr, 0, FALSE, FALSE );
            for ( unsigned delay = 0; delay < 30 && !user->cancelled; ++delay )
                user->transport.WaitForSignInRetry( 100 );
        }
    }
    if ( user->cancelled ) hr = E_ABORT;
    else if ( FAILED( hr ) && SUCCEEDED( com ) ) hr = user->SignInOffline( hr );
    if ( SUCCEEDED( com ) ) CoUninitialize();
    context->Complete( threading, hr );
    user->Release();
    context->Release();
    threading->Release();
    isSignInWorker = false;
    ChangeSignInWorkers( false );
    return 0;
}

/* Bounded wait for the background identity/network initialization. */
static HRESULT user_wait_init( XUserHandle user )
{
    HRESULT hr;

    EnterCriticalSection( &user->deviceAuthSection );
    while ( !user->initDone )
    {
        if ( !SleepConditionVariableCS( &user->initCv, &user->deviceAuthSection, 120000 ) )
        {
            LeaveCriticalSection( &user->deviceAuthSection );
            return HRESULT_FROM_WIN32( GetLastError() );
        }
    }
    hr = user->initResult;
    LeaveCriticalSection( &user->deviceAuthSection );
    return hr;
}

static BOOLEAN match_wildcard( const WCHAR *pat, UINT32 patLen, const WCHAR *inp, UINT32 inpLen )
{
    UINT32 lastMatch = -1, lastWildcard = -1, patOff = 0, inpOff = 0;

    while ( inpOff < inpLen && patOff < patLen )
    {
        if ( pat[patOff] == '*' )
        {
            lastWildcard = patOff++;
            lastMatch = inpOff;
        }
        else if ( pat[patOff] == '?' || pat[patOff] == inp[inpOff] )
        {
            patOff++;
            inpOff++;
        }
        else if ( lastWildcard != -1 )
        {
            patOff = lastWildcard + 1;
            inpOff = ++lastMatch;
        }
        else
            return FALSE;
    }

    return inpOff == inpLen && patOff == patLen;
}

HRESULT WINAPI XUser::GetEndpointInfo( const char *url, struct endpoint *info )
{
    URL_COMPONENTS uc = { .dwStructSize = sizeof( URL_COMPONENTS ),
                          .dwSchemeLength = MAXDWORD,
                          .dwHostNameLength = MAXDWORD,
                          .dwUrlPathLength = MAXDWORD };
    auto *impl = this;
    struct endpoint *match = NULL;
    INT32 urlWSize;
    WCHAR *urlW;
    HRESULT hr;

    if ( FAILED( hr = user_wait_init( impl ) ) ) return hr;

    if ( !( urlWSize = MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, url, -1, NULL, 0 ) ) )
        return HRESULT_FROM_WIN32( GetLastError() );
    if ( !( urlW = static_cast<std::remove_reference_t<decltype( urlW )>>( calloc( urlWSize, sizeof( WCHAR ) ) ) ) )
        return E_OUTOFMEMORY;
    if ( !MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, url, -1, urlW, urlWSize ) ) goto error;
    if ( !WinHttpCrackUrl( urlW, 0, 0, &uc ) ) goto error;

    for ( UINT32 i = 0; i < impl->endpointsLen; i++ )
    {
        UINT32 protocolLen, hostLen, pathLen;
        const WCHAR *protocol = WindowsGetStringRawBuffer( impl->endpoints[i].protocol, &protocolLen );
        const WCHAR *host = WindowsGetStringRawBuffer( impl->endpoints[i].host, &hostLen );
        const WCHAR *path = WindowsGetStringRawBuffer( impl->endpoints[i].path, &pathLen );
        if ( uc.dwSchemeLength != protocolLen || wcsnicmp( uc.lpszScheme, protocol, protocolLen ) ) continue;
        if ( impl->endpoints[i].path )
        {
            const WCHAR *urlPath = uc.lpszUrlPath;
            UINT32 urlPathLen = uc.dwUrlPathLength;
            /* Service metadata accepts paths relative to the URL root ("login")
             * as well as absolute paths ("/login"). WinHTTP includes the root
             * slash in its parsed path. Keep all remaining bytes and the
             * existing case-sensitive prefix semantics unchanged. */
            if ( pathLen && path[0] != '/' && urlPathLen && urlPath[0] == '/' )
            {
                ++urlPath;
                --urlPathLen;
            }
            if ( urlPathLen < pathLen || wcsncmp( urlPath, path, pathLen ) ) continue;
        }
        if ( impl->endpoints[i].wildcard )
        {
            if ( !match && match_wildcard( host, hostLen, uc.lpszHostName, uc.dwHostNameLength ) )
                match = &impl->endpoints[i];
            continue;
        }
        if ( uc.dwHostNameLength != hostLen || wcsnicmp( uc.lpszHostName, host, hostLen ) ) continue;
        match = &impl->endpoints[i];
        break;
    }
    free( urlW );
    if ( !match ) return E_FAIL;
    *info = *match;
    if ( match->policy ) info->policy = &info->policyValue;
    return S_OK;

error:
    free( urlW );
    return HRESULT_FROM_WIN32( GetLastError() );
}

HRESULT WINAPI XUser::GetAuthorization( const WCHAR *relyingParty, WCHAR **auth )
{
    auto *impl = this;
    char *relyingPartyA, *authA = NULL;
    SIZE_T size;
    HRESULT hr;

    if ( FAILED( hr = user_wait_init( impl ) ) ) return hr;

    if ( !( size = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, relyingParty, -1, NULL, 0, NULL, NULL ) ) )
        return HRESULT_FROM_WIN32( GetLastError() );
    if ( !( relyingPartyA = static_cast<std::remove_reference_t<decltype( relyingPartyA )>>( calloc( 1, size ) ) ) )
        return E_OUTOFMEMORY;
    WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, relyingParty, -1, relyingPartyA, size, NULL, NULL );
    if ( SUCCEEDED( hr = xsts_authorize( impl, relyingPartyA, TRUE, &authA ) ) && !( *auth = utf8_to_wide( authA ) ) )
        hr = E_OUTOFMEMORY;
    free( relyingPartyA );
    free( authA );
    return hr;
}

HRESULT WINAPI XUser::GetSignature( UINT32 version, const char *method, const char *url, const char *auth,
                                    UINT32 bodySize, const void *body, char signature[104] )
{
    if ( !signature ) return E_POINTER;
    if ( !method || !url || !auth || ( bodySize && !body ) ) return E_INVALIDARG;
    if ( !key ) return E_GAMEUSER_NO_AUTH_USER;
    try
    {
        const size_t methodSize = strnlen( method, 65 ), urlSize = strnlen( url, 65537 ),
                     authSize = strnlen( auth, 1024 * 1024 + 1 );
        if ( !methodSize || methodSize > 64 || !urlSize || urlSize > 65536 || authSize > 1024 * 1024 )
            return E_INVALIDARG;
        auto tokenCharacter = []( unsigned char c )
        {
            return ( c >= 'A' && c <= 'Z' ) || ( c >= 'a' && c <= 'z' ) || ( c >= '0' && c <= '9' ) ||
                   strchr( "!#$%&'*+-.^_\x60|~", c );
        };
        if ( !std::all_of( method, method + methodSize, tokenCharacter ) ) return E_INVALIDARG;
        if ( std::any_of( auth, auth + authSize, []( unsigned char c ) { return c < 0x20 || c == 0x7f; } ) )
            return E_INVALIDARG;
        std::string_view uri( url, urlSize );
        auto scheme = uri.find( "://" );
        if ( !scheme || scheme == std::string_view::npos ) return E_INVALIDARG;
        auto authority = uri.substr( scheme + 3 );
        auto separator = authority.find_first_of( "/?#" );
        if ( authority.empty() || separator == 0 ) return E_INVALIDARG;
        std::string path = "/";
        if ( separator != std::string_view::npos && authority[separator] != '#' )
        {
            auto suffix = authority.substr( separator );
            suffix = suffix.substr( 0, suffix.find( '#' ) );
            if ( suffix.front() == '?' )
                path.append( suffix );
            else
                path.assign( suffix );
        }
        const UINT64 required = 18ull + methodSize + path.size() + authSize + bodySize;
        if ( required > MAXDWORD ) return E_INVALIDARG;
        BYTE raw[76]{};
        for ( unsigned i = 0; i < 4; ++i )
            raw[i] = static_cast<BYTE>( version >> ( 24 - i * 8 ) );
        FILETIME now;
        GetSystemTimeAsFileTime( &now );
        const UINT64 timestamp = ( UINT64( now.dwHighDateTime ) << 32 ) | now.dwLowDateTime;
        for ( unsigned i = 0; i < 8; ++i )
            raw[4 + i] = static_cast<BYTE>( timestamp >> ( 56 - i * 8 ) );
        std::vector<BYTE> data;
        data.reserve( static_cast<size_t>( required ) );
        data.insert( data.end(), raw, raw + 4 );
        data.push_back( 0 );
        data.insert( data.end(), raw + 4, raw + 12 );
        data.push_back( 0 );
        for ( size_t i = 0; i < methodSize; ++i )
            data.push_back( static_cast<BYTE>( std::toupper( static_cast<unsigned char>( method[i] ) ) ) );
        data.push_back( 0 );
        data.insert( data.end(), path.begin(), path.end() );
        data.push_back( 0 );
        data.insert( data.end(), auth, auth + authSize );
        data.push_back( 0 );
        if ( bodySize )
        {
            const auto *bytes = static_cast<const BYTE *>( body );
            data.insert( data.end(), bytes, bytes + bodySize );
        }
        data.push_back( 0 );
        BYTE digest[32];
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider( &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0 );
        if ( NT_SUCCESS( status ) )
        {
            status = BCryptHash( algorithm, nullptr, 0, data.data(), static_cast<ULONG>( data.size() ), digest,
                                 sizeof( digest ) );
            BCryptCloseAlgorithmProvider( algorithm, 0 );
        }
        SecureZeroMemory( data.data(), data.size() );
        if ( !NT_SUCCESS( status ) ) return HRESULT_FROM_NT( status );
        ULONG written = 0;
        status = BCryptSignHash( key, nullptr, digest, sizeof( digest ), raw + 12, 64, &written, 0 );
        if ( !NT_SUCCESS( status ) ) return HRESULT_FROM_NT( status );
        if ( written != 64 ) return E_UNEXPECTED;
        return encode_base64( sizeof( raw ), raw, 104, signature, TRUE );
    }
    catch ( const std::bad_alloc & )
    {
        return E_OUTOFMEMORY;
    }
}

HRESULT WINAPI XUserImpl::XUserDuplicateHandle( XUserHandle handle, XUserHandle *duplicatedHandle )
{

    if ( !duplicatedHandle ) return E_INVALIDARG;
    *duplicatedHandle = NULL;
    if ( !handle ) return E_INVALIDARG;
    ( handle )->AddRef();
    *duplicatedHandle = handle;
    return S_OK;
}

void WINAPI XUserImpl::XUserCloseHandle( XUserHandle user )
{

    if ( user ) ( user )->Release();
}

INT32 WINAPI XUserImpl::XUserCompare( XUserHandle user1, XUserHandle user2 )
{
    UINT64 a = user1 ? user1->xuid : 0, b = user2 ? user2->xuid : 0;

    if ( user1 == user2 ) return 0;
    return a < b ? -1 : a > b ? 1 : 0;
}

HRESULT WINAPI XUserImpl::XUserGetMaxUsers( UINT32 *maxUsers )
{

    if ( !maxUsers ) return E_INVALIDARG;
    *maxUsers = 1;
    return S_OK;
}

static struct XUser *signed_in_user;
static SRWLOCK signed_in_section = SRWLOCK_INIT;

static void set_signed_in_user( struct XUser *user )
{
    AcquireSRWLockExclusive( &signed_in_section );
    ( user )->AddRef();
    if ( signed_in_user ) ( signed_in_user )->Release();
    signed_in_user = user;
    nexus::user::offlineIdentityInUse = user->offline;
    ReleaseSRWLockExclusive( &signed_in_section );
}

BOOL xuser_is_current_user( XUserHandle user )
{
    BOOL current;
    AcquireSRWLockExclusive( &signed_in_section );
    current = user && user == signed_in_user;
    ReleaseSRWLockExclusive( &signed_in_section );
    return current;
}

static HRESULT find_signed_in_user( UINT64 xuid, UINT64 localId, XUserHandle *handle )
{
    HRESULT hr = E_GAMEUSER_USER_NOT_FOUND;
    if ( !handle ) return E_INVALIDARG;
    *handle = NULL;
    AcquireSRWLockExclusive( &signed_in_section );
    if ( signed_in_user && ( ( xuid && signed_in_user->xuid == xuid ) || ( localId && localId == 1 ) ) )
    {
        ( signed_in_user )->AddRef();
        *handle = signed_in_user;
        hr = S_OK;
    }
    ReleaseSRWLockExclusive( &signed_in_section );
    return hr;
}

static const char UserAddIdentity = 0;
static HRESULT WINAPI XUserAddProvider( XAsyncOp op, const XAsyncProviderData *data )
{
    auto context = static_cast<XUserAddContext *>( data->context );
    if ( op == XAsyncOp::Cleanup )
    {
        context->Release();
        return S_OK;
    }
    UserAddContextRef retained( context );
    IXThreadingImpl *threading = nullptr;
    auto hr =
        QueryApiImpl( CLSID_XThreadingImpl, __uuidof( IXThreadingImpl ), reinterpret_cast<void **>( &threading ) );
    if ( FAILED( hr ) ) return hr;
    switch ( op )
    {
    case XAsyncOp::Begin:
        hr = threading->XAsyncSchedule( data->async, 0 );
        break;
    case XAsyncOp::GetResult:
        memcpy( data->buffer, &context->user, sizeof( XUserHandle ) );
        context->user = nullptr;
        break;
    case XAsyncOp::DoWork:
    {
        AcquireSRWLockExclusive( &context->lock );
        if ( context->completed )
        {
            ReleaseSRWLockExclusive( &context->lock );
            break;
        }
        context->user = new ( std::nothrow ) XUser( *context->transport );
        auto user = context->user;
        if ( user ) user->ref = 1;
        ReleaseSRWLockExclusive( &context->lock );
        if ( !user )
        {
            context->Complete( threading, E_OUTOFMEMORY );
            break;
        }
        const auto com = CoInitializeEx( nullptr, COINIT_MULTITHREADED );
        hr = user->Initialize( context->options );
        if ( SUCCEEDED( com ) ) CoUninitialize();
        if ( SUCCEEDED( hr ) && !context->completed )
        {
            auto init = new ( std::nothrow ) UserNetworkInit{ user, context, threading };
            if ( !init )
                hr = E_OUTOFMEMORY;
            else
            {
                user->AddRef();
                context->AddRef();
                threading->AddRef();
                ChangeSignInWorkers( true );
                auto thread = CreateThread( nullptr, 0, UserNetworkInitThread, init, 0, nullptr );
                if ( thread )
                {
                    CloseHandle( thread );
                    hr = E_PENDING;
                }
                else
                {
                    hr = HRESULT_FROM_WIN32( GetLastError() );
                    user->Release();
                    context->Release();
                    threading->Release();
                    delete init;
                    ChangeSignInWorkers( false );
                }
            }
        }
        if ( hr != E_PENDING )
        {
            context->Complete( threading, hr );
            hr = S_OK;
        }
        break;
    }
    case XAsyncOp::Cancel:
        context->Complete( threading, E_ABORT );
        break;
    case XAsyncOp::Cleanup:
        break;
    }
    threading->Release();
    return hr;
}
HRESULT WINAPI XUserImpl::XUserAddAsync( XUserAddOptions options, XAsyncBlock *async )
{
    if ( !async ) return E_POINTER;
    IXThreadingImpl *threading = nullptr;
    auto hr =
        QueryApiImpl( CLSID_XThreadingImpl, __uuidof( IXThreadingImpl ), reinterpret_cast<void **>( &threading ) );
    if ( FAILED( hr ) ) return hr;
    auto context = new ( std::nothrow ) XUserAddContext;
    if ( !context )
    {
        threading->Release();
        return E_OUTOFMEMORY;
    }
    context->options = options;
    context->transport = &transport;
    context->async = async;
    hr = threading->XAsyncBegin( async, context, &UserAddIdentity, "XUserAddAsync", XUserAddProvider );
    threading->Release();
    if ( FAILED( hr ) ) context->Release();
    return hr;
}
HRESULT WINAPI XUserImpl::XUserAddResult( XAsyncBlock *async, XUserHandle *newUser )
{
    if ( !async || !newUser ) return E_POINTER;
    *newUser = nullptr;
    IXThreadingImpl *threading = nullptr;
    auto hr =
        QueryApiImpl( CLSID_XThreadingImpl, __uuidof( IXThreadingImpl ), reinterpret_cast<void **>( &threading ) );
    if ( FAILED( hr ) ) return hr;
    SIZE_T size = 0;
    hr = threading->XAsyncGetResultSize( async, &size );
    if ( SUCCEEDED( hr ) )
        hr = size == sizeof( *newUser )
                 ? threading->XAsyncGetResult( async, &UserAddIdentity, sizeof( *newUser ), newUser, nullptr )
                 : E_INVALIDARG;
    threading->Release();
    if ( SUCCEEDED( hr ) && *newUser ) nexus::presence::Start( *newUser );
    return hr;
}

HRESULT WINAPI XUserImpl::XUserGetLocalId( XUserHandle user, XUserLocalId *userLocalId )
{

    if ( !user || !userLocalId ) return E_INVALIDARG;
    userLocalId->value = 1;
    return S_OK;
}

HRESULT WINAPI XUserImpl::XUserFindUserByLocalId( XUserLocalId userLocalId, XUserHandle *handle )
{

    return find_signed_in_user( 0, userLocalId.value, handle );
}

HRESULT WINAPI XUserImpl::XUserGetId( XUserHandle user, UINT64 *userId )
{

    if ( !user || !userId ) return E_INVALIDARG;
    if ( FAILED( user_wait_init( user ) ) ) return E_GAMEUSER_NO_DEFAULT_USER;
    *userId = user->xuid;
    return S_OK;
}

HRESULT WINAPI XUserImpl::XUserFindUserById( UINT64 userId, XUserHandle *handle )
{

    return find_signed_in_user( userId, 0, handle );
}

HRESULT WINAPI XUserImpl::XUserGetIsGuest( XUserHandle user, BOOLEAN *isGuest )
{

    if ( !user || !isGuest ) return E_INVALIDARG;
    /* This provider creates authenticated Xbox users, not guest users. */
    *isGuest = FALSE;
    return S_OK;
}

HRESULT WINAPI XUserImpl::XUserGetState( XUserHandle user, XUserState *state )
{

    if ( !user || !state ) return E_INVALIDARG;
    /* SignedIn describes platform identity, not network connectivity. Preserve
     * the PR#28 XUser handle and its real identity/token/cloud-save data. */
    *state = user->xuid ? XUserState::SignedIn : XUserState::SignedOut;
    return S_OK;
}

HRESULT WINAPI XUserImpl::__PADDING__()
{

    return E_NOTIMPL;
}

struct XUserGetGamerPictureContext
{
    LONG refs, canceled;
    XUserHandle user;
    XUserGamerPictureSize pictureSize;
    SIZE_T bufferSize;
    BYTE *buffer;
};

static void gamer_picture_release( struct XUserGetGamerPictureContext *context )
{
    if ( !InterlockedDecrement( &context->refs ) )
    {
        ( context->user )->Release();
        free( context->buffer );
        free( context );
    }
}

static HRESULT WINAPI gamer_picture_phase( XAsyncOp op, const XAsyncProviderData *data )
{
    IJsonObject *object = NULL, *profile = NULL, *setting = NULL;
    static const WCHAR *accept[] = { L"image/png", NULL };
    WCHAR *auth = NULL, *headers = NULL, *url = NULL;
    WCHAR signatureW[104] = { 0 };
    char *authA = NULL, signature[104];
    struct endpoint info;
    static const char profileUrlA[] = "https://profile.xboxlive.com/users/me/profile/settings?settings=PublicGamerpic";
    static const WCHAR profileUrlW[] =
        L"https://profile.xboxlive.com/users/me/profile/settings?settings=PublicGamerpic";
    IJsonArray *profiles = NULL, *settings = NULL;
    struct XUserGetGamerPictureContext *context;
    const WCHAR *suffix, *valueBuffer;
    IXThreadingImpl *xthreading;
    HSTRING value = NULL;
    BYTE *buffer = NULL;
    SIZE_T size;
    HRESULT hr;

    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&xthreading ) ) ) return hr;
    context = ( struct XUserGetGamerPictureContext * )data->context;

    switch ( op )
    {
    case XAsyncOp::Begin:
        hr = ( xthreading )->XAsyncSchedule( data->async, 0 );
        break;

    case XAsyncOp::GetResult:
        memcpy( data->buffer, context->buffer, context->bufferSize );
        break;

    case XAsyncOp::DoWork:
        switch ( context->pictureSize )
        {
        case XUserGamerPictureSize::Small:
            suffix = L"&format=png&w=64&h=64";
            break;
        case XUserGamerPictureSize::Medium:
            suffix = L"&format=png&w=208&h=208";
            break;
        case XUserGamerPictureSize::Large:
            suffix = L"&format=png&w=424&h=424";
            break;
        case XUserGamerPictureSize::ExtraLarge:
            suffix = L"&format=png&w=1080&h=1080";
            break;
        default:
            hr = E_INVALIDARG;
            goto cleanup;
        }

        if ( FAILED( hr = ( context->user )->GetAuthorization( L"http://xboxlive.com", &auth ) ) ) goto cleanup;
        /* This internal call needs the same proof-of-possession signature
         * as title requests, and the profile service's v2 contract. Never
         * forward the Xbox credential or signature to the image CDN. */
        if ( FAILED( hr = ( context->user )->GetEndpointInfo( profileUrlA, &info ) ) ) goto cleanup;
        if ( info.policy )
        {
            int authLength = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, auth, -1, NULL, 0, NULL, NULL );
            if ( !authLength )
            {
                hr = HRESULT_FROM_WIN32( GetLastError() );
                goto cleanup;
            }
            if ( !( authA = static_cast<std::remove_reference_t<decltype( authA )>>( calloc( authLength, 1 ) ) ) )
            {
                hr = E_OUTOFMEMORY;
                goto cleanup;
            }
            if ( !WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, auth, -1, authA, authLength, NULL, NULL ) )
            {
                hr = HRESULT_FROM_WIN32( GetLastError() );
                goto cleanup;
            }
            if ( FAILED(
                     hr = ( context->user )
                              ->GetSignature( info.policy->version, "GET", profileUrlA, authA, 0, NULL, signature ) ) )
                goto cleanup;
            if ( !MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, signature, 104, signatureW, 104 ) )
            {
                hr = HRESULT_FROM_WIN32( GetLastError() );
                goto cleanup;
            }
        }
        if ( !( headers = static_cast<std::remove_reference_t<decltype( headers )>>(
                    calloc( wcslen( auth ) + wcslen( signatureW ) + 96, sizeof( WCHAR ) ) ) ) )
        {
            hr = E_OUTOFMEMORY;
            goto cleanup;
        }
        wcscpy( headers, L"Authorization: " );
        wcscat( headers, auth );
        wcscat( headers, L"\r\nx-xbl-contract-version: 2\r\n" );
        if ( signatureW[0] )
        {
            wcscat( headers, L"Signature: " );
            wcscat( headers, signatureW );
            wcscat( headers, L"\r\n" );
        }
        if ( FAILED( hr = context->user->transport.Http( L"GET", profileUrlW, NULL, headers, ACCEPT_JSON, &buffer,
                                                         &size ) ) )
            goto cleanup;
        if ( FAILED( hr = parse_json( ( char * )buffer, size, &object ) ) ) goto cleanup;
        if ( FAILED( hr = get_json_array( object, L"profileUsers", &profiles ) ) ) goto cleanup;
        if ( FAILED( hr = ( profiles )->GetObjectAt( 0, &profile ) ) ) goto cleanup;
        if ( FAILED( hr = get_json_array( profile, L"settings", &settings ) ) ) goto cleanup;
        if ( FAILED( hr = ( settings )->GetObjectAt( 0, &setting ) ) ) goto cleanup;
        if ( FAILED( hr = get_json_string( setting, L"value", &value ) ) ) goto cleanup;
        valueBuffer = WindowsGetStringRawBuffer( value, NULL );
        if ( !( url = static_cast<std::remove_reference_t<decltype( url )>>(
                    calloc( wcslen( valueBuffer ) + wcslen( suffix ) + 1, sizeof( WCHAR ) ) ) ) )
        {
            hr = E_OUTOFMEMORY;
            goto cleanup;
        }

        wcscpy( url, valueBuffer );
        wcscat( url, suffix );
        if ( !wcschr( valueBuffer, '?' ) ) url[wcslen( valueBuffer )] = '?';
        hr = context->user->transport.Http( L"GET", url, NULL, NULL, accept, &context->buffer, &context->bufferSize );

    cleanup:
        ( xthreading )->XAsyncComplete( data->async, hr, SUCCEEDED( hr ) ? context->bufferSize : 0 );
        if ( profiles ) ( profiles )->Release();
        if ( settings ) ( settings )->Release();
        if ( profile ) ( profile )->Release();
        if ( setting ) ( setting )->Release();
        if ( object ) ( object )->Release();
        if ( value ) WindowsDeleteString( value );
        if ( headers ) free( headers );
        if ( buffer ) free( buffer );
        if ( auth ) free( auth );
        free( authA );
        if ( url ) free( url );
        hr = S_OK;
        break;

    case XAsyncOp::Cleanup:
        gamer_picture_release( context );
        break;

    case XAsyncOp::Cancel:
        InterlockedExchange( &context->canceled, TRUE );
        break;
    }

    ( xthreading )->Release();
    return hr;
}

struct gamer_picture_worker
{
    XAsyncProviderData data;
    IXThreadingImpl *threading;
};

static DWORD WINAPI gamer_picture_worker_thread( void *arg )
{
    struct gamer_picture_worker *worker = static_cast<struct gamer_picture_worker *>( arg );
    auto *context = static_cast<XUserGetGamerPictureContext *>( worker->data.context );
    HRESULT hr, com = CoInitializeEx( NULL, COINIT_MULTITHREADED );
    hr = InterlockedCompareExchange( &context->canceled, 0, 0 )
             ? E_ABORT
             : gamer_picture_phase( XAsyncOp::DoWork, &worker->data );
    if ( FAILED( hr ) ) ( worker->threading )->XAsyncComplete( worker->data.async, hr, 0 );
    if ( SUCCEEDED( com ) ) CoUninitialize();
    gamer_picture_release( context );
    ( worker->threading )->Release();
    free( worker );
    return 0;
}

static HRESULT WINAPI XUserGetGamerPictureProvider( XAsyncOp op, const XAsyncProviderData *data )
{
    struct XUserGetGamerPictureContext *context = static_cast<struct XUserGetGamerPictureContext *>( data->context );
    struct gamer_picture_worker *worker;
    HANDLE thread;
    HRESULT hr;
    if ( op != XAsyncOp::DoWork ) return gamer_picture_phase( op, data );
    if ( !( worker = static_cast<std::remove_reference_t<decltype( worker )>>( calloc( 1, sizeof( *worker ) ) ) ) )
        return E_OUTOFMEMORY;
    worker->data = *data;
    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&worker->threading ) ) )
    {
        free( worker );
        return hr;
    }
    InterlockedIncrement( &context->refs );
    if ( !( thread = CreateThread( NULL, 0, gamer_picture_worker_thread, worker, 0, NULL ) ) )
    {
        hr = HRESULT_FROM_WIN32( GetLastError() );
        gamer_picture_release( context );
        ( worker->threading )->Release();
        free( worker );
        return hr;
    }
    CloseHandle( thread );
    return E_PENDING;
}

HRESULT WINAPI XUserImpl::XUserGetGamerPictureAsync( XUserHandle user, XUserGamerPictureSize pictureSize,
                                                     XAsyncBlock *async )
{
    struct XUserGetGamerPictureContext *context;
    IXThreadingImpl *xthreading;
    HRESULT hr;

    if ( !user || !async ) return E_POINTER;
    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&xthreading ) ) ) return hr;
    if ( !( context = static_cast<std::remove_reference_t<decltype( context )>>( calloc( 1, sizeof( *context ) ) ) ) )
    {
        ( xthreading )->Release();
        return E_OUTOFMEMORY;
    }

    context->refs = 1;
    context->pictureSize = pictureSize;
    if ( FAILED( hr = this->XUserDuplicateHandle( user, &context->user ) ) )
    {
        ( xthreading )->Release();
        free( context );
        return hr;
    }

    hr = ( xthreading )->XAsyncBegin( async, context, NULL, "XUserGetGamerPictureAsync", XUserGetGamerPictureProvider );
    ( xthreading )->Release();
    if ( FAILED( hr ) ) gamer_picture_release( context );
    return hr;
}

HRESULT WINAPI XUserImpl::XUserGetGamerPictureResultSize( XAsyncBlock *async, SIZE_T *bufferSize )
{
    IXThreadingImpl *xthreading;
    HRESULT hr;

    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&xthreading ) ) ) return hr;
    hr = ( xthreading )->XAsyncGetResultSize( async, bufferSize );
    ( xthreading )->Release();
    return hr;
}

HRESULT WINAPI XUserImpl::XUserGetGamerPictureResult( XAsyncBlock *async, SIZE_T bufferSize, void *buffer,
                                                      SIZE_T *bufferUsed )
{
    IXThreadingImpl *xthreading;
    HRESULT hr;

    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&xthreading ) ) ) return hr;
    hr = ( xthreading )->XAsyncGetResult( async, NULL, bufferSize, buffer, bufferUsed );
    ( xthreading )->Release();
    return hr;
}

HRESULT WINAPI XUserImpl::XUserGetAgeGroup( XUserHandle user, XUserAgeGroup *ageGroup )
{
    HRESULT hr;

    if ( !user || !ageGroup ) return E_INVALIDARG;
    *ageGroup = XUserAgeGroup::Unknown;
    if ( FAILED( hr = user_wait_init( user ) ) ) return hr;
    *ageGroup = user->age_group;
    return S_OK;
}

HRESULT XUser::CachePrivileges( const WCHAR *identity, UINT32 identitySize, const WCHAR *claims, UINT32 claimsSize )
{
    static constexpr XUserPrivilege known[] = { XUserPrivilege::CrossPlay,
                                                XUserPrivilege::Clubs,
                                                XUserPrivilege::Sessions,
                                                XUserPrivilege::Broadcast,
                                                XUserPrivilege::ManageProfilePrivacy,
                                                XUserPrivilege::GameDvr,
                                                XUserPrivilege::MultiplayerParties,
                                                XUserPrivilege::CloudManageSession,
                                                XUserPrivilege::CloudJoinSession,
                                                XUserPrivilege::CloudSavedGames,
                                                XUserPrivilege::SocialNetworkSharing,
                                                XUserPrivilege::UserGeneratedContent,
                                                XUserPrivilege::Communications,
                                                XUserPrivilege::Multiplayer,
                                                XUserPrivilege::AddFriends };
    BYTE verified[256]{};
    for ( auto privilege : known )
    {
        BOOLEAN granted = FALSE;
        HRESULT hr = privilege_claim( identity, identitySize, xuid, claims, claimsSize, privilege, &granted );
        if ( FAILED( hr ) ) return hr;
        verified[static_cast<UINT32>( privilege )] = granted;
    }
    AcquireSRWLockExclusive( &privilegeLock );
    memcpy( grantedPrivileges, verified, sizeof( verified ) );
    privilegesCheckedAt = GetTickCount64();
    privilegesKnown = TRUE;
    ReleaseSRWLockExclusive( &privilegeLock );
    return S_OK;
}

HRESULT XUser::CheckPrivilege( XUserPrivilege privilege, BOOLEAN *granted, XUserPrivilegeDenyReason *reason )
{
    if ( !granted ) return E_INVALIDARG;
    *granted = FALSE;
    if ( reason ) *reason = XUserPrivilegeDenyReason::Unknown;
    if ( !privilege_valid( privilege ) ) return E_INVALIDARG;
    HRESULT hr = user_wait_init( this );
    if ( FAILED( hr ) ) return hr;
    AcquireSRWLockShared( &privilegeLock );
    bool cached = privilegesKnown && GetTickCount64() - privilegesCheckedAt < 60000;
    if ( cached ) *granted = grantedPrivileges[static_cast<UINT32>( privilege )];
    ReleaseSRWLockShared( &privilegeLock );
    if ( !cached )
    {
        char *authorization = nullptr;
        hr = xsts_authorize_privilege( this, "http://xboxlive.com", TRUE, &authorization, privilege, granted );
        free( authorization );
        if ( FAILED( hr ) ) return hr;
    }
    if ( reason && *granted ) *reason = XUserPrivilegeDenyReason::None;
    return S_OK;
}

HRESULT WINAPI XUserImpl::XUserCheckPrivilege( XUserHandle user, XUserPrivilegeOptions options,
                                               XUserPrivilege privilege, BOOLEAN *hasPrivilege,
                                               XUserPrivilegeDenyReason *reason )
{
    if ( !hasPrivilege ) return E_INVALIDARG;
    *hasPrivilege = FALSE;
    if ( reason ) *reason = XUserPrivilegeDenyReason::Unknown;
    if ( !user || ( options != XUserPrivilegeOptions::None && options != XUserPrivilegeOptions::AllUsers ) )
        return E_INVALIDARG;
    return user->CheckPrivilege( privilege, hasPrivilege, reason );
}

static HRESULT user_verify_privilege( XUser *iface, XUserPrivilege privilege )
{
    XUserHandle user = iface;
    BOOLEAN granted = FALSE;
    char *auth = NULL;
    HRESULT hr;
    if ( FAILED( hr = user_wait_init( user ) ) ) return hr;
    if ( !user->xuid || !user->userToken || !user->deviceToken || !user->proofKey ) return E_GAMEUSER_NO_AUTH_USER;
    hr = xsts_authorize_privilege( user, "http://xboxlive.com", TRUE, &auth, privilege, &granted );
    free( auth );
    if ( SUCCEEDED( hr ) && !granted ) hr = E_GAMEUSER_FAILED_TO_RESOLVE;
    /* Parent/ban/subscription remediation UI is not implemented. Never claim
     * resolution, or change account settings, when the service denies access. */
    auth_metadata( "resolve-privilege", user, hr, 0, TRUE, !!user->titleToken );

    return hr;
}

HRESULT WINAPI XUserImpl::XUserResolvePrivilegeWithUiAsync( XUserHandle user, XUserPrivilegeOptions options,
                                                            XUserPrivilege privilege, XAsyncBlock *async )
{
    IXThreadingImpl *threading;
    HRESULT hr;

    if ( !user || !async || !xuser_is_current_user( user ) ) return E_INVALIDARG;
    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&threading ) ) ) return hr;
    hr = privilege_begin( threading, user, options, privilege, async, user_verify_privilege );
    ( threading )->Release();
    return hr;
}

HRESULT WINAPI XUserImpl::XUserResolvePrivilegeWithUiResult( XAsyncBlock *async )
{
    IXThreadingImpl *threading;
    HRESULT hr;

    if ( !async ) return E_INVALIDARG;
    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&threading ) ) ) return hr;
    hr = privilege_result( threading, async );
    ( threading )->Release();
    return hr;
}

static const char tokenSignatureIdentity = 0, tokenSignatureUtf16Identity = 0;

static bool AddTokenContextSize( SIZE_T &size, SIZE_T extra ) noexcept
{
    if ( extra > SIZE_MAX - size ) return false;
    size += extra;
    return true;
}

struct XUserGetTokenAndSignatureContext
{
    LONG refs;
    LONG canceled;
    XUserHandle user;
    XUserGetTokenAndSignatureOptions options;
    char *url;
    char *method;
    SIZE_T headersSize;
    char *headers;
    SIZE_T bodySize;
    void *bodyBuffer;
    BOOLEAN isUtf16;
    SIZE_T dataSize;
    union
    {
        XUserGetTokenAndSignatureData *data;
        XUserGetTokenAndSignatureUtf16Data *dataUtf16;
    };
};

static void token_signature_release( struct XUserGetTokenAndSignatureContext *context )
{
    if ( !InterlockedDecrement( &context->refs ) )
    {
        ( context->user )->Release();
        free( context->data );
        free( context );
    }
}

/* Work is invoked only by the retained background worker below. Other provider
 * phases still execute on the caller's requested queue, including completion. */
static HRESULT WINAPI token_signature_phase( XAsyncOp op, const XAsyncProviderData *data )
{
    struct XUserGetTokenAndSignatureContext *context;
    char *buffer = NULL, signature[104];
    IXThreadingImpl *xthreading;
    struct endpoint info;
    WCHAR *auth = NULL;
    SIZE_T size = 0;
    HRESULT hr;

    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&xthreading ) ) ) return hr;
    context = ( struct XUserGetTokenAndSignatureContext * )data->context;

    switch ( op )
    {
    case XAsyncOp::Begin:
        hr = ( xthreading )->XAsyncSchedule( data->async, 0 );
        break;

    case XAsyncOp::GetResult:
    {
        char *base = ( char * )context->data, *out = static_cast<char *>( data->buffer );
        memcpy( out, base, context->dataSize );
        if ( context->isUtf16 )
        {
            XUserGetTokenAndSignatureUtf16Data *result =
                static_cast<XUserGetTokenAndSignatureUtf16Data *>( data->buffer );
            if ( result->token ) result->token = ( WCHAR * )( out + ( ( char * )result->token - base ) );
            if ( result->signature ) result->signature = ( WCHAR * )( out + ( ( char * )result->signature - base ) );
        }
        else
        {
            XUserGetTokenAndSignatureData *result = static_cast<XUserGetTokenAndSignatureData *>( data->buffer );
            if ( result->token ) result->token = out + ( result->token - base );
            if ( result->signature ) result->signature = out + ( result->signature - base );
        }
        break;
    }

    case XAsyncOp::DoWork:
    {
        HSTRING ownedParty = nullptr, ownedType = nullptr;
        auth_metadata( "get-token-begin", context->user, E_PENDING, 0, TRUE, !!context->user->titleToken );
        if ( FAILED( hr = ( context->user )->GetEndpointInfo( context->url, &info ) ) )
        {
            memset( &info, 0, sizeof( info ) );
            if ( FAILED( hr = token_fallback_party( context->url, &ownedParty ) ) ||
                 FAILED( hr = WindowsCreateString( L"JWT", 3, &ownedType ) ) ) goto complete;
            info.relyingParty = ownedParty;
            info.tokenType = ownedType;
        }
        if ( info.tokenType &&
             FAILED( hr = ( context->user )
                              ->GetAuthorization( WindowsGetStringRawBuffer( info.relyingParty, NULL ), &auth ) ) )
            goto complete;

        if ( context->isUtf16 )
        {
            /* The working community stand-in returns a present, empty
             * signature (count 1, L"") when no signature policy applies;
             * consumers treat NULL as a hard failure on this title. */
            /* XUser writes 104 base64 characters, without a terminator.
             * Public results are C strings, including the trailing NUL in
             * their buffer counts, just like the authorization token. */
            context->dataSize = sizeof( *context->dataUtf16 ) +
                                ( auth ? ( wcslen( auth ) + 1 ) * sizeof( WCHAR ) : 0 ) +
                                ( info.policy ? 105 * sizeof( WCHAR ) : sizeof( WCHAR ) );
            if ( !( context->dataUtf16 = static_cast<std::remove_reference_t<decltype( context->dataUtf16 )>>(
                        calloc( 1, context->dataSize ) ) ) )
            {
                hr = E_OUTOFMEMORY;
                goto complete;
            }
            if ( auth )
            {
                context->dataUtf16->tokenCount = wcslen( auth ) + 1;
                context->dataUtf16->token = ( WCHAR * )( context->dataUtf16 + 1 );
                wcscpy( ( WCHAR * )context->dataUtf16->token, auth );
            }
            if ( info.policy )
            {
                if ( auth )
                {
                    if ( !( size =
                                WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, auth, -1, NULL, 0, NULL, NULL ) ) )
                        goto error;
                    if ( !( buffer = static_cast<std::remove_reference_t<decltype( buffer )>>( calloc( 1, size ) ) ) )
                    {
                        hr = E_OUTOFMEMORY;
                        goto complete;
                    }
                    if ( !WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, auth, -1, buffer, size, NULL, NULL ) )
                        goto error;
                }
                context->dataUtf16->signatureCount = 105;
                context->dataUtf16->signature =
                    ( WCHAR * )( context->dataUtf16 + 1 ) + ( auth ? wcslen( auth ) + 1 : 0 );
                if ( FAILED( hr = ( context->user )
                                      ->GetSignature( info.policy->version, context->method, context->url,
                                                      ( auth ? buffer : "" ),
                                                      std::min<SIZE_T>( context->bodySize, info.policy->maxBodyBytes ),
                                                      context->bodyBuffer, signature ) ) )
                    goto complete;
                if ( !MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, signature, 104,
                                           ( WCHAR * )context->dataUtf16->signature, 104 ) )
                    goto error;
            }
            else
            {
                context->dataUtf16->signatureCount = 1;
                context->dataUtf16->signature =
                    ( WCHAR * )( context->dataUtf16 + 1 ) + ( auth ? wcslen( auth ) + 1 : 0 );
            }
        }
        else
        {
            if ( auth && !( size = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, auth, wcslen( auth ), NULL, 0,
                                                        NULL, NULL ) ) )
                goto error;
            context->dataSize = sizeof( *context->data ) + ( auth ? size + 1 : 0 ) + ( info.policy ? 105 : 1 );
            if ( !( context->data = static_cast<std::remove_reference_t<decltype( context->data )>>(
                        calloc( 1, context->dataSize ) ) ) )
            {
                hr = E_OUTOFMEMORY;
                goto complete;
            }
            if ( auth )
            {
                context->data->tokenSize = size + 1;
                context->data->token = ( char * )( context->data + 1 );
                if ( !WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, auth, wcslen( auth ),
                                           ( char * )context->data->token, size, NULL, NULL ) )
                    goto error;
            }
            if ( info.policy )
            {
                context->data->signatureSize = 105;
                context->data->signature = ( char * )( context->data + 1 ) + ( auth ? size + 1 : 0 );
                if ( FAILED( hr = ( context->user )
                                      ->GetSignature( info.policy->version, context->method, context->url,
                                                      ( auth ? context->data->token : "" ),
                                                      std::min<SIZE_T>( context->bodySize, info.policy->maxBodyBytes ),
                                                      context->bodyBuffer, ( char * )context->data->signature ) ) )
                    goto complete;
            }
            else
            {
                context->data->signatureSize = 1;
                context->data->signature = ( char * )( context->data + 1 ) + ( auth ? size + 1 : 0 );
            }
        }
        goto complete;

    error:
        hr = HRESULT_FROM_WIN32( GetLastError() );
    complete:
        WindowsDeleteString( ownedParty );
        WindowsDeleteString( ownedType );
        auth_metadata( "get-token-complete", context->user, hr, 0, TRUE, !!context->user->titleToken );
        if ( FAILED( hr ) )
        {
            free( context->data );
            context->data = NULL;
        }
        if ( buffer ) free( buffer );
        if ( auth ) free( auth );
        /* Completion can synchronously consume/free this context. */
        ( xthreading )->XAsyncComplete( data->async, hr, SUCCEEDED( hr ) ? context->dataSize : 0 );
        hr = S_OK;
        break;
    }

    case XAsyncOp::Cleanup:
        token_signature_release( context );
        break;

    case XAsyncOp::Cancel:
        InterlockedExchange( &context->canceled, TRUE );
        break;
    }

    ( xthreading )->Release();
    return hr;
}

struct token_signature_worker
{
    XAsyncProviderData data;
    IXThreadingImpl *threading;
};

static DWORD WINAPI token_signature_worker_thread( void *arg )
{
    struct token_signature_worker *worker = static_cast<struct token_signature_worker *>( arg );
    auto *context = static_cast<XUserGetTokenAndSignatureContext *>( worker->data.context );
    HRESULT hr, com = CoInitializeEx( NULL, COINIT_MULTITHREADED );
    if ( InterlockedCompareExchange( &context->canceled, 0, 0 ) )
        hr = E_ABORT;
    else
        hr = token_signature_phase( XAsyncOp::DoWork, &worker->data );
    /* The normal phase completes with the real network result. Cover failures
     * before it can complete too; XAsyncComplete is idempotent after cancel. */
    if ( FAILED( hr ) ) ( worker->threading )->XAsyncComplete( worker->data.async, hr, 0 );
    if ( SUCCEEDED( com ) ) CoUninitialize();
    token_signature_release( context );
    ( worker->threading )->Release();
    free( worker );
    return 0;
}

static HRESULT WINAPI XUserGetTokenAndSignatureProvider( XAsyncOp op, const XAsyncProviderData *data )
{
    struct XUserGetTokenAndSignatureContext *context =
        static_cast<struct XUserGetTokenAndSignatureContext *>( data->context );
    struct token_signature_worker *worker;
    HANDLE thread;
    HRESULT hr;
    if ( op != XAsyncOp::DoWork ) return token_signature_phase( op, data );
    if ( !( worker = static_cast<std::remove_reference_t<decltype( worker )>>( calloc( 1, sizeof( *worker ) ) ) ) )
        return E_OUTOFMEMORY;
    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&worker->threading ) ) )
    {
        free( worker );
        return hr;
    }
    worker->data = *data; /* Runtime-owned async block, not caller stack memory. */
    InterlockedIncrement( &context->refs );
    if ( !( thread = CreateThread( NULL, 0, token_signature_worker_thread, worker, 0, NULL ) ) )
    {
        hr = HRESULT_FROM_WIN32( GetLastError() );
        token_signature_release( context );
        ( worker->threading )->Release();
        free( worker );
        return hr;
    }
    CloseHandle( thread );
    return E_PENDING;
}

HRESULT WINAPI XUserImpl::XUserGetTokenAndSignatureAsync( XUserHandle user, XUserGetTokenAndSignatureOptions options,
                                                          const char *method, const char *url, SIZE_T headerCount,
                                                          const XUserGetTokenAndSignatureHttpHeader *headers,
                                                          SIZE_T bodySize, const void *bodyBuffer, XAsyncBlock *async )
{
    struct XUserGetTokenAndSignatureContext *context;
    SIZE_T contextSize, headersSize = 0;
    IXThreadingImpl *xthreading;
    HRESULT hr;
    char *ptr;

    if ( !user || !async || !method || !url || !*method || !*url || ( headerCount && !headers ) ||
         ( bodySize && !bodyBuffer ) || headerCount > SIZE_MAX / sizeof( *headers ) )
        return E_INVALIDARG;
    contextSize = sizeof( *context );
    if ( !AddTokenContextSize( contextSize, bodySize ) || !AddTokenContextSize( contextSize, strlen( url ) ) ||
         !AddTokenContextSize( contextSize, strlen( method ) ) || !AddTokenContextSize( contextSize, 2 ) )
        return E_INVALIDARG;
    for ( SIZE_T i = 0; i < headerCount; ++i )
    {
        if ( !headers[i].value || !AddTokenContextSize( headersSize, strlen( headers[i].value ) ) ||
             !AddTokenContextSize( headersSize, 1 ) )
            return E_INVALIDARG;
    }
    if ( !AddTokenContextSize( contextSize, headersSize ) ) return E_INVALIDARG;

    if ( !( context = static_cast<std::remove_reference_t<decltype( context )>>( calloc( 1, contextSize ) ) ) )
        return E_OUTOFMEMORY;
    context->refs = 1;
    ( user )->AddRef();
    context->user = user;
    context->options = options;
    context->headersSize = headersSize;
    context->bodySize = bodySize;
    context->isUtf16 = FALSE;

    /* url */
    ptr = ( char * )context + sizeof( *context );
    ptr += strlen( strcpy( ( context->url = ptr ), url ) ) + 1;
    /* method */
    ptr += ( strlen( strcpy( ( context->method = ptr ), method ) ) + 1 );
    /* headers */
    context->headers = ptr;
    for ( SIZE_T i = 0; i < headerCount; i++ )
        ptr += ( strlen( strcpy( ptr, headers[i].value ) ) + 1 );
    /* body */
    context->bodyBuffer = ptr;
    if ( bodySize ) memcpy( ptr, bodyBuffer, bodySize );

    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&xthreading ) ) ) goto error;
    hr = ( xthreading )
             ->XAsyncBegin( async, context, &tokenSignatureIdentity, "XUserGetTokenAndSignatureAsync",
                            XUserGetTokenAndSignatureProvider );
    ( xthreading )->Release();
    if ( FAILED( hr ) ) goto error;
    return hr;
error:
    free( context );
    ( user )->Release();
    return hr;
}

HRESULT WINAPI XUserImpl::XUserGetTokenAndSignatureResultSize( XAsyncBlock *async, SIZE_T *bufferSize )
{
    IXThreadingImpl *xthreading;
    HRESULT hr;

    if ( !async || !bufferSize ) return E_POINTER;
    *bufferSize = 0;
    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&xthreading ) ) ) return hr;
    hr = ( xthreading )->XAsyncGetResultSize( async, bufferSize );
    ( xthreading )->Release();
    return hr;
}

HRESULT WINAPI XUserImpl::XUserGetTokenAndSignatureResult( XAsyncBlock *async, SIZE_T bufferSize, void *buffer,
                                                           XUserGetTokenAndSignatureData **ptrToBuffer,
                                                           SIZE_T *bufferUsed )
{
    IXThreadingImpl *xthreading;
    HRESULT hr;

    if ( !ptrToBuffer ) return E_POINTER;
    *ptrToBuffer = nullptr;
    if ( bufferUsed ) *bufferUsed = 0;
    if ( !async || ( bufferSize && !buffer ) ) return E_INVALIDARG;
    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&xthreading ) ) ) return hr;
    hr = ( xthreading )->XAsyncGetResult( async, &tokenSignatureIdentity, bufferSize, buffer, bufferUsed );
    if ( SUCCEEDED( hr ) ) *ptrToBuffer = ( XUserGetTokenAndSignatureData * )buffer;
    ( xthreading )->Release();
    return hr;
}

HRESULT WINAPI XUserImpl::XUserGetTokenAndSignatureUtf16Async(
    XUserHandle user, XUserGetTokenAndSignatureOptions options, const WCHAR *method, const WCHAR *url,
    SIZE_T headerCount, const XUserGetTokenAndSignatureUtf16HttpHeader *headers, SIZE_T bodySize,
    const void *bodyBuffer, XAsyncBlock *async )
{
    SIZE_T contextSize, headersSize = 0, methodLen, urlLen;
    struct XUserGetTokenAndSignatureContext *context;
    IXThreadingImpl *xthreading;
    HRESULT hr;
    char *ptr;
    int size;

    if ( !user || !async || !method || !url || !*method || !*url || ( headerCount && !headers ) ||
         ( bodySize && !bodyBuffer ) || headerCount > SIZE_MAX / sizeof( *headers ) )
        return E_INVALIDARG;
    contextSize = sizeof( *context );
    if ( !AddTokenContextSize( contextSize, bodySize ) ) return E_INVALIDARG;
    if ( !( methodLen = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, method, -1, NULL, 0, NULL, NULL ) ) )
        return HRESULT_FROM_WIN32( GetLastError() );
    if ( !( urlLen = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, url, -1, NULL, 0, NULL, NULL ) ) )
        return HRESULT_FROM_WIN32( GetLastError() );
    if ( !AddTokenContextSize( contextSize, urlLen ) || !AddTokenContextSize( contextSize, methodLen ) )
        return E_INVALIDARG;
    for ( SIZE_T i = 0; i < headerCount; i++ )
    {
        if ( !headers[i].value ) return E_INVALIDARG;
        if ( !( size =
                    WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, headers[i].value, -1, NULL, 0, NULL, NULL ) ) )
            return HRESULT_FROM_WIN32( GetLastError() );
        if ( !AddTokenContextSize( headersSize, size ) ) return E_INVALIDARG;
    }

    if ( !AddTokenContextSize( contextSize, headersSize ) ) return E_INVALIDARG;
    if ( !( context = static_cast<std::remove_reference_t<decltype( context )>>( calloc( 1, contextSize ) ) ) )
        return E_OUTOFMEMORY;
    context->refs = 1;
    ( user )->AddRef();
    context->user = user;
    context->options = options;
    context->headersSize = headersSize;
    context->bodySize = bodySize;
    context->isUtf16 = TRUE;

    /* url */
    ptr = ( char * )context + sizeof( *context );
    if ( !WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, url, -1, ( context->url = ptr ), urlLen, NULL, NULL ) )
        goto error_win32;
    ptr += urlLen;
    /* method */
    if ( !WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, method, -1, ( context->method = ptr ), methodLen, NULL,
                               NULL ) )
        goto error_win32;
    ptr += methodLen;
    /* headers */
    context->headers = ptr;
    for ( SIZE_T i = 0; i < headerCount; i++ )
    {
        if ( !( size =
                    WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, headers[i].value, -1, NULL, 0, NULL, NULL ) ) )
            goto error_win32;
        if ( !WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, headers[i].value, -1, ptr, size, NULL, NULL ) )
            goto error_win32;
        ptr += size;
    }
    /* body */
    context->bodyBuffer = ptr;
    if ( bodySize ) memcpy( ptr, bodyBuffer, bodySize );

    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&xthreading ) ) ) goto error;
    hr = ( xthreading )
             ->XAsyncBegin( async, context, &tokenSignatureUtf16Identity, "XUserGetTokenAndSignatureUtf16Async",
                            XUserGetTokenAndSignatureProvider );
    ( xthreading )->Release();
    if ( FAILED( hr ) ) goto error;
    return hr;

error_win32:
    hr = HRESULT_FROM_WIN32( GetLastError() );
error:
    free( context );
    ( user )->Release();
    return hr;
}

HRESULT WINAPI XUserImpl::XUserGetTokenAndSignatureUtf16ResultSize( XAsyncBlock *async, SIZE_T *bufferSize )
{
    IXThreadingImpl *xthreading;
    HRESULT hr;

    if ( !async || !bufferSize ) return E_POINTER;
    *bufferSize = 0;
    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&xthreading ) ) ) return hr;
    hr = ( xthreading )->XAsyncGetResultSize( async, bufferSize );
    ( xthreading )->Release();
    return hr;
}

HRESULT WINAPI XUserImpl::XUserGetTokenAndSignatureUtf16Result( XAsyncBlock *async, SIZE_T bufferSize, void *buffer,
                                                                XUserGetTokenAndSignatureUtf16Data **ptrToBuffer,
                                                                SIZE_T *bufferUsed )
{
    IXThreadingImpl *xthreading;
    HRESULT hr;

    if ( !ptrToBuffer ) return E_POINTER;
    *ptrToBuffer = nullptr;
    if ( bufferUsed ) *bufferUsed = 0;
    if ( !async || ( bufferSize && !buffer ) ) return E_INVALIDARG;
    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&xthreading ) ) ) return hr;
    hr = ( xthreading )->XAsyncGetResult( async, &tokenSignatureUtf16Identity, bufferSize, buffer, bufferUsed );
    if ( SUCCEEDED( hr ) ) *ptrToBuffer = ( XUserGetTokenAndSignatureUtf16Data * )buffer;
    ( xthreading )->Release();
    return hr;
}

HRESULT WINAPI XUserImpl::XUserResolveIssueWithUiAsync( XUserHandle user, const char *url, XAsyncBlock *async )
{

    return E_NOTIMPL;
}

HRESULT WINAPI XUserImpl::XUserResolveIssueWithUiResult( XAsyncBlock *async )
{

    return E_NOTIMPL;
}

HRESULT WINAPI XUserImpl::XUserResolveIssueWithUiUtf16Async( XUserHandle user, const WCHAR *url, XAsyncBlock *async )
{

    return E_NOTIMPL;
}

HRESULT WINAPI XUserImpl::XUserResolveIssueWithUiUtf16Result( XAsyncBlock *async )
{

    return E_NOTIMPL;
}

struct user_change_registration
{
    struct user_change_registration *next;
    UINT64 token;
    IXThreadingImpl *threading;
    XTaskQueueHandle queue;
    void *context;
    XUserChangeEventCallback *callback;
};

static struct user_change_registration *user_change_registrations;
static UINT64 next_user_change_token;

HRESULT WINAPI XUserImpl::XUserRegisterForChangeEvent( XTaskQueueHandle queue, void *context,
                                                       XUserChangeEventCallback *callback,
                                                       XTaskQueueRegistrationToken *token )
{
    struct user_change_registration *registration;
    IXThreadingImpl *threading;
    HRESULT hr;

    if ( !token ) return E_INVALIDARG;
    token->token = 0;
    if ( !callback ) return E_INVALIDARG;
    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&threading ) ) ) return hr;
    if ( !( registration = static_cast<std::remove_reference_t<decltype( registration )>>(
                calloc( 1, sizeof( *registration ) ) ) ) )
    {
        ( threading )->Release();
        return E_OUTOFMEMORY;
    }
    if ( queue )
        hr = ( threading )->XTaskQueueDuplicateHandle( queue, &registration->queue );
    else
        hr = ( threading )->XTaskQueueGetCurrentProcessTaskQueue( &registration->queue )
                 ? S_OK
                 : HRESULT_FROM_WIN32( ERROR_NO_TASK_QUEUE );
    if ( FAILED( hr ) )
    {
        free( registration );
        ( threading )->Release();
        return hr;
    }
    registration->threading = threading;
    registration->context = context;
    registration->callback = callback;
    AcquireSRWLockExclusive( &signed_in_section );
    if ( !++next_user_change_token ) ++next_user_change_token;
    token->token = registration->token = next_user_change_token;
    registration->next = user_change_registrations;
    user_change_registrations = registration;
    /* Registration observes future changes; adding the initial account is
     * completed by XUserAddAsync, not by a synthetic SignedInAgain event. */
    ReleaseSRWLockExclusive( &signed_in_section );
    return S_OK;
}

BOOLEAN WINAPI XUserImpl::XUserUnregisterForChangeEvent( XTaskQueueRegistrationToken token, BOOLEAN wait )
{
    struct user_change_registration **cursor, *registration = NULL;

    AcquireSRWLockExclusive( &signed_in_section );
    for ( cursor = &user_change_registrations; *cursor; cursor = &( *cursor )->next )
    {
        if ( ( *cursor )->token != token.token ) continue;
        registration = *cursor;
        *cursor = registration->next;
        break;
    }
    ReleaseSRWLockExclusive( &signed_in_section );
    if ( registration )
    {
        ( registration->threading )->XTaskQueueCloseHandle( registration->queue );
        ( registration->threading )->Release();
        free( registration );
    }
    /* No change callbacks are dispatched by the current single-account
     * provider, so there are no in-flight callbacks to wait for. If a future
     * provider dispatches them, add execution refs and cancellation/wait here. */
    return TRUE;
}

HRESULT WINAPI XUserImpl::XUserGetSignOutDeferral( XUserSignOutDeferralHandle *deferral )
{

    *deferral = NULL;
    return E_GAMEUSER_DEFERRAL_NOT_AVAILABLE;
}

void WINAPI XUserImpl::XUserCloseSignOutDeferralHandle( XUserSignOutDeferralHandle deferral ) {}

HRESULT WINAPI XUserImpl::XUserAddByIdWithUiAsync( UINT64 userId, XAsyncBlock *async )
{

    return E_NOTIMPL;
}

HRESULT WINAPI XUserImpl::XUserAddByIdWithUiResult( XAsyncBlock *async, XUserHandle *newUser )
{

    return E_NOTIMPL;
}

HRESULT WINAPI XUserImpl::XUserGetMsaTokenSilentlyAsync( XUserHandle user, XUserGetMsaTokenSilentlyOptions options,
                                                         const char *scope, XAsyncBlock *async )
{

    NEXUS_STORE_META( 11, E_NOTIMPL, 0, NULL );
    return E_NOTIMPL;
}

HRESULT WINAPI XUserImpl::XUserGetMsaTokenSilentlyResult( XAsyncBlock *async, SIZE_T resultTokenSize, char *resultToken,
                                                          SIZE_T *resultTokenUsed )
{

    NEXUS_STORE_META( 12, E_NOTIMPL, 0, NULL );
    return E_NOTIMPL;
}

HRESULT WINAPI XUserImpl::XUserGetMsaTokenSilentlyResultSize( XAsyncBlock *async, SIZE_T *tokenSize )
{

    NEXUS_STORE_META( 13, E_NOTIMPL, 0, NULL );
    return E_NOTIMPL;
}

BOOLEAN XUser::IsStoreUser()
{
    if ( FAILED( user_wait_init( this ) ) ) return FALSE;
    return xuid && xbox_msa_id[0] && store_msa_id[0] && !strcmp( xbox_msa_id, store_msa_id );
}

BOOLEAN WINAPI XUserImpl::XUserIsStoreUser( XUserHandle user )
{
    return user && xuser_is_current_user( user ) && user->IsStoreUser();
}

/* Remote-connect and SPoP prompt registrations are accepted and never
 * raised: this runtime has no remote device pairing or subscription
 * prompts to deliver. Refusing them in the session-setup window left the
 * title's platform state incomplete (observed in the Gears online
 * transition right before the queue/token flow). */
HRESULT WINAPI XUserImpl::XUserPlatformRemoteConnectSetEventHandlers(
    XTaskQueueHandle queue, XUserPlatformRemoteConnectEventHandlers *handlers )
{

    if ( !handlers ) return E_INVALIDARG;
    return S_OK;
}

HRESULT WINAPI XUserImpl::XUserPlatformRemoteConnectCancelPrompt( XUserPlatformOperation operation )
{

    return S_OK;
}

HRESULT WINAPI XUserImpl::XUserPlatformSpopPromptSetEventHandlers( XTaskQueueHandle queue,
                                                                   XUserPlatformSpopPromptEventHandler *handler,
                                                                   void *context )
{

    if ( !handler ) return E_INVALIDARG;
    return S_OK;
}

HRESULT WINAPI XUserImpl::XUserPlatformSpopPromptComplete( XUserPlatformOperation operation,
                                                           XUserPlatformOperationResult result )
{

    return S_OK;
}

BOOLEAN WINAPI XUserImpl::XUserIsSignOutPresent()
{

    return FALSE;
}

HRESULT WINAPI XUserImpl::XUserSignOutAsync( XUserHandle user, XAsyncBlock *async )
{

    return E_NOTIMPL;
}

HRESULT WINAPI XUserImpl::XUserSignOutResult( XAsyncBlock *async )
{

    return E_NOTIMPL;
}

HRESULT WINAPI XUserImpl::XUserGetGamertag( XUserHandle user, XUserGamertagComponent gamertagComponent,
                                            SIZE_T gamertagSize, char *gamertag, SIZE_T *gamertagUsed )
{

    if ( FAILED( user_wait_init( user ) ) ) return E_GAMEUSER_NO_DEFAULT_USER;

    switch ( gamertagComponent )
    {
    case XUserGamertagComponent::Classic:
        if ( gamertagSize <= strlen( user->gamertag ) ) return HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER );
        strcpy( gamertag, user->gamertag );
        if ( gamertagUsed ) *gamertagUsed = strlen( user->gamertag ) + 1;
        return S_OK;

    case XUserGamertagComponent::Modern:
        if ( gamertagSize <= strlen( user->modernGamertag ) ) return HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER );
        strcpy( gamertag, user->modernGamertag );
        if ( gamertagUsed ) *gamertagUsed = strlen( user->modernGamertag ) + 1;
        return S_OK;

    case XUserGamertagComponent::ModernSuffix:
        if ( gamertagSize <= strlen( user->modernGamertagSuffix ) )
            return HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER );
        strcpy( gamertag, user->modernGamertagSuffix );
        if ( gamertagUsed ) *gamertagUsed = strlen( user->modernGamertagSuffix ) + 1;
        return S_OK;

    case XUserGamertagComponent::UniqueModern:
        if ( gamertagSize <= strlen( user->uniqueModernGamertag ) )
            return HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER );
        strcpy( gamertag, user->uniqueModernGamertag );
        if ( gamertagUsed ) *gamertagUsed = strlen( user->uniqueModernGamertag ) + 1;
        return S_OK;
    }

    return E_INVALIDARG;
}

HRESULT WINAPI XUserImpl::XUserFindForDevice( const APP_LOCAL_DEVICE_ID *deviceId, XUserHandle *handle )
{

    return E_NOTIMPL;
}

#include "User/DeviceAssociations.h"

static BOOL audio_current_user( XUserLocalId *local )
{
    BOOL available;
    AcquireSRWLockExclusive( &signed_in_section );
    available = signed_in_user != NULL;
    if ( available ) local->value = 1;
    ReleaseSRWLockExclusive( &signed_in_section );
    return available;
}
#include "User/Audio.h"

HRESULT WINAPI XUserImpl::XUserRegisterForDeviceAssociationChanged( XTaskQueueHandle queue, void *context,
                                                                    XUserDeviceAssociationChangedCallback *callback,
                                                                    XTaskQueueRegistrationToken *token )
{

    return device_association_register( queue, context, callback, token );
}

BOOLEAN WINAPI XUserImpl::XUserUnregisterForDeviceAssociationChanged( XTaskQueueRegistrationToken token, BOOLEAN wait )
{

    return device_association_unregister( token, wait );
}

HRESULT WINAPI XUserImpl::XUserGetDefaultAudioEndpointUtf16( XUserLocalId user,
                                                             XUserDefaultAudioEndpointKind defaultAudioEndpointKind,
                                                             SIZE_T endpointIdUtf16Count, WCHAR *endpointIdUtf16,
                                                             SIZE_T *endpointIdUtf16Used )
{
    return audio_get_default( user, defaultAudioEndpointKind, endpointIdUtf16Count, endpointIdUtf16,
                              endpointIdUtf16Used );
}

HRESULT WINAPI XUserImpl::XUserRegisterForDefaultAudioEndpointUtf16Changed(
    XTaskQueueHandle queue, void *context, XUserDefaultAudioEndpointUtf16ChangedCallback *callback,
    XTaskQueueRegistrationToken *token )
{
    return audio_register( queue, context, callback, token );
}

BOOLEAN WINAPI XUserImpl::XUserUnregisterForDefaultAudioEndpointUtf16Changed( XTaskQueueRegistrationToken token,
                                                                              BOOLEAN wait )
{
    return audio_unregister( token, wait );
}

HRESULT WINAPI XUserImpl::XUserFindControllerForUserWithUiAsync( XUserHandle user, XAsyncBlock *async )
{

    return E_NOTIMPL;
}

HRESULT WINAPI XUserImpl::XUserFindControllerForUserWithUiResult( XAsyncBlock *async, APP_LOCAL_DEVICE_ID *deviceId )
{

    return E_NOTIMPL;
}

static char *hstring_to_utf8( HSTRING string )
{
    const WCHAR *buffer = WindowsGetStringRawBuffer( string, NULL );
    int size = WideCharToMultiByte( CP_UTF8, 0, buffer, -1, NULL, 0, NULL, NULL );
    char *out;

    if ( !size || !( out = static_cast<std::remove_reference_t<decltype( out )>>( calloc( 1, size ) ) ) ) return NULL;
    WideCharToMultiByte( CP_UTF8, 0, buffer, -1, out, size, NULL, NULL );
    return out;
}

static WCHAR *utf8_to_wide( const char *string )
{
    int size = MultiByteToWideChar( CP_UTF8, 0, string, -1, NULL, 0 );
    WCHAR *out;

    if ( !size || !( out = static_cast<std::remove_reference_t<decltype( out )>>( calloc( size, sizeof( WCHAR ) ) ) ) )
        return NULL;
    MultiByteToWideChar( CP_UTF8, 0, string, -1, out, size );
    return out;
}

UINT64 xuser_get_xuid( XUserHandle user )
{
    return user->xuid;
}

HRESULT xuser_signed_request( XUserHandle user, const char *method, const char *url, const char *auth,
                              const char *extraHeaders, const void *body, DWORD bodySize, DWORD *status, BYTE **buffer,
                              SIZE_T *bufferSize )
{
    WCHAR *methodW = NULL, *urlW = NULL, *headersW = NULL;
    char signature[105] = { 0 }, *headers = NULL;
    SIZE_T headersSize;
    HRESULT hr;

    if ( FAILED( hr = ( user )->GetSignature( 1, method, url, auth ? auth : "", std::min<SIZE_T>( bodySize, 8192 ),
                                              body, signature ) ) )
        return hr;
    headersSize = strlen( "Authorization: \r\nSignature: \r\n" ) + ( auth ? strlen( auth ) : 0 ) + 104 +
                  ( extraHeaders ? strlen( extraHeaders ) : 0 ) + 1;
    if ( !( headers = static_cast<std::remove_reference_t<decltype( headers )>>( calloc( 1, headersSize ) ) ) )
        return E_OUTOFMEMORY;
    if ( auth )
        snprintf( headers, headersSize, "Authorization: %s\r\nSignature: %s\r\n%s", auth, signature,
                  extraHeaders ? extraHeaders : "" );
    else
        snprintf( headers, headersSize, "Signature: %s\r\n%s", signature, extraHeaders ? extraHeaders : "" );

    if ( !( methodW = utf8_to_wide( method ) ) || !( urlW = utf8_to_wide( url ) ) ||
         !( headersW = utf8_to_wide( headers ) ) )
        hr = E_OUTOFMEMORY;
    else
    {
        for ( int attempt = 0; attempt < 3; attempt++ )
        {
            if ( attempt )
            {

                Sleep( 500 * attempt );
            }
            if ( SUCCEEDED( hr = user->transport.HttpRaw( methodW, urlW, headersW, body, bodySize, status, buffer,
                                                          bufferSize ) ) &&
                 *status < 500 )
                break;
            if ( SUCCEEDED( hr ) )
            {
                free( *buffer );
                *buffer = NULL;
                *bufferSize = 0;
            }
        }
    }

    free( methodW );
    free( urlW );
    free( headersW );
    free( headers );
    return hr;
}

static HRESULT xsts_authorize( XUserHandle user, const char *relyingParty, BOOL title, char **auth )
{
    return xsts_authorize_privilege( user, relyingParty, title, auth, static_cast<XUserPrivilege>( 0 ), NULL );
}

static HRESULT xsts_authorize_privilege( XUserHandle user, const char *relyingParty, BOOL title, char **auth,
                                         XUserPrivilege privilege, BOOLEAN *granted, bool presence )
{
    static const char url[] = "https://xsts.auth.xboxlive.com/xsts/authorize";
    IJsonObject *object = NULL, *claims = NULL, *identity = NULL;
    HSTRING token = NULL, uhs = NULL, xid = NULL, prv = NULL;
    char *body = NULL, *tokenA = NULL, *uhsA = NULL;
    IJsonArray *xui = NULL;
    BYTE *buffer = NULL;
    SIZE_T size, bufferSize;
    HRESULT hr, comInit = E_FAIL;
    DWORD status = 0;
    BOOL requested_title = title;

    auth_metadata( "xsts-begin", user, E_PENDING, 0, requested_title, FALSE );
    if ( granted ) *granted = FALSE;
    /* A cached offline identity has no tokens; report what an online attempt
     * would produce. */
    if ( user->offline ) return HRESULT_FROM_WIN32( ERROR_WINHTTP_CANNOT_CONNECT );
    if ( presence && ( !title || !user->titleToken || !*user->titleToken || !user->xuid ) ) return E_GAMEUSER_NO_AUTH_USER;

    if ( !user->deviceToken || !user->userToken || !user->proofKey )
    {
        auth_metadata( "xsts", user, E_UNEXPECTED, 0, requested_title, FALSE );
        return E_UNEXPECTED;
    }

    if ( !title || !user->titleToken ) title = FALSE;
    size = strlen( relyingParty ) + strlen( user->deviceToken ) + strlen( user->userToken ) + strlen( user->proofKey ) +
           ( title ? strlen( user->titleToken ) : 0 ) + 256;
    if ( !( body = static_cast<std::remove_reference_t<decltype( body )>>( calloc( 1, size ) ) ) )
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }
    snprintf( body, size,
              "{\"RelyingParty\":\"%s\",\"TokenType\":\"JWT\",\"Properties\":{\"SandboxId\":\"RETAIL\",\"DeviceToken\":"
              "\"%s\",%s%s%s\"UserTokens\":[\"%s\"],\"ProofKey\":%s}}",
              relyingParty, user->deviceToken, title ? "\"TitleToken\":\"" : "", title ? user->titleToken : "",
              title ? "\"," : "", user->userToken, user->proofKey );

    if ( FAILED( hr = xuser_signed_request( user, "POST", url, NULL,
                                            "x-xbl-contract-version: 1\r\nContent-Type: application/json\r\n", body,
                                            strlen( body ), &status, &buffer, &bufferSize ) ) )
        goto cleanup;
    if ( status != 200 )
    {
        auth_rejection_metadata(relyingParty, status, buffer, bufferSize);
        ERR( "xsts authorization failed, status %lu.\n", status );
        hr = E_FAIL;
        goto cleanup;
    }

    comInit = CoInitializeEx( NULL, COINIT_MULTITHREADED );
    if ( FAILED( hr = parse_json( ( char * )buffer, bufferSize, &object ) ) ) goto cleanup;
    if ( FAILED( hr = get_json_string( object, L"Token", &token ) ) ) goto cleanup;
    if ( FAILED( hr = get_json_object( object, L"DisplayClaims", &claims ) ) ) goto cleanup;
    if ( FAILED( hr = get_json_array( claims, L"xui", &xui ) ) ) goto cleanup;
    if ( FAILED( hr = ( xui )->GetObjectAt( 0, &identity ) ) ) goto cleanup;
    if ( FAILED( hr = get_json_string( identity, L"uhs", &uhs ) ) ) goto cleanup;
    if ( presence )
    {
        UINT32 count = 0; UINT64 actual = 0;
        if ( FAILED( hr = get_json_string( identity, L"xid", &xid ) ) ) goto cleanup;
        const auto text = WindowsGetStringRawBuffer( xid, &count );
        if ( !count || count > 20 ) { hr = E_GAMEUSER_NO_AUTH_USER; goto cleanup; }
        for ( UINT32 i = 0; i < count; ++i )
        {
            if ( text[i] < '0' || text[i] > '9' || actual > ( ~UINT64( 0 ) - ( text[i] - '0' ) ) / 10 )
            { hr = E_GAMEUSER_NO_AUTH_USER; goto cleanup; }
            actual = actual * 10 + text[i] - '0';
        }
        if ( actual != user->xuid ) { hr = E_GAMEUSER_NO_AUTH_USER; goto cleanup; }
    }
    if ( granted )
    {
        const WCHAR *xid_text, *prv_text;
        UINT32 xid_len, prv_len;
        /* Only accept the requested authenticated identity. Missing claims or
         * malformed data must never turn into guessed permission. */
        hr = get_json_string( identity, L"xid", &xid );
        auth_metadata( "privilege-identity-claim", user, hr, status, requested_title, title );
        if ( FAILED( hr ) ) goto cleanup;
        hr = get_json_string( identity, L"prv", &prv );
        auth_metadata( "privilege-permissions-claim", user, hr, status, requested_title, title );
        if ( FAILED( hr ) ) goto cleanup;
        xid_text = WindowsGetStringRawBuffer( xid, &xid_len );
        prv_text = WindowsGetStringRawBuffer( prv, &prv_len );
        if ( FAILED( hr = privilege_claim( xid_text, xid_len, user->xuid, prv_text, prv_len, privilege, granted ) ) )
            goto cleanup;
        if ( FAILED( hr = user->CachePrivileges( xid_text, xid_len, prv_text, prv_len ) ) ) goto cleanup;
    }
    if ( !( tokenA = hstring_to_utf8( token ) ) || !( uhsA = hstring_to_utf8( uhs ) ) )
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }
    size = strlen( "XBL3.0 x=;" ) + strlen( uhsA ) + strlen( tokenA ) + 1;
    if ( !( *auth = static_cast<std::remove_reference_t<decltype( *auth )>>( calloc( 1, size ) ) ) )
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }
    snprintf( *auth, size, "XBL3.0 x=%s;%s", uhsA, tokenA );

cleanup:
    if ( identity ) ( identity )->Release();
    if ( claims ) ( claims )->Release();
    if ( object ) ( object )->Release();
    if ( xui ) ( xui )->Release();
    if ( token ) WindowsDeleteString( token );
    if ( uhs ) WindowsDeleteString( uhs );
    if ( xid ) WindowsDeleteString( xid );
    if ( prv ) WindowsDeleteString( prv );
    free( tokenA );
    free( uhsA );
    free( buffer );
    free( body );
    if ( SUCCEEDED( comInit ) ) CoUninitialize();
    auth_metadata( "xsts", user, hr, status, requested_title, title );
    return hr;
}

HRESULT XUser::GetPresenceAuthorization( const char *url, char **auth, UINT32 *signatureVersion )
{
    if ( !auth || !signatureVersion ) return E_POINTER;
    *auth = nullptr; *signatureVersion = 0;
    if ( !url || !titleToken || !*titleToken || !xuid || cancelled ) return E_GAMEUSER_NO_AUTH_USER;
    try
    {
        const auto expected = "https://userpresence.xboxlive.com/users/xuid(" + std::to_string( xuid ) + ")/devices/current/titles/current";
        if ( expected != url ) return E_ACCESSDENIED;
        endpoint info{};
        auto hr = GetEndpointInfo( url, &info );
        if ( FAILED( hr ) ) return hr;
        if ( !info.policy || info.policy->version != 1 || info.policy->maxBodyBytes < 18 ||
             !info.relyingParty || !info.tokenType ||
             wcscmp( WindowsGetStringRawBuffer( info.tokenType, nullptr ), L"JWT" ) ) return E_NOTIMPL;
        char *audience = hstring_to_utf8( info.relyingParty );
        if ( !audience ) return E_OUTOFMEMORY;
        hr = xsts_authorize_privilege( this, audience, TRUE, auth, static_cast<XUserPrivilege>( 0 ), nullptr, true );
        free( audience );
        if ( SUCCEEDED( hr ) ) *signatureVersion = info.policy->version;
        return hr;
    }
    catch ( ... ) { return E_OUTOFMEMORY; }
}

HRESULT xuser_device_authorization( XUserHandle user, const char *relyingParty, char **auth )
{
    HRESULT hr;

    EnterCriticalSection( &user->deviceAuthSection );
    if ( user->deviceAuth && user->deviceAuthAudience && !strcmp( user->deviceAuthAudience, relyingParty ) &&
         GetTickCount64() - user->deviceAuthTime < 3600 * 1000 )
        hr = ( *auth = strdup( user->deviceAuth ) ) ? S_OK : E_OUTOFMEMORY;
    else if ( SUCCEEDED( hr = xsts_authorize( user, relyingParty, FALSE, auth ) ) )
    {
        free( user->deviceAuth );
        free( user->deviceAuthAudience );
        user->deviceAuth = strdup( *auth );
        user->deviceAuthAudience = strdup( relyingParty );
        user->deviceAuthTime = GetTickCount64();
    }
    LeaveCriticalSection( &user->deviceAuthSection );
    return hr;
}

static XUserImpl x_user;
IXUserImpl *x_user_impl = static_cast<IXUserImpl6 *>( &x_user );
IXUserDeviceImpl *x_user_device_impl = static_cast<IXUserDeviceImpl2 *>( &x_user );
