/* SPDX-License-Identifier: MIT
 * Synthetic identities and own fresh prefix only, never authentication. */
#include "../../src/System/User/XUser.h"
#include "../../src/Runtime/Xml.h"
#include <libxml/parser.h>
#include <algorithm>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static LONG checks, failures, writes, fail_write;
#define CHECK( n, v )                                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        InterlockedIncrement( &checks );                                                                               \
        if ( !( v ) )                                                                                                  \
        {                                                                                                              \
            if ( InterlockedIncrement( &failures ) <= 20 ) printf( "FAIL %s line=%u\n", n, __LINE__ );                 \
        }                                                                                                              \
    } while ( 0 )
static LSTATUS probe_write( HKEY k, const char *n, DWORD r, DWORD t, const BYTE *v, DWORD s )
{
    if ( InterlockedIncrement( &writes ) == fail_write ) return ERROR_ACCESS_DENIED;
    return RegSetValueExA( k, n, r, t, v, s );
}
#define RegSetValueExA probe_write
#include "../../src/System/User/AccountMetadata.h"
#undef RegSetValueExA
static const char first[] = "0123456789abcdef", second[] = "fedcba9876543210";
static BOOL absent( const char *key, const char *value )
{
    char b[32];
    DWORD size = sizeof( b );
    return RegGetValueA( HKEY_CURRENT_USER, key, value, RRF_RT_REG_SZ, NULL, b, &size ) == ERROR_FILE_NOT_FOUND;
}
static BOOL value_is( const char *key, const char *name, const char *expected )
{
    char b[32];
    DWORD size = sizeof( b );
    return RegGetValueA( HKEY_CURRENT_USER, key, name, RRF_RT_REG_SZ, NULL, b, &size ) == ERROR_SUCCESS &&
           !strcmp( b, expected );
}
static void reset( void )
{
    RegDeleteTreeA( HKEY_CURRENT_USER, account_metadata_marker );
    RegDeleteTreeA( HKEY_CURRENT_USER, account_metadata_xbox );
    RegDeleteTreeA( HKEY_CURRENT_USER, account_metadata_store );
    writes = fail_write = 0;
}
static DWORD WINAPI worker( void *context )
{
    unsigned i;
    ( void )context;
    for ( i = 0; i < 100; i++ )
    {
        CHECK( "same-account concurrent publisher",
               account_metadata_publish( 1234567890123456ULL, first, first ) == S_OK );
        CHECK( "same-account Xuid never removed", value_is( account_metadata_xbox, "Xuid", "1234567890123456" ) );
    }
    return 0;
}
static void child( const char *mode )
{
    WCHAR exe[MAX_PATH], command[MAX_PATH + 64];
    STARTUPINFOW startup = { 0 };
    PROCESS_INFORMATION p = { 0 };
    DWORD code;
    startup.cb = sizeof( startup );
    GetModuleFileNameW( NULL, exe, MAX_PATH );
    swprintf( command, ARRAY_SIZE( command ), L"\"%ls\" --child-%hs", exe, mode );
    CHECK( "child starts", CreateProcessW( NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &p ) );
    if ( !p.hProcess ) return;
    CHECK( "child finishes", WaitForSingleObject( p.hProcess, 15000 ) == WAIT_OBJECT_0 );
    GetExitCodeProcess( p.hProcess, &code );
    CHECK( "child result", code == 0 );
    CloseHandle( p.hProcess );
    CloseHandle( p.hThread );
}

// Exercise the same C++ ticket body with real bounded XML parsing. Only
// this test executable supplies a closed transport and synthetic configuration.
static const char *msaAppId = "synthetic-client";
static BOOL fullTrust;
static HRESULT transport_result;
static BOOL bad_xml;
struct FixtureNode
{
    const xmlChar *name;
    int type;
    FixtureNode *children, *next;
    const char *value;
};
static FixtureNode nodes[5];
static const char *GetMsaAppId()
{
    return msaAppId;
}
static BOOL GetFullTrust()
{
    return fullTrust;
}
static bool legacyFullTrust;
static bool GetLegacyFullTrust()
{
    return legacyFullTrust;
}
static constexpr UINT16 XODUS_MSA_TOKEN_REQUEST = 3;
class TicketTransport final : public UserTransport
{
public:
    HRESULT Backend( UINT16 type, const char *body, UINT16 size, char **response, UINT16 *length ) override
    {
        CHECK( "same ticket transport", type == XODUS_MSA_TOKEN_REQUEST && body && size && strlen( body ) == size );
        nexus::XmlNode request;
        CHECK( "actual ticket request is valid XML",
               SUCCEEDED( nexus::ParseXml( std::string_view( body, size ), request ) ) &&
                   request.name == "MSATokenRequest" );
        for ( const auto &child : request.children )
            CHECK( "ticket request has unchanged fields", !child.name.empty() && !child.text.empty() );
        auto client = request.child( "ClientId" ), trust = request.child( "MSAFullTrust" );
        CHECK( "explicit client or actual platform client, never a guessed title",
               client && client->text == ( GetMsaAppId() ? GetMsaAppId() : "0000000040159362" ) );
        CHECK( "full-trust scope is preserved", trust && trust->text == ( GetFullTrust() ? "true" : "false" ) );
        *response = nullptr;
        *length = 0;
        if ( FAILED( transport_result ) ) return transport_result;
        if ( bad_xml )
        {
            *response = strdup( "<" );
            *length = 1;
            return S_OK;
        }
        auto doc = xmlNewDoc( BAD_CAST "1.0" );
        auto root = xmlNewNode( nullptr, BAD_CAST "MSATokenResponse" );
        xmlDocSetRootElement( doc, root );
        for ( unsigned i = 1; i < 5; ++i )
            if ( nodes[i].value ) xmlNewTextChild( root, nullptr, nodes[i].name, BAD_CAST nodes[i].value );
        xmlChar *xml = nullptr;
        int bytes = 0;
        xmlDocDumpMemory( doc, &xml, &bytes );
        xmlFreeDoc( doc );
        if ( !xml ) return E_OUTOFMEMORY;
        *response = strdup( reinterpret_cast<const char *>( xml ) );
        xmlFree( xml );
        *length = bytes;
        return *response ? S_OK : E_OUTOFMEMORY;
    }
    HRESULT Http( const WCHAR *, const WCHAR *, char *, const WCHAR *, const WCHAR **, BYTE **, SIZE_T * ) override
    {
        return E_ACCESSDENIED;
    }
    HRESULT HttpRaw( const WCHAR *, const WCHAR *, const WCHAR *, const void *, DWORD, DWORD *, BYTE **,
                     SIZE_T * ) override
    {
        return E_ACCESSDENIED;
    }
};
// This standalone ticket/registry fixture does not exercise the optional
// diagnostic file sink owned by XUser.cpp. Supply its typed local boundary.
static void auth_metadata( const char *, XUserHandle, HRESULT, DWORD, BOOL, BOOL ) {}
#include "../../src/System/User/Tickets.h"
static HRESULT get_rps_tickets( BOOL ui, char **user, char **device, char xbox[17], char store[17] )
{
    TicketTransport transport;
    XUser owner( transport );
    auto result = get_rps_tickets( &owner, ui, user, device, xbox, store );
    DeleteCriticalSection( &owner.deviceAuthSection );
    return result;
}
static void ticket_cases( void )
{
    unsigned i;
    char *user = NULL, *device = NULL, a[17], b[17];
    HRESULT hr;
    const char *names[] = { "Token", "DeviceRps", "XboxMsaAccountId", "StoreMsaAccountId" };
    nodes[0].children = nodes + 1;
    for ( i = 1; i < 5; i++ )
    {
        nodes[i].name = ( const xmlChar * )names[i - 1];
        nodes[i].type = XML_ELEMENT_NODE;
        nodes[i].next = i < 4 ? nodes + i + 1 : NULL;
    }
    nodes[1].value = "synthetic-user-ticket";
    nodes[2].value = "synthetic-device-ticket";
    for ( i = 0; i < 5; i++ )
    {
        nodes[3].value = i == 0 ? NULL : i == 1 ? "invalid" : "0123456789ABCDEF";
        nodes[4].value = i == 0 ? NULL : i == 2 ? NULL : i == 4 ? "fedcba9876543210" : "0123456789abcdef";
        hr = get_rps_tickets( TRUE, &user, &device, a, b );
        CHECK( "legacy and optional malformed metadata never fails valid tickets",
               hr == S_OK && user && device && !strcmp( user, "synthetic-user-ticket" ) &&
                   !strcmp( device, "synthetic-device-ticket" ) );
        CHECK( "optional pair all-or-none", i < 3
                                                ? ( !a[0] && !b[0] )
                                                : ( !strcmp( a, "0123456789abcdef" ) &&
                                                    !strcmp( b, i == 4 ? "fedcba9876543210" : "0123456789abcdef" ) ) );
        free( user );
        free( device );
        user = device = NULL;
    }
    nodes[1].value = "";
    CHECK( "incomplete credentials remain refused",
           get_rps_tickets( FALSE, &user, &device, a, b ) == E_UNEXPECTED && !user && !device );
    nodes[1].value = "synthetic-user-ticket";
    transport_result = E_ACCESSDENIED;
    CHECK( "transport auth failure preserved", get_rps_tickets( FALSE, &user, &device, a, b ) == E_ACCESSDENIED );
    transport_result = S_OK;
    bad_xml = TRUE;
    CHECK( "malformed XML auth failure preserved", get_rps_tickets( FALSE, &user, &device, a, b ) == E_UNEXPECTED );
    bad_xml = FALSE;
    msaAppId = NULL;
    fullTrust = TRUE;
    CHECK( "missing full-trust game config still refused",
           get_rps_tickets( FALSE, &user, &device, a, b ) == E_GAME_MISSING_GAME_CONFIG );
    legacyFullTrust = true;
    CHECK( "legacy full-trust requests actual platform account tickets",
           get_rps_tickets( FALSE, &user, &device, a, b ) == S_OK && user && device );
    free( user ); free( device ); user = device = nullptr;
    transport_result = E_ACCESSDENIED;
    CHECK( "legacy full-trust never hides backend denial",
           get_rps_tickets( FALSE, &user, &device, a, b ) == E_ACCESSDENIED && !user && !device );
    transport_result = S_OK;
    legacyFullTrust = false;
    fullTrust = FALSE;
    CHECK( "platform fallback still authenticates", get_rps_tickets( FALSE, &user, &device, a, b ) == S_OK );
    free( user );
    free( device );
}

int main( int argc, char **argv )
{
    InitializeLogging();
    HKEY key;
    DWORD disposition, i;
    char a[17], b[17];
    HANDLE threads[8];
    BOOL empty;
    if ( argc == 2 && strstr( argv[1], "--child-" ) == argv[1] )
    {
        HRESULT hr = account_metadata_publish(
            strstr( argv[1], "different" ) ? 2234567890123456ULL : 1234567890123456ULL, first, first );
        return hr == ( strstr( argv[1], "different" ) ? S_FALSE : S_OK ) ? 0 : 1;
    }
    empty = absent( account_metadata_xbox, "Xuid" ) && absent( account_metadata_store, "PrimaryWebAccountId" );
    CHECK( "fresh disposable prefix", empty );
    if ( !empty ) return 2;
    if ( argc == 2 && !strcmp( argv[1], "--empty-only" ) ) goto finished;
    if ( argc == 2 && !strcmp( argv[1], "--leave-volatile" ) )
    {
        CHECK( "volatile publication", account_metadata_publish( 1234567890123456ULL, first, first ) == S_OK );
        goto finished;
    }
    ticket_cases();
    for ( i = 0; i < 6; i++ )
    {
        const char *bad[] = {
            "", "short", "0000000000000000", "0123456789abcdeg", "0123456789abcdef0", "0123456789abcde\n" };
        CHECK( "malformed identity rejected", account_metadata_publish( 123, bad[i], first ) == S_FALSE );
        CHECK( "invalid metadata never creates identity", absent( account_metadata_xbox, "Xuid" ) );
    }
    CHECK( "pair canonicalization",
           account_metadata_pair( "0123456789ABCDEF", second, a, b ) && !strcmp( a, first ) && !strcmp( b, second ) );
    CHECK( "pair preserves actual mismatch", strcmp( a, b ) != 0 );
    CHECK( "partial pair omitted", !account_metadata_pair( first, NULL, a, b ) && !a[0] && !b[0] );
    CHECK( "zero Xbox identity rejected", account_metadata_publish( 0, first, first ) == S_FALSE );
    CHECK( "publication from supplied identities",
           account_metadata_publish( 1234567890123456ULL, first, first ) == S_OK );
    CHECK( "actual supplied Xbox id", value_is( account_metadata_xbox, "Xuid", "1234567890123456" ) );
    CHECK( "actual supplied MSA id", value_is( account_metadata_xbox, "AccountId", first ) );
    CHECK( "actual supplied Store id", value_is( account_metadata_store, "PrimaryWebAccountId", first ) );
    child( "same" );
    child( "different" );
    CHECK( "live foreign account cannot replace metadata",
           value_is( account_metadata_xbox, "Xuid", "1234567890123456" ) );
    for ( i = 0; i < 8; i++ )
        threads[i] = CreateThread( NULL, 0, worker, NULL, 0, NULL );
    CHECK( "publishers join", WaitForMultipleObjects( 8, threads, TRUE, 30000 ) == WAIT_OBJECT_0 );
    for ( i = 0; i < 8; i++ )
        CloseHandle( threads[i] );
    CHECK( "active account switch refused",
           account_metadata_publish( 2234567890123456ULL, second, second ) == S_FALSE );
    reset();
    child( "same" );
    CHECK( "dead producer replaced for actual next account",
           account_metadata_publish( 2234567890123456ULL, second, second ) == S_OK );
    CHECK( "new account Xuid", value_is( account_metadata_xbox, "Xuid", "2234567890123456" ) );
    CHECK( "new account MSA", value_is( account_metadata_store, "PrimaryWebAccountId", second ) );
    reset();
    CHECK( "actual mismatch still published honestly",
           account_metadata_publish( 1234567890123456ULL, first, second ) == S_OK );
    CHECK( "Store mismatch is not forced equal",
           value_is( account_metadata_xbox, "AccountId", first ) &&
               value_is( account_metadata_store, "PrimaryWebAccountId", second ) );
    CHECK( "open own key",
           RegOpenKeyExA( HKEY_CURRENT_USER, account_metadata_xbox, 0, KEY_WRITE, &key ) == ERROR_SUCCESS );
    CHECK( "synthetic manual change",
           RegSetValueExA( key, "AccountId", 0, REG_SZ, ( BYTE * )"manual", 7 ) == ERROR_SUCCESS );
    RegCloseKey( key );
    CHECK( "manual change not overwritten", account_metadata_publish( 1234567890123456ULL, first, second ) == S_FALSE &&
                                                value_is( account_metadata_xbox, "AccountId", "manual" ) );
    reset();
    CHECK( "foreign key fixture", RegCreateKeyExA( HKEY_CURRENT_USER, account_metadata_xbox, 0, NULL, 0, KEY_WRITE,
                                                   NULL, &key, &disposition ) == ERROR_SUCCESS );
    CHECK( "foreign value fixture", RegSetValueExA( key, "Xuid", 0, REG_SZ, ( BYTE * )"foreign", 8 ) == ERROR_SUCCESS );
    RegCloseKey( key );
    CHECK( "unmanaged keys preserved", account_metadata_publish( 1234567890123456ULL, first, first ) == S_FALSE &&
                                           value_is( account_metadata_xbox, "Xuid", "foreign" ) );
    for ( i = 1; i <= 7; i++ )
    {
        reset();
        fail_write = i;
        CHECK( "fault does not publish incomplete Xuid",
               account_metadata_publish( 1234567890123456ULL, first, first ) == S_FALSE &&
                   absent( account_metadata_xbox, "Xuid" ) );
    }
    reset();
    SetLastError( 0x12345678 );
    CHECK( "publish succeeds", account_metadata_publish( 1234567890123456ULL, first, first ) == S_OK );
    CHECK( "LastError preserved", GetLastError() == 0x12345678 );
    reset();
finished:
    printf( "CHECKS %ld FAILURES %ld\n", checks, failures );
    return failures ? 1 : 0;
}
