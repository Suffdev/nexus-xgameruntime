/* SPDX-License-Identifier: MIT
 * Account-free fixtures and real IXPackage ABI. No account, license or save API.
 * Disk installation records never establish ownership. */
#define INITGUID
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../src/System/XPackage.cpp"
#include <xstore.h>

static unsigned checks, failures, visits, expected;
static BOOL stop_early, recurse;
static WCHAR folder[MAX_PATH];
static const char *main_config = "<Game><Identity Name=\"Nexus.Base\" Publisher=\"CN=Probe\"/>"
                                 "<StoreId>B00000000001</StoreId><RelatedProducts><RelatedProduct>B00000000002</"
                                 "RelatedProduct></RelatedProducts></Game>";
#define CHECK( name, test )                                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        ++checks;                                                                                                      \
        if ( !( test ) )                                                                                               \
        {                                                                                                              \
            ++failures;                                                                                                \
            printf( "FAIL %s line=%d\n", name, __LINE__ );                                                             \
        }                                                                                                              \
    } while ( 0 )

static void write_text( const WCHAR *path, const char *text )
{
    HANDLE file = CreateFileW( path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL );
    DWORD written;
    CHECK( "fixture-open", file != INVALID_HANDLE_VALUE );
    if ( file == INVALID_HANDLE_VALUE ) return;
    CHECK( "fixture-write", WriteFile( file, text, strlen( text ), &written, NULL ) && written == strlen( text ) );
    CloseHandle( file );
}

static void configure( const char *text )
{
    INITIALIZE_OPTIONS options{};
    options.isInlineConfig = TRUE;
    options.gameConfig = text;
    CHECK( "config-xml", nexus::InitializeGameConfiguration( &options ) == S_OK );
}

static void fixture( const WCHAR *name, const char *identity, const char *id, const char *parent, const char *parent_id,
                     UINT guid, BOOL game )
{
    WCHAR root[MAX_PATH], file[MAX_PATH], layout[80];
    char config[4096], manifest[4096], dependency[512] = "", allowed[256] = "";
    content_join( folder, name, root );
    CreateDirectoryW( root, NULL );
    if ( !game )
    {
        snprintf( dependency, sizeof( dependency ), "<MainPackageDependency Name=\"%s\"/>", parent );
        snprintf( allowed, sizeof( allowed ), "<AllowedProducts><AllowedProduct>%s</AllowedProduct></AllowedProducts>",
                  parent_id );
    }
    snprintf( config, sizeof( config ),
              "<Game><Identity Name=\"%s\" Publisher=\"CN=Probe\" Version=\"1.2.3.4\"/>"
              "<StoreId>%s</StoreId><ShellVisuals DefaultDisplayName=\"Campaign &amp; More\" "
              "Description=\"Description\" PublisherDisplayName=\"Publisher\"/>"
              "%s<DesktopRegistration>%s</DesktopRegistration>%s</Game>",
              identity, id, allowed, dependency, game ? "<Executables/>" : "" );
    snprintf( manifest, sizeof( manifest ),
              "<Package xmlns:uap4=\"urn:probe\"><Identity Name=\"%s\" Publisher=\"CN=Probe\" Version=\"1.2.3.4\"/>"
              "<Dependencies>%s</Dependencies>%s</Package>",
              identity, dependency, game ? "<Applications/>" : "" );
    content_join( root, L"MicrosoftGame.Config", file );
    write_text( file, config );
    content_join( root, L"appxmanifest.xml", file );
    write_text( file, manifest );
    swprintf( layout, 80, L"layout_%08x-1111-2222-3333-444444444444.xml", guid );
    content_join( root, layout, file );
    write_text( file,
                "<Package><Chunk Id=\"Registration\"><FileGroup SourcePath=\".\" Include=\"MicrosoftGame.Config\"/>"
                "<FileGroup SourcePath=\".\" Include=\"*.png\"/></Chunk></Package>" );
    content_join( root, L"logo.png", file );
    write_text( file, "synthetic payload, not a game" );
}

static BOOLEAN WINAPI visit( void *context, const XPackageDetails *details )
{
    ( void )context;
    CHECK( "record-kind", details->kind == XPackageKind::Content );
    CHECK( "record-installed", !details->installing );
    CHECK( "record-index", details->index == visits );
    CHECK( "record-count", details->count == expected );
    CHECK( "record-store", content_id( details->storeId ) );
    CHECK( "record-identifier", strlen( details->packageIdentifier ) == 32 );
    CHECK( "record-version", details->version.major == 1 && details->version.minor == 2 &&
                                 details->version.build == 3 && details->version.revision == 4 );
    CHECK( "record-xml-entities", !strcmp( details->displayName, "Campaign & More" ) );
    visits++;
    if ( recurse )
    {
        unsigned saved = visits;
        BOOL saved_stop = stop_early;
        recurse = FALSE;
        visits = 0;
        stop_early = TRUE;
        CHECK( "reentrant-enumerate",
               enumerate_content_packages( XPackageEnumerationScope::ThisOnly, NULL, visit ) == S_OK && visits == 1 );
        visits = saved;
        stop_early = saved_stop;
    }
    return !stop_early;
}

static void enumerate( XPackageEnumerationScope scope, unsigned count, BOOL stop )
{
    expected = count;
    visits = 0;
    stop_early = stop;
    CHECK( "enumerate-success", enumerate_content_packages( scope, NULL, visit ) == S_OK );
    CHECK( "enumerate-count", visits == ( stop && count ? 1 : count ) );
}

static void helpers( void )
{
    XVersion version;
    char identifier[33];
    WCHAR path[MAX_PATH], file[MAX_PATH];
    struct content_package *package =
        static_cast<std::remove_reference_t<decltype( package )>>( calloc( 1, sizeof( *package ) ) );
    CHECK( "store-id-valid", content_id( "B00000000001" ) );
    CHECK( "store-id-invalid", !content_id( "b00000000001" ) && !content_id( "invalid" ) );
    CHECK( "version-valid", content_version( "65535.2.3.4", &version ) && version.major == 65535 );
    CHECK( "version-overflow", !content_version( "65536.0.0.0", &version ) );
    CHECK( "version-trailing", !content_version( "1.2.3.4x", &version ) );
    CHECK( "version-short", !content_version( "1.2.3", &version ) );
    CHECK( "layout-guid", content_layout_id( L"layout_12345678-1234-5678-9abc-123456789abc.xml", identifier ) &&
                              strlen( identifier ) == 32 );
    CHECK( "layout-guid-invalid", !content_layout_id( L"layout_bad.xml", identifier ) );
    CHECK( "source-traversal", !content_relative( "../escape", FALSE ) && !content_relative( "a/../escape", TRUE ) );
    CHECK( "source-absolute", !content_relative( "C:\\escape", FALSE ) && !content_relative( "/escape", FALSE ) );
    CHECK( "source-relative", content_relative( ".", FALSE ) && content_relative( "*.png", TRUE ) );
    fixture( L"own-one", "Nexus.Dlc.One", "D00000000001", "Nexus.Base", "B00000000001", 1, FALSE );
    fixture( L"own-two", "Nexus.Dlc.Two", "D00000000002", "Nexus.Base", "B00000000001", 2, FALSE );
    fixture( L"related-base", "Nexus.Related", "B00000000002", NULL, NULL, 3, TRUE );
    fixture( L"related-dlc", "Nexus.Related.Dlc", "D00000000003", "Nexus.Related", "B00000000002", 4, FALSE );
    fixture( L"other-base", "Nexus.Other", "B00000000003", NULL, NULL, 5, TRUE );
    fixture( L"other-dlc", "Nexus.Other.Dlc", "D00000000004", "Nexus.Other", "B00000000003", 6, FALSE );
    fixture( L"orphan", "Nexus.Orphan", "D00000000005", "Nexus.Missing", "B00000000004", 7, FALSE );
    configure( main_config );
    SetEnvironmentVariableW( L"XODUS_CONTENT_ROOTS", folder );
    enumerate( XPackageEnumerationScope::ThisOnly, 2, FALSE );
    enumerate( XPackageEnumerationScope::ThisAndRelated, 3, FALSE );
    enumerate( XPackageEnumerationScope::ThisPublisher, 4, FALSE );
    enumerate( XPackageEnumerationScope::ThisOnly, 2, TRUE );
    CHECK( "lookup-installed", content_query_identifier( "D00000000001", sizeof( identifier ), identifier ) == S_OK &&
                                   !strcmp( identifier, "00000001111122223333444444444444" ) );
    CHECK( "lookup-related", content_query_identifier( "D00000000003", sizeof( identifier ), identifier ) == S_OK &&
                                 !strcmp( identifier, "00000004111122223333444444444444" ) );
    CHECK( "lookup-unknown",
           content_query_identifier( "D00000000099", sizeof( identifier ), identifier ) == E_INVALIDARG &&
               !identifier[0] );
    CHECK( "lookup-unrelated",
           content_query_identifier( "D00000000004", sizeof( identifier ), identifier ) == E_INVALIDARG &&
               !identifier[0] );
    CHECK( "lookup-null-store", content_query_identifier( NULL, sizeof( identifier ), identifier ) == E_INVALIDARG );
    CHECK( "lookup-null-output",
           content_query_identifier( "D00000000001", sizeof( identifier ), NULL ) == E_INVALIDARG );
    CHECK( "lookup-short", content_query_identifier( "D00000000001", sizeof( identifier ) - 1, identifier ) ==
                                   E_NOT_SUFFICIENT_BUFFER &&
                               !identifier[0] );
    CHECK( "reverse-installed", xpackage_query_content_store( "00000001111122223333444444444444", sizeof( identifier ),
                                                              identifier ) == S_OK &&
                                    !strcmp( identifier, "D00000000001" ) );
    CHECK( "reverse-missing", xpackage_query_content_store( "00000099111122223333444444444444", sizeof( identifier ),
                                                            identifier ) == E_GAMEPACKAGE_NO_PACKAGE_IDENTIFIER &&
                                  !identifier[0] );
    CHECK( "reverse-invalid", xpackage_query_content_store( "bad", sizeof( identifier ), identifier ) == E_INVALIDARG );
    CHECK( "reverse-short", xpackage_query_content_store( "00000001111122223333444444444444", 12, identifier ) ==
                                E_NOT_SUFFICIENT_BUFFER );
    fixture( L"ambiguous", "Nexus.Dlc.Duplicate", "D00000000001", "Nexus.Base", "B00000000001", 8, FALSE );
    CHECK( "lookup-ambiguous",
           content_query_identifier( "D00000000001", sizeof( identifier ), identifier ) == E_INVALIDARG &&
               !identifier[0] );
    content_join( folder, L"ambiguous", path );
    content_join( path, L"MicrosoftGame.Config", file );
    DeleteFileW( file );
    recurse = TRUE;
    enumerate( XPackageEnumerationScope::ThisOnly, 2, TRUE );
    content_join( folder, L"own-one", path );
    CHECK( "valid-real-shape", content_load( path, package ) && package->content );
    content_join( path, L"logo.png", file );
    DeleteFileW( file );
    CHECK( "missing-payload-rejected", !content_load( path, package ) );
    write_text( file, "payload" );
    content_join( path, L"appxmanifest.xml", file );
    write_text( file, "<Package><Identity Name=\"Wrong\"/></Package>" );
    CHECK( "identity-mismatch-rejected", !content_load( path, package ) );
    fixture( L"own-one", "Nexus.Dlc.One", "D00000000001", "Nexus.Base", "B00000000001", 1, FALSE );
    content_join( path, L"MicrosoftGame.Config", file );
    write_text( file, "<!DOCTYPE Game [<!ENTITY fake 'bad'>]><Game>&fake;</Game>" );
    CHECK( "dtd-rejected", !content_load( path, package ) );
    fixture( L"own-one", "Nexus.Dlc.One", "D00000000001", "Nexus.Base", "B00000000001", 1, FALSE );
    /* Same physical package reachable through two roots must enumerate once. */
    {
        WCHAR roots[MAX_PATH * 2 + 2];
        swprintf( roots, ARRAY_SIZE( roots ), L"%ls;%ls", folder, path );
        SetEnvironmentVariableW( L"XODUS_CONTENT_ROOTS", roots );
        enumerate( XPackageEnumerationScope::ThisOnly, 2, FALSE );
    }
    SetEnvironmentVariableW( L"XODUS_CONTENT_ROOTS", L"relative/path" );
    CHECK( "relative-root-rejected",
           enumerate_content_packages( XPackageEnumerationScope::ThisOnly, NULL, visit ) == E_INVALIDARG );
    SetEnvironmentVariableW( L"XODUS_CONTENT_ROOTS", folder );
    free( package );
}

static void chunk_order( IXPackageImpl *package, const char *id, HRESULT installed )
{
    XPackageChunkSelector selectors[4]{}, before[4], bad{};
    selectors[0].type = XPackageChunkSelectorType::Chunk;
    selectors[0].chunkId = 123;
    selectors[1].type = XPackageChunkSelectorType::Language;
    selectors[1].language = "en-US;fr-FR";
    selectors[2].type = XPackageChunkSelectorType::Tag;
    selectors[2].tag = "Campaign";
    selectors[3].type = XPackageChunkSelectorType::Feature;
    selectors[3].feature = "Campaign";
    memcpy( before, selectors, sizeof( before ) );
    CHECK( "chunks-installed-selection",
           ( package )->XPackageChangeChunkInstallOrder( id, 4, selectors ) == installed );
    CHECK( "chunks-zero-selectors", ( package )->XPackageChangeChunkInstallOrder( id, 0, NULL ) == installed );
    CHECK( "chunks-no-input-mutation", !memcmp( before, selectors, sizeof( before ) ) );
    CHECK( "chunks-null-array", ( package )->XPackageChangeChunkInstallOrder( id, 1, NULL ) == E_INVALIDARG );
    CHECK( "chunks-null-id", ( package )->XPackageChangeChunkInstallOrder( NULL, 4, selectors ) == E_INVALIDARG );
    CHECK( "chunks-empty-id", ( package )->XPackageChangeChunkInstallOrder( "", 3, selectors ) == E_INVALIDARG );
    CHECK( "chunks-malformed-id",
           ( package )->XPackageChangeChunkInstallOrder( "not-a-package", 4, selectors ) == E_INVALIDARG );
    CHECK( "chunks-nonhex-id", ( package )->XPackageChangeChunkInstallOrder( "z0000001111122223333444444444444", 4,
                                                                             selectors ) == E_INVALIDARG );
    CHECK( "chunks-unknown-id",
           ( package )->XPackageChangeChunkInstallOrder( "00000099111122223333444444444444", 4, selectors ) ==
               E_GAMEPACKAGE_NO_PACKAGE_IDENTIFIER );
    CHECK( "chunks-unrelated-id",
           ( package )->XPackageChangeChunkInstallOrder( "00000006111122223333444444444444", 4, selectors ) ==
               E_GAMEPACKAGE_NO_PACKAGE_IDENTIFIER );
    bad.type = ( XPackageChunkSelectorType )99;
    CHECK( "chunks-invalid-kind", ( package )->XPackageChangeChunkInstallOrder( id, 1, &bad ) == E_INVALIDARG );
    bad.type = XPackageChunkSelectorType::Tag;
    CHECK( "chunks-null-tag", ( package )->XPackageChangeChunkInstallOrder( id, 1, &bad ) == E_INVALIDARG );
    bad.tag = "";
    CHECK( "chunks-empty-tag", ( package )->XPackageChangeChunkInstallOrder( id, 1, &bad ) == E_INVALIDARG );
    bad.type = XPackageChunkSelectorType::Feature;
    bad.feature = NULL;
    CHECK( "chunks-null-feature", ( package )->XPackageChangeChunkInstallOrder( id, 1, &bad ) == E_INVALIDARG );
    bad.type = XPackageChunkSelectorType::Language;
    CHECK( "chunks-null-language", ( package )->XPackageChangeChunkInstallOrder( id, 1, &bad ) == E_INVALIDARG );
}

static void current_child( const WCHAR *executable, BOOL missing, BOOL knownGame = TRUE )
{
    STARTUPINFOW startup = { 0 };
    PROCESS_INFORMATION process = { 0 };
    WCHAR command[MAX_PATH + 64];
    DWORD code = 99, wait;
    startup.cb = sizeof( startup );
    swprintf( command, ARRAY_SIZE( command ), L"\"%ls\" --chunks-%ls %ls", executable,
              missing ? L"missing" : L"current", knownGame ? L"--kind-game" : L"--kind-unknown" );
    CHECK( "chunks-child-start",
           CreateProcessW( executable, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process ) );
    if ( !process.hProcess ) return;
    wait = WaitForSingleObject( process.hProcess, 15000 );
    CHECK( "chunks-child-finished", wait == WAIT_OBJECT_0 );
    if ( wait != WAIT_OBJECT_0 ) TerminateProcess( process.hProcess, 77 );
    GetExitCodeProcess( process.hProcess, &code );
    CHECK( "chunks-child-pass", code == 0 );
    CloseHandle( process.hProcess );
    CloseHandle( process.hThread );
}

static void current_fixtures( void )
{
    WCHAR root[MAX_PATH], nested[MAX_PATH], executable[MAX_PATH], original[MAX_PATH], file[MAX_PATH];
    fixture( L"current-base", "Nexus.Base", "B00000000001", NULL, NULL, 9, TRUE );
    content_join( folder, L"current-base", root );
    content_join( root, L"Binaries", nested );
    CreateDirectoryW( nested, NULL );
    content_join( nested, L"chunks.exe", executable );
    CHECK( "chunks-self-path", GetModuleFileNameW( NULL, original, MAX_PATH ) );
    CHECK( "chunks-self-copy", CopyFileW( original, executable, TRUE ) );
    current_child( executable, FALSE );
    content_join( root, L"logo.png", file );
    DeleteFileW( file );
    current_child( executable, TRUE );
    write_text( file, "payload" );
    content_join( root, L"layout_00000009-1111-2222-3333-444444444444.xml", file );
    write_text( file, "<invalid/>" );
    current_child( executable, TRUE );
    fixture( L"current-base", "Nexus.Base", "B00000000001", NULL, NULL, 9, TRUE );
    content_join( root, L"appxmanifest.xml", file );
    write_text( file, "<Package><Identity Name=\"Wrong\"/></Package>" );
    current_child( executable, TRUE, FALSE );
}

static void actual_runtime( const char *child, BOOL knownGame = TRUE )
{
    struct options
    {
        UINT32 tag;
        BOOL is_inline;
        const char *config;
    } options = { 1, TRUE, main_config };
    HMODULE module = LoadLibraryW( L"xgameruntime.dll" );
    HRESULT( WINAPI * initialize )( ULONG, ULONG, char, const void * );
    HRESULT( WINAPI * query )( REFCLSID, REFIID, void ** );
    IXPackageImpl *package = NULL;
    IXStoreImpl *store = NULL;
    char identifier[35];
    CHECK( "runtime-load", module != NULL );
    if ( !module ) return;
    initialize = reinterpret_cast<decltype( initialize )>( GetProcAddress( module, "InitializeApiImplEx2" ) );
    query = reinterpret_cast<decltype( query )>( GetProcAddress( module, "QueryApiImpl" ) );
    CHECK( "runtime-exports", initialize && query );
    if ( !initialize || !query ) return;
    CHECK( "runtime-initialize", initialize( 0, 0, 0, &options ) == S_OK );
    CHECK( "runtime-query", query( CLSID_XPackageImpl, IID_IXPackageImpl, ( void ** )&package ) == S_OK && package );
    if ( !package ) return;
    if ( child )
    {
        IXPackageImpl4 *latest = nullptr;
        CHECK( "runtime-current-kind-interface",
               package->QueryInterface( __uuidof( IXPackageImpl4 ), reinterpret_cast<void **>( &latest ) ) == S_OK &&
                   latest );
        if ( latest )
        {
            XPackageKind kind = XPackageKind::PublisherContent;
            // Package type is independent of chunk completeness. A real base
            // manifest remains Game when payload is missing; a foreign manifest
            // must not be classified as the current game.
            const auto kindResult = latest->XPackageGetKind( "00000009111122223333444444444444", &kind );
            printf( "KIND result=%08lx knownGame=%u kind=%u\n", kindResult, knownGame, static_cast<UINT32>( kind ) );
            CHECK( "runtime-current-kind-actual",
                   kindResult == ( knownGame ? S_OK : E_GAMEPACKAGE_NO_PACKAGE_IDENTIFIER ) &&
                       ( !knownGame || kind == XPackageKind::Game ) );
            latest->Release();
        }

        chunk_order( package, "00000009111122223333444444444444",
                     !strcmp( child, "--chunks-current" ) ? S_OK : E_GAMEPACKAGE_NO_PACKAGE_IDENTIFIER );
        ( package )->Release();
        return;
    }
    chunk_order( package, "00000001111122223333444444444444", S_OK );
    {
        WCHAR root[MAX_PATH], file[MAX_PATH];
        XPackageChunkSelector selector{};
        selector.type = XPackageChunkSelectorType::Chunk;
        CHECK( "chunks-related-installed", ( package )->XPackageChangeChunkInstallOrder(
                                               "00000004111122223333444444444444", 1, &selector ) == S_OK );
        selector.chunkId = 0xffffffff;
        CHECK( "chunks-unscheduled-ignored", ( package )->XPackageChangeChunkInstallOrder(
                                                 "00000001111122223333444444444444", 1, &selector ) == S_OK );
        content_join( folder, L"own-one", root );
        content_join( root, L"logo.png", file );
        DeleteFileW( file );
        CHECK( "chunks-content-missing-file",
               ( package )->XPackageChangeChunkInstallOrder( "00000001111122223333444444444444", 1, &selector ) ==
                   E_GAMEPACKAGE_NO_PACKAGE_IDENTIFIER );
        write_text( file, "payload" );
    }
    IXPackageImpl4 *latest = nullptr;
    CHECK( "runtime-content-kind-interface",
           package->QueryInterface( __uuidof( IXPackageImpl4 ), reinterpret_cast<void **>( &latest ) ) == S_OK &&
               latest );
    if ( latest )
    {
        XPackageKind kind = XPackageKind::Game;
        CHECK( "runtime-content-kind-actual",
               latest->XPackageGetKind( "00000001111122223333444444444444", &kind ) == S_OK &&
                   kind == XPackageKind::Content );
        latest->Release();
    }
    WCHAR mount_root[MAX_PATH], mount_layout[MAX_PATH];
    content_join( folder, L"own-one", mount_root );
    content_join( mount_root, L"layout_00000001-1111-2222-3333-444444444444.xml", mount_layout );
    write_text( mount_layout, "<Package><Chunk><FileGroup SourcePath=\".\" Include=\"MicrosoftGame.Config\" DestinationPath=\"\\\"/>"
        "<FileGroup SourcePath=\".\" Include=\"*.png\" DestinationPath=\"\\\"/></Chunk></Package>" );
    content_package mount_content{};
    package_mount_plan mount_mapping;
    CHECK( "runtime-mount-source-projection-valid", content_load( mount_root, &mount_content ) &&
        package_mount_read_plan( mount_content, mount_mapping ) == S_OK && mount_mapping.files.size() == 2 );
    // A deliberately invalid bridge configuration fails before socket creation.
    // This exercises the production mount/license path without an account or a
    // service, and must never be treated as proof of an owned DLC.
    char absent_transport[65];
    CHECK( "runtime-mount-no-inherited-transport", !GetEnvironmentVariableA( "XODUS_BRIDGE_PORT", absent_transport, sizeof( absent_transport ) ) &&
        !GetEnvironmentVariableA( "XODUS_BRIDGE_KEY", absent_transport, sizeof( absent_transport ) ) );
    CHECK( "runtime-mount-closed-transport", SetEnvironmentVariableA( "XODUS_BRIDGE_PORT", "0" ) &&
        SetEnvironmentVariableA( "XODUS_BRIDGE_KEY", "0000000000000000000000000000000000000000000000000000000000000000" ) );
    XPackageMountHandle no_license = ( XPackageMountHandle )1;
    HRESULT mount_error = package->XPackageMountLegacy( "00000001111122223333444444444444", &no_license );
    printf( "MOUNT_NO_LICENSE hr=%08lx\n", mount_error );
    CHECK( "runtime-mount-no-license-no-handle", mount_error == E_INVALIDARG && !no_license );
    CHECK( "runtime-mount-restores-transport", SetEnvironmentVariableA( "XODUS_BRIDGE_PORT", NULL ) &&
        SetEnvironmentVariableA( "XODUS_BRIDGE_KEY", NULL ) );
    SIZE_T invalid_size = 123;
    CHECK( "runtime-mount-foreign-size", package->XPackageGetMountPathSize( ( XPackageMountHandle )1, &invalid_size ) == E_INVALIDARG && !invalid_size );
    char invalid_path[8] = "keep";
    CHECK( "runtime-mount-foreign-path", package->XPackageGetMountPath( ( XPackageMountHandle )1, sizeof( invalid_path ), invalid_path ) == E_INVALIDARG && !invalid_path[0] );
    package->XPackageCloseMountHandle( ( XPackageMountHandle )1 );
    expected = 2;
    visits = 0;
    stop_early = FALSE;
    CHECK( "runtime-enumerate", ( package )->XPackageEnumeratePackages(
                                    XPackageKind::Content, XPackageEnumerationScope::ThisOnly, NULL, visit ) == S_OK );
    CHECK( "runtime-content-count", visits == 2 );
    CHECK( "runtime-null-callback",
           ( package )->XPackageEnumeratePackages( XPackageKind::Content, XPackageEnumerationScope::ThisOnly, NULL,
                                                   NULL ) == E_INVALIDARG );
    CHECK( "runtime-invalid-kind",
           ( package )->XPackageEnumeratePackages( ( XPackageKind )99, XPackageEnumerationScope::ThisOnly, NULL,
                                                   visit ) == E_INVALIDARG );
    CHECK( "runtime-invalid-scope",
           ( package )->XPackageEnumeratePackages( XPackageKind::Content, ( XPackageEnumerationScope )99, NULL,
                                                   visit ) == E_INVALIDARG );
    ( package )->Release();
    CHECK( "runtime-store-query", query( CLSID_XStoreImpl, IID_IXStoreImpl, ( void ** )&store ) == S_OK && store );
    if ( store )
    {
        memset( identifier, '!', sizeof( identifier ) );
        CHECK( "runtime-store-package-id",
               ( store )->XStoreQueryPackageIdentifier( "D00000000001", 33, identifier + 1 ) == S_OK );
        CHECK( "runtime-store-package-value", !strcmp( identifier + 1, "00000001111122223333444444444444" ) );
        CHECK( "runtime-store-buffer-guards", identifier[0] == '!' && identifier[34] == '!' );
        CHECK( "runtime-store-package-unknown",
               ( store )->XStoreQueryPackageIdentifier( "D00000000099", 33, identifier + 1 ) == E_INVALIDARG &&
                   !identifier[1] );
        CHECK( "runtime-store-package-short", ( store )->XStoreQueryPackageIdentifier(
                                                  "D00000000001", 32, identifier + 1 ) == E_NOT_SUFFICIENT_BUFFER );
        CHECK( "runtime-store-package-null",
               ( store )->XStoreQueryPackageIdentifier( NULL, 33, identifier + 1 ) == E_INVALIDARG );
        CHECK( "runtime-store-current-not-installed",
               ( store )->XStoreQueryPackageIdentifier( "B00000000001", 33, identifier + 1 ) == E_INVALIDARG );
        ( store )->Release();
    }
}

struct mount_fixture_license
{
    BOOL active = TRUE;
    unsigned closes = 0;
};
static BOOL mount_fixture_valid( void *context ) { return ( ( mount_fixture_license * )context )->active; }
static void mount_fixture_close( void *context ) { ++( ( mount_fixture_license * )context )->closes; }
static package_mount_right mount_fixture_right( mount_fixture_license &license )
{
    return { &license, mount_fixture_valid, mount_fixture_close };
}
static BOOL mount_fixture_bytes( const std::wstring &path, const char *expected )
{
    HANDLE file = CreateFileW( path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL );
    if ( file == INVALID_HANDLE_VALUE ) return FALSE;
    char bytes[128]{}; DWORD size = 0;
    BOOL ok = ReadFile( file, bytes, sizeof( bytes ) - 1, &size, NULL ) && size == strlen( expected ) &&
        !memcmp( bytes, expected, size );
    CloseHandle( file ); return ok;
}
static void test_mount_projection()
{
    configure( main_config );
    fixture( L"mount-content", "Nexus.Mount", "D00000000009", "Nexus.Base", "B00000000001", 0x30, FALSE );
    WCHAR root[MAX_PATH], source[MAX_PATH], path[MAX_PATH], layout[MAX_PATH];
    content_join( folder, L"mount-content", root );
    content_join( root, L"SRC", source );
    CHECK( "mount-source-directory", CreateDirectoryW( source, NULL ) );
    content_join( source, L"alpha.dat", path ); write_text( path, "alpha content" );
    content_join( source, L"beta.dat", path ); write_text( path, "beta content" );
    content_join( root, L"Extras", source );
    CHECK( "mount-extra-directory", CreateDirectoryW( source, NULL ) );
    content_join( source, L"gamma.dat", path ); write_text( path, "gamma content" );
    content_join( root, L"layout_00000030-1111-2222-3333-444444444444.xml", layout );
    const char *mapping = "<Package><Chunk Id=\"1000\"><FileGroup SourcePath=\"SRC\" Include=\"*.dat\" DestinationPath=\"\\Data\"/>"
        "<FileGroup SourcePath=\"Extras\" Include=\"gamma.dat\" DestinationPath=\"\\Data\"/></Chunk></Package>";
    write_text( layout, mapping );
    content_package package{};
    CHECK( "mount-valid-content", content_load( root, &package ) && package.content );
    package_mount_plan plan;
    CHECK( "mount-plan-projects-groups", package_mount_read_plan( package, plan ) == S_OK &&
        plan.groups == 2 && plan.files.size() == 3 );
    CHECK( "mount-plan-preserves-source-names", plan.destinations.count( L"Data\\alpha.dat" ) &&
        plan.destinations.count( L"Data\\beta.dat" ) && plan.destinations.count( L"Data\\gamma.dat" ) );
    mount_fixture_license unmanaged;
    XPackageMountHandle unmanaged_mount = ( XPackageMountHandle )1;
    CHECK( "mount-unmanaged-copy-refused", package_mount_create( package, mount_fixture_right( unmanaged ),
        &unmanaged_mount ) == E_NOTIMPL && !unmanaged_mount && unmanaged.closes == 1 );
    WCHAR workspace[MAX_PATH];
    content_join( folder, L"mount-workspace", workspace );
    CHECK( "mount-managed-workspace-created", CreateDirectoryW( workspace, NULL ) );
    CHECK( "mount-managed-workspace-published", SetEnvironmentVariableW( L"XODUS_MOUNT_ROOT", workspace ) );
    mount_fixture_license first, second;
    XPackageMountHandle mount = NULL, other = NULL;
    CHECK( "mount-create-private-view", package_mount_create( package, mount_fixture_right( first ), &mount ) == S_OK && mount );
    CHECK( "mount-second-independent-view", package_mount_create( package, mount_fixture_right( second ), &other ) == S_OK && other && mount != other );
    if ( mount && other )
    {
        IXPackageImpl *api = GetPackageInterface();
        SIZE_T size = 0;
        CHECK( "mount-size-includes-terminator", api->XPackageGetMountPathSize( mount, &size ) == S_OK && size > 1 && size < MAX_PATH * 4 );
        std::vector<char> buffer( size + 2, '!' );
        CHECK( "mount-small-buffer-refused", api->XPackageGetMountPath( mount, size - 1, buffer.data() + 1 ) == E_NOT_SUFFICIENT_BUFFER &&
            buffer[0] == '!' && !buffer[1] && buffer[size] == '!' );
        CHECK( "mount-path-buffer-guards", api->XPackageGetMountPath( mount, size, buffer.data() + 1 ) == S_OK &&
            buffer[0] == '!' && !buffer[size] && buffer[size+1] == '!' );
        WCHAR wide[MAX_PATH];
        CHECK( "mount-path-utf8", MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, buffer.data() + 1, -1, wide, MAX_PATH ) > 0 );
        std::wstring view = wide;
        CHECK( "mount-view-under-managed-root", view.rfind( std::wstring( workspace ) + L"\\", 0 ) == 0 );
        CHECK( "mount-view-not-original-root", CompareStringOrdinal( root, -1, view.c_str(), -1, TRUE ) != CSTR_EQUAL );
        CHECK( "mount-alpha-mapped", mount_fixture_bytes( view + L"\\Data\\alpha.dat", "alpha content" ) );
        CHECK( "mount-beta-mapped", mount_fixture_bytes( view + L"\\Data\\beta.dat", "beta content" ) );
        CHECK( "mount-groups-merged", mount_fixture_bytes( view + L"\\Data\\gamma.dat", "gamma content" ) );
        CHECK( "mount-physical-source-hidden", GetFileAttributesW( ( view + L"\\SRC" ).c_str() ) == INVALID_FILE_ATTRIBUTES );
        CHECK( "mount-unmapped-metadata-hidden", GetFileAttributesW( ( view + L"\\MicrosoftGame.Config" ).c_str() ) == INVALID_FILE_ATTRIBUTES );
        CHECK( "mount-assets-readonly", GetFileAttributesW( ( view + L"\\Data\\alpha.dat" ).c_str() ) & FILE_ATTRIBUTE_READONLY );
        HANDLE write = CreateFileW( ( view + L"\\Data\\alpha.dat" ).c_str(), GENERIC_WRITE, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, 0, NULL );
        CHECK( "mount-write-denied", write == INVALID_HANDLE_VALUE );
        if ( write != INVALID_HANDLE_VALUE ) CloseHandle( write );
        char other_path[MAX_PATH * 4];
        CHECK( "mount-independent-path", package_mount_path( other, sizeof( other_path ), other_path ) == S_OK &&
            strcmp( other_path, buffer.data() + 1 ) );
        HANDLE original_file = CreateFileW( ( std::wstring( root ) + L"\\SRC\\alpha.dat" ).c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL );
        HANDLE projected_file = CreateFileW( ( view + L"\\Data\\alpha.dat" ).c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL );
        BY_HANDLE_FILE_INFORMATION original_info{}, projected_info{};
        BOOL inspected = original_file != INVALID_HANDLE_VALUE && projected_file != INVALID_HANDLE_VALUE &&
            GetFileInformationByHandle( original_file, &original_info ) && GetFileInformationByHandle( projected_file, &projected_info );
        CHECK( "mount-projection-not-a-hardlink", inspected && ( original_info.dwVolumeSerialNumber != projected_info.dwVolumeSerialNumber ||
            original_info.nFileIndexHigh != projected_info.nFileIndexHigh || original_info.nFileIndexLow != projected_info.nFileIndexLow ) );
        if ( original_file != INVALID_HANDLE_VALUE ) CloseHandle( original_file );
        if ( projected_file != INVALID_HANDLE_VALUE ) CloseHandle( projected_file );
        CHECK( "mount-cleanup-fixture-link", CreateSymbolicLinkW( ( view + L"\\outside-link" ).c_str(),
            ( std::wstring( root ) + L"\\SRC" ).c_str(), SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE ) );
        first.active = FALSE;
        size = 99;
        CHECK( "mount-expired-license-no-path-size", api->XPackageGetMountPathSize( mount, &size ) == E_ACCESSDENIED && !size );
        char denied[16] = "sentinel";
        CHECK( "mount-expired-license-no-path", api->XPackageGetMountPath( mount, sizeof( denied ), denied ) == E_ACCESSDENIED && !denied[0] );
        api->XPackageCloseMountHandle( mount );
        CHECK( "mount-close-removes-private-view", GetFileAttributesW( view.c_str() ) == INVALID_FILE_ATTRIBUTES && first.closes == 1 );
        CHECK( "mount-close-keeps-other-view", package_mount_path( other, sizeof( other_path ), other_path ) == S_OK && !second.closes );
        api->XPackageCloseMountHandle( mount );
        CHECK( "mount-close-idempotent", first.closes == 1 );
        package_mount_close( other );
        CHECK( "mount-second-license-closed", second.closes == 1 );
    }
    else
    {
        package_mount_close( mount ); package_mount_close( other );
    }
    SIZE_T absent = 123;
    CHECK( "mount-foreign-size-refused", package_mount_path_size( ( XPackageMountHandle )1, &absent ) == E_INVALIDARG && !absent );
    char absent_path[8] = "keep";
    CHECK( "mount-foreign-path-refused", package_mount_path( ( XPackageMountHandle )1, sizeof( absent_path ), absent_path ) == E_INVALIDARG && !absent_path[0] );
    package_mount_close( ( XPackageMountHandle )1 );
    CHECK( "mount-original-alpha-preserved", mount_fixture_bytes( std::wstring( root ) + L"\\SRC\\alpha.dat", "alpha content" ) );
    CHECK( "mount-original-gamma-preserved", mount_fixture_bytes( std::wstring( root ) + L"\\Extras\\gamma.dat", "gamma content" ) );
    CHECK( "mount-original-not-made-readonly", !( GetFileAttributesW( ( std::wstring( root ) + L"\\SRC\\alpha.dat" ).c_str() ) & FILE_ATTRIBUTE_READONLY ) );
    mount_fixture_license unowned; unowned.active = FALSE;
    mount = ( XPackageMountHandle )1;
    CHECK( "mount-unowned-rejected", package_mount_create( package, mount_fixture_right( unowned ), &mount ) == E_ACCESSDENIED && !mount && unowned.closes == 1 );
    content_package base = package; base.content = FALSE;
    mount_fixture_license base_right;
    CHECK( "mount-game-package-rejected", package_mount_create( base, mount_fixture_right( base_right ), &mount ) == E_ACCESSDENIED && !mount && base_right.closes == 1 );
    std::wstring normalized;
    CHECK( "mount-logical-root", package_mount_relative( "\\", TRUE, normalized ) && normalized.empty() );
    CHECK( "mount-logical-subdirectory", package_mount_relative( "\\Data\\Maps", TRUE, normalized ) && normalized == L"Data\\Maps" );
    CHECK( "mount-destination-traversal-rejected", !package_mount_relative( "\\..\\outside", TRUE, normalized ) );
    CHECK( "mount-drive-destination-rejected", !package_mount_relative( "C:\\outside", TRUE, normalized ) );
    CHECK( "mount-unc-destination-rejected", !package_mount_relative( "\\\\server\\share", TRUE, normalized ) );
    CHECK( "mount-trailing-dot-rejected", !package_mount_relative( "Data.\\x", TRUE, normalized ) );
    CHECK( "mount-source-traversal-rejected", !package_mount_relative( "SRC\\..\\outside", FALSE, normalized ) );
    write_text( layout, "<Package><Chunk><FileGroup SourcePath=\"SRC\" Include=\"*.dat\" DestinationPath=\"\\..\\outside\"/></Chunk></Package>" );
    mount_fixture_license invalid;
    CHECK( "mount-invalid-layout-no-publication", package_mount_create( package, mount_fixture_right( invalid ), &mount ) == E_INVALIDARG && !mount && invalid.closes == 1 );
    content_join( root, L"Alias", path );
    CHECK( "mount-source-link-fixture", CreateSymbolicLinkW( path, ( std::wstring( root ) + L"\\SRC" ).c_str(),
        SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE ) );
    write_text( layout, "<Package><Chunk><FileGroup SourcePath=\"Alias\" Include=\"*.dat\" DestinationPath=\"\\Data\"/></Chunk></Package>" );
    mount_fixture_license linked;
    CHECK( "mount-linked-source-rejected", FAILED( package_mount_create( package, mount_fixture_right( linked ), &mount ) ) &&
        !mount && linked.closes == 1 );
    CHECK( "mount-source-link-unlinked", RemoveDirectoryW( path ) );
    content_join( root, L"Extras\\alpha.dat", path ); write_text( path, "different asset" );
    write_text( layout, "<Package><Chunk><FileGroup SourcePath=\"SRC\" Include=\"alpha.dat\" DestinationPath=\"\\Data\"/>"
        "<FileGroup SourcePath=\"Extras\" Include=\"alpha.dat\" DestinationPath=\"\\data\"/></Chunk></Package>" );
    mount_fixture_license collision;
    CHECK( "mount-destination-case-collision-refused", package_mount_create( package, mount_fixture_right( collision ), &mount ) ==
        HRESULT_FROM_WIN32( ERROR_INVALID_DATA ) && !mount && collision.closes == 1 );
    CHECK( "mount-no-original-deletion-through-link", mount_fixture_bytes( std::wstring( root ) + L"\\SRC\\alpha.dat", "alpha content" ) );
    write_text( layout, mapping );
    CHECK( "mount-registry-drained", !package_mounts );
    CHECK( "mount-managed-workspace-cleared", SetEnvironmentVariableW( L"XODUS_MOUNT_ROOT", NULL ) );
    CHECK( "mount-managed-workspace-empty", RemoveDirectoryW( workspace ) );
    // Keep subsequent discovery independent of this additional synthetic package.
    DeleteFileW( layout );
}

/* A tree extracted at its declared DestinationPath is what the launcher keeps
 * for content that is already deployed; the runtime must enumerate and mount it
 * without falling back to the build-machine SourcePath. */
static void test_deployed_destination()
{
    WCHAR root[MAX_PATH], layout[MAX_PATH], file[MAX_PATH], nested[MAX_PATH], workspace[MAX_PATH], staging[MAX_PATH];
    content_package package{};
    package_mount_plan plan;
    char identifier[33];
    const char *deployed = "<Package><Chunk Id=\"1000\">"
        "<FileGroup SourcePath=\"build\" Include=\"MicrosoftGame.config\" DestinationPath=\"\\\"/>"
        "<FileGroup SourcePath=\"build\\Assets\" Include=\"*.png\" DestinationPath=\"\\Assets\"/>"
        "</Chunk></Package>";
    fixture( L"deployed", "Nexus.Deployed", "D0000000000A", "Nexus.Base", "B00000000001", 0x41, FALSE );
    content_join( folder, L"deployed", root );
    content_join( root, L"Assets", nested );
    CHECK( "deployed-payload-directory", CreateDirectoryW( nested, NULL ) );
    content_join( nested, L"logo.png", file );
    write_text( file, "deployed payload" );
    content_join( root, L"layout_00000041-1111-2222-3333-444444444444.xml", layout );
    write_text( layout, deployed );
    CHECK( "deployed-content-loaded", content_load( root, &package ) && package.content );
    CHECK( "deployed-content-identifier", !strcmp( package.identifier, "00000041111122223333444444444444" ) );
    CHECK( "deployed-content-query",
           content_query_identifier( "D0000000000A", sizeof( identifier ), identifier ) == S_OK &&
               !strcmp( identifier, "00000041111122223333444444444444" ) );
    CHECK( "deployed-mount-plan", package_mount_read_plan( package, plan ) == S_OK && plan.groups == 2 &&
                                      plan.files.size() == 2 && plan.destinations.count( L"Assets\\logo.png" ) );
    content_join( folder, L"deployed-workspace", workspace );
    CHECK( "deployed-mount-workspace",
           CreateDirectoryW( workspace, NULL ) && SetEnvironmentVariableW( L"XODUS_MOUNT_ROOT", workspace ) );
    mount_fixture_license license;
    XPackageMountHandle mount = NULL;
    CHECK( "deployed-mount-created",
           package_mount_create( package, mount_fixture_right( license ), &mount ) == S_OK && mount );
    if ( mount )
    {
        IXPackageImpl *api = GetPackageInterface();
        SIZE_T size = 0;
        char view_path[MAX_PATH * 4] = "";
        WCHAR view[MAX_PATH] = L"";
        BOOL path_ok = api->XPackageGetMountPathSize( mount, &size ) == S_OK && size > 1 &&
            api->XPackageGetMountPath( mount, size, view_path ) == S_OK &&
            MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, view_path, -1, view, MAX_PATH ) > 0;
        CHECK( "deployed-mount-path", path_ok );
        CHECK( "deployed-mount-payload",
               path_ok && mount_fixture_bytes( std::wstring( view ) + L"\\Assets\\logo.png", "deployed payload" ) );
        api->XPackageCloseMountHandle( mount );
    }
    CHECK( "deployed-mount-workspace-cleared", SetEnvironmentVariableW( L"XODUS_MOUNT_ROOT", NULL ) );
    CHECK( "deployed-mount-workspace-empty", RemoveDirectoryW( workspace ) );
    content_join( nested, L"logo.png", file );
    CHECK( "deployed-payload-removed", DeleteFileW( file ) );
    CHECK( "deployed-missing-payload-rejected", !content_load( root, &package ) );
    write_text( file, "deployed payload" );
    /* A complete build tree must not override the deployed payload. */
    content_join( root, L"build", staging );
    CHECK( "deployed-staging-directory", CreateDirectoryW( staging, NULL ) );
    content_join( staging, L"MicrosoftGame.Config", file );
    write_text( file, "<Game/>" );
    content_join( staging, L"Assets", nested );
    CHECK( "deployed-staging-payload-directory", CreateDirectoryW( nested, NULL ) );
    content_join( nested, L"logo.png", file );
    write_text( file, "staging payload" );
    CHECK( "deployed-both-coordinates-destination-preferred", content_load( root, &package ) && package.content );
    package_mount_plan preferred;
    BOOL planned = package_mount_read_plan( package, preferred ) == S_OK && preferred.files.size() == 2;
    auto deployed_entry = preferred.destinations.find( L"Assets\\logo.png" );
    std::wstring deployed_source = std::wstring( root ) + L"\\Assets\\logo.png";
    CHECK( "deployed-both-coordinates-mount-plan",
           planned && deployed_entry != preferred.destinations.end() &&
               preferred.files[deployed_entry->second].source == deployed_source );
    /* Missing DestinationPath uses the declared SourcePath, never the root. */
    write_text( layout, "<Package><Chunk><FileGroup SourcePath=\"Data\" Include=\"*.png\"/></Chunk></Package>" );
    content_join( root, L"Data", nested );
    CHECK( "deployed-no-destination-directory", CreateDirectoryW( nested, NULL ) );
    content_join( nested, L"logo.png", file );
    write_text( file, "source-only payload" );
    CHECK( "deployed-no-destination-source-valid", content_load( root, &package ) && package.content );
    package_mount_plan no_destination;
    CHECK( "deployed-no-destination-mount-plan", package_mount_read_plan( package, no_destination ) == S_OK &&
                                                    no_destination.files.size() == 1 &&
                                                    no_destination.destinations.count( L"Data\\logo.png" ) );
    CHECK( "deployed-no-destination-payload-removed", DeleteFileW( file ) );
    content_join( root, L"logo.png", file );
    write_text( file, "wrong root payload" );
    CHECK( "deployed-no-destination-root-payload-rejected", !content_load( root, &package ) );
    /* An invalid declared path must not hide behind the other coordinate. */
    write_text( layout, "<Package><Chunk>"
        "<FileGroup SourcePath=\"..\\outside\" Include=\"*.png\" DestinationPath=\"\\Assets\"/>"
        "</Chunk></Package>" );
    CHECK( "deployed-invalid-source-declaration-rejected", !content_load( root, &package ) );
    write_text( layout, "<Package><Chunk>"
        "<FileGroup SourcePath=\"build\\Assets\" Include=\"*.png\" DestinationPath=\"C:\\outside\"/>"
        "</Chunk></Package>" );
    CHECK( "deployed-invalid-destination-declaration-rejected", !content_load( root, &package ) );
    write_text( layout, "<Package><Chunk>"
        "<FileGroup SourcePath=\"build\\Assets\" Include=\"*.png\" DestinationPath=\"\\\\server\\share\"/>"
        "</Chunk></Package>" );
    CHECK( "deployed-invalid-unc-declaration-rejected", !content_load( root, &package ) );
    write_text( layout, "<Package><Chunk>"
        "<FileGroup SourcePath=\".. \" Include=\"*.png\" DestinationPath=\"\\Assets\"/>"
        "</Chunk></Package>" );
    CHECK( "deployed-invalid-source-dotspace-rejected", !content_load( root, &package ) );
    write_text( layout, "<Package><Chunk>"
        "<FileGroup SourcePath=\"build\\Assets\" Include=\"*.png\" DestinationPath=\"\\.. \"/>"
        "</Chunk></Package>" );
    CHECK( "deployed-invalid-destination-dotspace-rejected", !content_load( root, &package ) );
    write_text( layout, "<Package><Chunk>"
        "<FileGroup SourcePath=\"build\\Assets\" Include=\"*.png\" DestinationPath=\"\\Assets.\"/>"
        "</Chunk></Package>" );
    CHECK( "deployed-invalid-destination-trailing-dot-rejected", !content_load( root, &package ) );
    write_text( layout, "<Package><Chunk><FileGroup SourcePath=\"Assets\" Include=\"Data.\\*.png\"/></Chunk></Package>" );
    CHECK( "deployed-invalid-include-prefix-rejected", !content_load( root, &package ) );
    write_text( layout, "<Package><Chunk><FileGroup SourcePath=\"Assets\" Include=\"As*ets\\*.png\"/></Chunk></Package>" );
    CHECK( "deployed-invalid-include-wildcard-prefix-rejected", !content_load( root, &package ) );
    write_text( layout, "<Package><Chunk><FileGroup SourcePath=\"Assets\" Include=\"Data|\\*.png\"/></Chunk></Package>" );
    CHECK( "deployed-invalid-include-character-rejected", !content_load( root, &package ) );
    {
        char prefix[MAX_PATH];
        const char *leaf;
        CHECK( "deployed-include-prefix-valid",
               content_include_parts( "Data\\*.png", prefix, sizeof( prefix ), &leaf ) &&
                   !strcmp( prefix, "Data" ) && !strcmp( leaf, "*.png" ) );
        CHECK( "deployed-include-prefix-dot-rejected",
               !content_include_parts( "Data.\\*.png", prefix, sizeof( prefix ), &leaf ) );
        CHECK( "deployed-include-prefix-space-rejected",
               !content_include_parts( "Data \\*.png", prefix, sizeof( prefix ), &leaf ) );
        CHECK( "deployed-include-prefix-wildcard-rejected",
               !content_include_parts( "As*ets\\*.png", prefix, sizeof( prefix ), &leaf ) );
        CHECK( "deployed-include-prefix-character-rejected",
               !content_include_parts( "Data|\\*.png", prefix, sizeof( prefix ), &leaf ) );
    }
    {
        char relative[MAX_PATH];
        CHECK( "deployed-location-dotspace-rejected", !content_package_relative( ".. ", relative, sizeof( relative ) ) );
        CHECK( "deployed-location-trailing-dot-rejected", !content_package_relative( "Assets.", relative, sizeof( relative ) ) );
        CHECK( "deployed-location-normalized",
               content_package_relative( "./Assets/", relative, sizeof( relative ) ) && !strcmp( relative, "Assets" ) );
    }
    /* Groups that only resolve under different coordinates reject the package. */
    write_text( layout, "<Package><Chunk>"
        "<FileGroup SourcePath=\".\" Include=\"MicrosoftGame.config\" DestinationPath=\"\\\"/>"
        "<FileGroup SourcePath=\"OnlySource\" Include=\"*.png\" DestinationPath=\"\\MissingDest\"/>"
        "<FileGroup SourcePath=\"build\\Extra\" Include=\"*.dat\" DestinationPath=\"\\Data\"/>"
        "</Chunk></Package>" );
    content_join( root, L"OnlySource", nested );
    CHECK( "deployed-mixed-source-directory", CreateDirectoryW( nested, NULL ) );
    content_join( nested, L"a.png", file );
    write_text( file, "source only" );
    content_join( root, L"Data", nested );
    content_join( nested, L"b.dat", file );
    write_text( file, "destination only" );
    CHECK( "deployed-mixed-coordinates-rejected", !content_load( root, &package ) );
    /* A layout cannot reach the payload through a reparse-point directory. */
    write_text( layout, "<Package><Chunk><FileGroup SourcePath=\"Alias\" Include=\"*.png\"/></Chunk></Package>" );
    content_join( root, L"Real", nested );
    CHECK( "deployed-reparse-target", CreateDirectoryW( nested, NULL ) );
    content_join( nested, L"logo.png", file );
    write_text( file, "linked payload" );
    content_join( root, L"Alias", staging );
    CHECK( "deployed-reparse-link", CreateSymbolicLinkW( staging, nested,
        SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE ) );
    CHECK( "deployed-reparse-directory-rejected", !content_load( root, &package ) );
    CHECK( "deployed-reparse-link-removed", RemoveDirectoryW( staging ) );
    DeleteFileW( layout );
}

int main( int argc, char **argv )
{
    WCHAR temporary[MAX_PATH];
    if ( argc >= 2 && ( !strcmp( argv[1], "--chunks-current" ) || !strcmp( argv[1], "--chunks-missing" ) ) )
    {
        actual_runtime( argv[1], argc < 3 || strcmp( argv[2], "--kind-unknown" ) );
        printf( "CHUNK CHILD CHECKS %u FAILURES %u\n", checks, failures );
        return failures ? 1 : 0;
    }
    GetTempPathW( MAX_PATH, temporary );
    swprintf( folder, MAX_PATH, L"%lsnexus-content-%lu-%lu", temporary, GetCurrentProcessId(), GetTickCount() );
    CHECK( "fixture-directory", CreateDirectoryW( folder, NULL ) );
    helpers();
    actual_runtime( NULL );
    current_fixtures();
    test_mount_projection();
    test_deployed_destination();
    printf( "CHECKS %u FAILURES %u\n", checks, failures );
    return failures ? 1 : 0;
}
