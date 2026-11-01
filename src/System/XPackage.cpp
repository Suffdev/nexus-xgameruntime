/*
 * Xbox Game runtime Library
 *  GDK Component: System API -> XPackage
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

#include "XPackage.h"
#include "../Runtime/Configuration.h"
#include <mutex>
#include <string.h>

#include "Package/Content.h"
#include "Package/Chunks.h"
#include "Package/Monitors.h"
#include "Package/InstalledEvents.h"
#include "Package/Mount.h"

static HRESULT enumerate_current_package( XPackageKind, XPackageEnumerationScope, void *,
                                          XPackageEnumerationCallback * );
/* The package's own identifier, taken from the layout file beside it.
 *
 * Every package ships a layout_<guid>.xml at its root, and that guid without
 * its dashes is the 32 characters a caller asks for here -- titles pass a
 * bufferSize of 33, which is those characters and a terminator.
 *
 * Refusing left the buffer untouched, so titles built monitors for a package
 * identified as "" and died (the engine's GDKPackageChunkInstall raises a
 * LowLevelFatalError on this failure).
 *
 * The root is not always where the executable is -- Unreal ships its binary
 * several directories down -- so walk up until the layout turns up, the same
 * way the game config is found. */
static HRESULT package_identifier( char *buffer, SIZE_T bufferSize )
{
    WCHAR path[MAX_PATH];
    WCHAR *sep;

    if ( !GetModuleFileNameW( NULL, path, ARRAY_SIZE( path ) ) ) return E_FAIL;
    if ( !( sep = wcsrchr( path, '\\' ) ) ) return E_FAIL;
    *sep = 0;

    for ( ;; )
    {
        WCHAR pattern[MAX_PATH];
        WIN32_FIND_DATAW data;
        HANDLE find;

        if ( wcslen( path ) + ARRAY_SIZE( L"\\layout_*.xml" ) > ARRAY_SIZE( pattern ) ) return E_FAIL;
        wcscpy( pattern, path );
        wcscat( pattern, L"\\layout_*.xml" );

        if ( ( find = FindFirstFileW( pattern, &data ) ) != INVALID_HANDLE_VALUE )
        {
            const WCHAR *guid = data.cFileName + ARRAY_SIZE( L"layout_" ) - 1;
            SIZE_T used = 0;

            for ( ; *guid && *guid != '.'; guid++ )
            {
                if ( *guid == '-' ) continue;
                if ( used + 1 >= bufferSize )
                {
                    FindClose( find );
                    return E_NOT_SUFFICIENT_BUFFER;
                }
                buffer[used++] = ( char )*guid;
            }
            buffer[used] = 0;
            FindClose( find );
            return used ? S_OK : E_FAIL;
        }

        if ( !( sep = wcsrchr( path, '\\' ) ) ) return E_FAIL;
        *sep = 0;
    }
}

HRESULT WINAPI XPackageImpl::XPackageGetCurrentProcessPackageIdentifier( SIZE_T bufferSize, char *buffer )
{
    if ( !buffer || !bufferSize ) return E_INVALIDARG;
    return package_identifier( buffer, bufferSize );
}

BOOLEAN WINAPI XPackageImpl::XPackageIsPackagedProcess()
{

    /* Everything reaching this runtime came out of an MSIX package and is run
     * beside the appxmanifest and MicrosoftGame.config that describe it.
     * Answering FALSE sends a title down its unpackaged path (Deep Rock
     * Galactic asked twice and then put up its own crash dialog). */
    return TRUE;
}

HRESULT WINAPI XPackageImpl::XPackageCreateInstallationMonitor( const char *packageIdentifier, UINT32 selectorCount,
                                                                XPackageChunkSelector *selectors,
                                                                UINT32 minimumUpdateIntervalMs, XTaskQueueHandle queue,
                                                                XPackageInstallationMonitorHandle *installationMonitor )
{

    return installation_create( packageIdentifier, selectorCount, selectors, minimumUpdateIntervalMs, queue,
                                installationMonitor );
}

void WINAPI
XPackageImpl::XPackageCloseInstallationMonitorHandle( XPackageInstallationMonitorHandle installationMonitor )
{

    installation_close( installationMonitor );
}

void WINAPI XPackageImpl::XPackageGetInstallationProgress( XPackageInstallationMonitorHandle installationMonitor,
                                                           XPackageInstallationProgress *progress )
{
    struct installation_monitor *impl;

    if ( !progress ) return;

    memset( progress, 0, sizeof( *progress ) );
    if ( !( impl = installation_acquire( installationMonitor ) ) ) return;
    AcquireSRWLockShared( &installation_lock );
    *progress = impl->progress;
    ReleaseSRWLockShared( &installation_lock );
    installation_release( impl );
}

BOOLEAN WINAPI XPackageImpl::XPackageUpdateInstallationMonitor( XPackageInstallationMonitorHandle installationMonitor )
{
    struct installation_monitor *impl = installation_acquire( installationMonitor );
    HRESULT hr;
    if ( !impl ) return FALSE;
    hr = installation_refresh( impl );
    installation_notify( impl );
    installation_schedule( impl );
    installation_release( impl );
    return SUCCEEDED( hr );
}

HRESULT WINAPI XPackageImpl::XPackageRegisterInstallationProgressChanged(
    XPackageInstallationMonitorHandle installationMonitor, void *context,
    XPackageInstallationProgressCallback *callback, XTaskQueueRegistrationToken *token )
{
    return installation_register( installationMonitor, context, callback, token );
}

BOOLEAN WINAPI XPackageImpl::XPackageUnregisterInstallationProgressChanged(
    XPackageInstallationMonitorHandle installationMonitor, XTaskQueueRegistrationToken token, BOOLEAN wait )
{
    return installation_unregister( installationMonitor, token, wait );
}

HRESULT WINAPI XPackageImpl::XPackageGetUserLocale( SIZE_T localeSize, char *locale )
{
    char requested[LOCALE_NAME_MAX_LENGTH];
    WCHAR user_locale[LOCALE_NAME_MAX_LENGTH];
    DWORD length;
    INT converted;

    if ( !locale || !localeSize ) return E_INVALIDARG;

    /* The launcher selects a locale declared by the installed package. */
    length = GetEnvironmentVariableA( "XODUS_PACKAGE_LOCALE", requested, sizeof( requested ) );
    if ( length >= sizeof( requested ) ) return HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER );
    if ( length )
    {
        if ( length + 1 > localeSize ) return HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER );
        memcpy( locale, requested, length + 1 );
        return S_OK;
    }

    if ( !GetUserDefaultLocaleName( user_locale, ARRAY_SIZE( user_locale ) ) )
        return HRESULT_FROM_WIN32( GetLastError() );
    converted = WideCharToMultiByte( CP_UTF8, 0, user_locale, -1, NULL, 0, NULL, NULL );
    if ( !converted ) return HRESULT_FROM_WIN32( GetLastError() );
    if ( ( SIZE_T )converted > localeSize ) return HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER );
    if ( !WideCharToMultiByte( CP_UTF8, 0, user_locale, -1, locale, converted, NULL, NULL ) )
        return HRESULT_FROM_WIN32( GetLastError() );
    return S_OK;
}

/* Everything a title can ask about is already on disk.
 *
 * Chunks are how a package is installed in pieces, so a title can start before
 * the rest arrives and wait on what it still needs. Xodus extracts a package in
 * full before it can be launched, so every chunk is Ready and always was.
 * Refusing to say so leaves a title waiting for content that is already there:
 * Resident Evil 2 plays its publisher logos and then sits on a black screen. */
HRESULT WINAPI XPackageImpl::XPackageFindChunkAvailability( const char *packageIdentifier, UINT32 selectorCount,
                                                            XPackageChunkSelector *selectors,
                                                            XPackageChunkAvailability *availability )
{

    if ( !availability ) return E_INVALIDARG;
    *availability = XPackageChunkAvailability::Ready;
    return S_OK;
}

HRESULT WINAPI XPackageImpl::XPackageEnumerateChunkAvailability( const char *packageIdentifier,
                                                                 XPackageChunkSelectorType type, void *context,
                                                                 XPackageChunkAvailabilityCallback *callback )
{

    return enumerate_installed_chunks( packageIdentifier, type, context, callback );
}

/* Installation evidence only, never an ownership or download assertion. Content
 * lookup validates its layout and declared payload. For the current executable,
 * also require matching on-disk config/Appx identity and a readable layout. */
static HRESULT installed_chunk_package( const char *identifier )
{
    struct content_game current;
    struct content_package *package;
    WCHAR path[MAX_PATH], file[MAX_PATH], *sep;
    char store[13];
    HRESULT hr;
    UINT i;

    if ( !identifier || strlen( identifier ) != 32 ) return E_INVALIDARG;
    for ( i = 0; i < 32; i++ )
        if ( !( ( identifier[i] >= '0' && identifier[i] <= '9' ) || ( identifier[i] >= 'a' && identifier[i] <= 'f' ) ) )
            return E_INVALIDARG;

    hr = xpackage_query_content_store( identifier, sizeof( store ), store );
    if ( hr != E_GAMEPACKAGE_NO_PACKAGE_IDENTIFIER ) return hr;
    if ( !GetModuleFileNameW( NULL, path, ARRAY_SIZE( path ) ) || !( sep = wcsrchr( path, '\\' ) ) )
        return E_GAMEPACKAGE_NO_PACKAGE_IDENTIFIER;
    *sep = 0;
    current = GetContentConfiguration();
    if ( !( package = static_cast<std::remove_reference_t<decltype( package )>>( calloc( 1, sizeof( *package ) ) ) ) )
        return E_OUTOFMEMORY;
    for ( ;; )
    {
        if ( !content_join( path, L"MicrosoftGame.config", file ) ) break;
        if ( GetFileAttributesW( file ) != INVALID_FILE_ATTRIBUTES )
        {
            if ( content_load( path, package ) && !package->content && !strcmp( current.identity, package->identity ) &&
                 !strcmp( current.publisher, package->publisher_id ) && !strcmp( current.store, package->store ) &&
                 content_load_layout( package ) && !strcmp( identifier, package->identifier ) )
                hr = S_OK;
            break;
        }
        if ( !( sep = wcsrchr( path, '\\' ) ) || sep <= path + 2 ) break;
        *sep = 0;
    }
    free( package );
    return hr;
}

HRESULT WINAPI XPackageImpl::XPackageChangeChunkInstallOrder( const char *packageIdentifier, UINT32 selectorCount,
                                                              XPackageChunkSelector *selectors )
{
    UINT i;

    if ( selectorCount && !selectors ) return E_INVALIDARG;
    for ( i = 0; i < selectorCount; i++ )
    {
        switch ( selectors[i].type )
        {
        case XPackageChunkSelectorType::Chunk:
            break;
        case XPackageChunkSelectorType::Language:
        case XPackageChunkSelectorType::Tag:
        case XPackageChunkSelectorType::Feature:
            if ( !selectors[i].language || !selectors[i].language[0] ) return E_INVALIDARG;
            break;
        default:
            return E_INVALIDARG;
        }
    }
    /* Extracted packages are installed in full before launch. The SDK ignores
     * chunks already installed or not scheduled by intelligent delivery, so no
     * queue mutation is needed. Unknown installations must still fail. */
    return installed_chunk_package( packageIdentifier );
}

HRESULT WINAPI XPackageImpl::XPackageInstallChunks( const char *packageIdentifier, UINT32 selectorCount,
                                                    XPackageChunkSelector *selectors, UINT32 minimumUpdateIntervalMs,
                                                    BOOLEAN suppressUserConfirmation, XTaskQueueHandle queue,
                                                    XPackageInstallationMonitorHandle *installationMonitor )
{

    return E_NOTIMPL;
}

HRESULT WINAPI XPackageImpl::XPackageInstallChunksAsync( const char *packageIdentifier, UINT32 selectorCount,
                                                         XPackageChunkSelector *selectors,
                                                         UINT32 minimumUpdateIntervalMs,
                                                         BOOLEAN suppressUserConfirmation, XAsyncBlock *asyncBlock )
{

    return E_NOTIMPL;
}

HRESULT WINAPI XPackageImpl::XPackageInstallChunksResult( XAsyncBlock *asyncBlock,
                                                          XPackageInstallationMonitorHandle *installationMonitor )
{

    return E_NOTIMPL;
}

HRESULT WINAPI XPackageImpl::XPackageEstimateDownloadSize( const char *packageIdentifier, UINT32 selectorCount,
                                                           XPackageChunkSelector *selectors, UINT64 *downloadSize,
                                                           BOOLEAN *shouldPresentUserConfirmation )
{

    return E_NOTIMPL;
}

HRESULT WINAPI XPackageImpl::XPackageUninstallChunks( const char *packageIdentifier, UINT32 selectorCount,
                                                      XPackageChunkSelector *selectors )
{

    return E_NOTIMPL;
}

HRESULT WINAPI XPackageImpl::XPackageEnumeratePackagesLegacy( XPackageKind kind, XPackageEnumerationScope scope,
                                                              void *context, XPackageEnumerationCallback *callback )
{

    return enumerate_current_package( kind, scope, context, callback );
}

HRESULT WINAPI XPackageImpl::XPackageRegisterPackageInstalledLegacy( XTaskQueueHandle queue, void *context,
                                                                     XPackageInstalledCallback *callback,
                                                                     XTaskQueueRegistrationToken *token )
{

    return installed_package_register( queue, context, callback, token );
}

BOOLEAN WINAPI XPackageImpl::XPackageUnregisterPackageInstalled( XTaskQueueRegistrationToken token, BOOLEAN wait )
{

    return installed_package_unregister( token, wait );
}

HRESULT WINAPI XPackageImpl::XPackageMountLegacy( const char *identifier, XPackageMountHandle *mount )
{

    return package_mount_legacy( identifier, mount );
}

HRESULT WINAPI XPackageImpl::XPackageGetMountPathSize( XPackageMountHandle mount, SIZE_T *pathSize )
{

    return package_mount_path_size( mount, pathSize );
}

HRESULT WINAPI XPackageImpl::XPackageGetMountPath( XPackageMountHandle mount, SIZE_T pathSize, char *path )
{

    return package_mount_path( mount, pathSize, path );
}

void WINAPI XPackageImpl::XPackageCloseMountHandle( XPackageMountHandle mount )
{
    package_mount_close( mount );
}

HRESULT WINAPI XPackageImpl::XPackageGetIdentifierLegacy( const char *store, SIZE_T size, char *identifier )
{

    return xpackage_query_identifier( store, size, identifier );
}

/* The one package this process runs from: Xodus extracts a single MSIX
 * package in full, so an enumeration either visits that package (when the
 * caller asks for its kind) or visits nothing. Fields we have no data for
 * are empty rather than invented; installing is FALSE because there is
 * nothing left to install. */

/* Titles read their own record out of XPackageDetails -- Forza prints the
 * package version on its title screen and gates initialization steps on it.
 * The layout file carries no version, but MicrosoftGame.Config -- the GDK
 * standard file shipped beside the executable -- carries Identity/Version,
 * the display metadata and TitleId/StoreId. It is read once, on demand, by
 * walking up from the executable directory the same way the layout file is
 * found; nothing here knows which title is running. */
static struct
{
    XVersion version;
    char displayName[128];
    char description[256];
    char publisher[128];
    char titleID[16];
    char storeId[64];
} package_fields;
static std::once_flag packageFieldsOnce;

static void ReadPackageMetadata()
{
    WCHAR path[MAX_PATH];
    char version[32];
    xmlDocPtr doc = NULL;
    xmlNodePtr root, visuals;
    WCHAR *sep;

    if ( !GetModuleFileNameW( NULL, path, ARRAY_SIZE( path ) ) ) return;
    if ( !( sep = wcsrchr( path, '\\' ) ) ) return;
    *sep = 0;

    for ( ;; )
    {
        WCHAR config_path[MAX_PATH];

        if ( wcslen( path ) + ARRAY_SIZE( L"\\MicrosoftGame.Config" ) > ARRAY_SIZE( config_path ) ) break;
        wcscpy( config_path, path );
        wcscat( config_path, L"\\MicrosoftGame.Config" );

        if ( GetFileAttributesW( config_path ) != INVALID_FILE_ATTRIBUTES )
        {
            doc = content_read_xml( config_path );
            break;
        }
        if ( GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND ) break;
        if ( !( sep = wcsrchr( path, '\\' ) ) ) break;
        *sep = 0;
    }

    if ( !doc ) return;
    root = xmlDocGetRootElement( doc );
    if ( !root || strcmp( ( char * )root->name, "Game" ) )
    {
        xmlFreeDoc( doc );
        return;
    }

    /* Share the bounded, DTD-free XML reader with content packages. Only active
     * direct elements can supply metadata, never commented examples, CDATA
     * markup, similarly named attributes or unrelated nested elements. */
    if ( content_text( content_child( root, "Identity" ), "Version", version, sizeof( version ) ) )
        content_version( version, &package_fields.version );
    visuals = content_child( root, "ShellVisuals" );
    content_text( visuals, "DefaultDisplayName", package_fields.displayName, sizeof( package_fields.displayName ) );
    content_text( visuals, "Description", package_fields.description, sizeof( package_fields.description ) );
    content_text( visuals, "PublisherDisplayName", package_fields.publisher, sizeof( package_fields.publisher ) );
    content_text( content_child( root, "TitleId" ), NULL, package_fields.titleID, sizeof( package_fields.titleID ) );
    content_text( content_child( root, "StoreId" ), NULL, package_fields.storeId, sizeof( package_fields.storeId ) );
    xmlFreeDoc( doc );
}

static void load_package_fields()
{
    std::call_once( packageFieldsOnce, ReadPackageMetadata );
}

static HRESULT enumerate_current_package( XPackageKind kind, XPackageEnumerationScope scope, void *context,
                                          XPackageEnumerationCallback *callback )
{
    char identifier[33]; /* 32 characters and a terminator, as titles ask for. */
    XPackageDetails details;
    HRESULT hr;

    if ( !callback || static_cast<UINT>( kind ) > static_cast<UINT>( XPackageKind::PublisherContent ) ||
         static_cast<UINT>( scope ) > static_cast<UINT>( XPackageEnumerationScope::ThisPublisher ) )
        return E_INVALIDARG;
    if ( kind == XPackageKind::Content ) return enumerate_content_packages( scope, context, callback );
    if ( kind == XPackageKind::PublisherContent ) return E_NOTIMPL;
    if ( FAILED( hr = package_identifier( identifier, sizeof( identifier ) ) ) ) return hr;

    load_package_fields();

    memset( &details, 0, sizeof( details ) );
    details.packageIdentifier = identifier;
    details.kind = XPackageKind::Game;
    details.installing = FALSE;
    details.index = 0;
    details.count = 1;
    details.version = package_fields.version;
    details.displayName = package_fields.displayName[0] ? package_fields.displayName : NULL;
    details.description = package_fields.description[0] ? package_fields.description : NULL;
    details.publisher = package_fields.publisher[0] ? package_fields.publisher : NULL;
    details.storeId = package_fields.storeId[0] ? package_fields.storeId : NULL;
    details.titleID = package_fields.titleID[0] ? package_fields.titleID : NULL;
    callback( context, &details );
    return S_OK;
}

HRESULT WINAPI XPackageImpl::XPackageEnumeratePackages( XPackageKind kind, XPackageEnumerationScope scope,
                                                        void *context, XPackageEnumerationCallback *callback )
{

    return enumerate_current_package( kind, scope, context, callback );
}

HRESULT xpackage_query_identifier( const char *requested_store, SIZE_T size, char *identifier )
{
    HRESULT hr;
    if ( identifier && size ) identifier[0] = 0;
    if ( !content_id( requested_store ) || !identifier ) return E_INVALIDARG;
    if ( size < 33 ) return E_NOT_SUFFICIENT_BUFFER;
    const auto config = nexus::GetGameConfiguration();
    if ( config && !config->storeId.empty() && !strcmp( requested_store, config->storeId.c_str() ) )
    {
        hr = package_identifier( identifier, size );
        return hr == E_FAIL ? E_INVALIDARG : hr;
    }
    return content_query_identifier( requested_store, size, identifier );
}

HRESULT WINAPI XPackageImpl::XPackageRegisterPackageInstalled( XTaskQueueHandle queue, void *context,
                                                               XPackageInstalledCallback *callback,
                                                               XTaskQueueRegistrationToken *token )
{

    return installed_package_register( queue, context, callback, token );
}

HRESULT WINAPI XPackageImpl::XPackageGetWriteStats( XPackageWriteStats *writeStats )
{

    return E_NOTIMPL;
}

HRESULT WINAPI XPackageImpl::XPackageEnumerateFeaturesLegacy( const char *identifier, void *context,
                                                              XPackageFeatureEnumerationCallback *callback )
{
    return XPackageEnumerateFeatures( identifier, context, callback );
}

HRESULT WINAPI XPackageImpl::XPackageUninstallUWPInstance( const char *packageName )
{

    return E_NOTIMPL;
}

HRESULT WINAPI XPackageImpl::XPackageEnumerateFeatures( const char *packageIdentifier, void *context,
                                                        XPackageFeatureEnumerationCallback *callback )
{

    if ( !callback ) return E_INVALIDARG;

    /* Optional features are declared in MicrosoftGame.config, and nothing
     * installed here declares any: an enumeration that visits nothing is the
     * true answer, not a failure. Refusing was enough to end Deep Rock
     * Galactic, which put up a crash dialog carrying no message at all. */
    return S_OK;
}

BOOLEAN WINAPI XPackageImpl::XPackageUninstallPackage( const char *packageIdentifier )
{

    return FALSE;
}

HRESULT WINAPI XPackageImpl::XPackageEnumeratePackages2( XPackageKind kind, XPackageEnumerationScope scope,
                                                         void *context, XPackageEnumerationCallback *callback )
{

    return enumerate_current_package( kind, scope, context, callback );
}

HRESULT WINAPI XPackageImpl::XPackageRegisterPackageInstalled2( XTaskQueueHandle queue, void *context,
                                                                XPackageInstalledCallback *callback,
                                                                XTaskQueueRegistrationToken *token )
{

    return installed_package_register( queue, context, callback, token );
}

HRESULT WINAPI XPackageImpl::XPackageMountWithUiAsync( const char *packageIdentifier, XAsyncBlock *async )
{

    return E_NOTIMPL;
}

HRESULT WINAPI XPackageImpl::XPackageMountWithUiResult( XAsyncBlock *async, XPackageMountHandle *mount )
{

    return E_NOTIMPL;
}

HRESULT WINAPI XPackageImpl::XPackageEnumeratePackages3( XPackageKind kind, XPackageEnumerationScope scope,
                                                         void *context, XPackageEnumerationCallback *callback )
{

    return enumerate_current_package( kind, scope, context, callback );
}

HRESULT WINAPI XPackageImpl::XPackageRegisterPackageInstalled3( XTaskQueueHandle queue, void *context,
                                                                XPackageInstalledCallback *callback,
                                                                XTaskQueueRegistrationToken *token )
{
    return XPackageRegisterPackageInstalledLegacy( queue, context, callback, token );
}

HRESULT WINAPI XPackageImpl::XPackageGetKind( const char *identifier, XPackageKind *kind )
{
    if ( !kind || !chunks_identifier( identifier ) ) return E_INVALIDARG;
    WCHAR path[MAX_PATH];
    HRESULT hr = chunks_resolve( identifier, path );
    if ( FAILED( hr ) ) return hr;
    content_package package{};
    if ( !content_load( path, &package ) ) return E_GAMEPACKAGE_NO_PACKAGE_IDENTIFIER;
    *kind = package.content ? XPackageKind::Content : XPackageKind::Game;
    return S_OK;
}

IXPackageImpl *GetPackageInterface() noexcept
{
    static XPackageImpl package;
    return &package;
}
