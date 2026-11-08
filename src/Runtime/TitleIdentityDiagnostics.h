// SPDX-License-Identifier: LGPL-2.1-or-later
// Opt-in, bounded public-identifier diagnostics for title identity resolution.
// Only public configuration identifiers and binding outcomes are written.
// Accounts, XUIDs, tokens, endpoints, raw responses and paths are never logged.
#pragma once
#include "Configuration.h"
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string_view>

namespace nexus::title_identity
{
inline const char *ConfigSourceName( GameConfigSource source ) noexcept
{
    switch ( source )
    {
    case GameConfigSource::Inline: return "inline";
    case GameConfigSource::File: return "file";
    default: return "default";
    }
}

inline const char *ClientSourceName( const GameConfiguration &config ) noexcept
{
    if ( !config.msaAppId.empty() )
        return config.msaAppIdSource == MsaAppIdSource::Legacy ? "legacy" : "explicit";
    /* Matches the ticket request gate: newer full-trust content without a
     * declared client fails before any fallback is chosen. */
    if ( config.fullTrust && !UsesLegacyFullTrust( config ) ) return "none";
    return "fallback";
}

inline bool IsHex16( std::string_view value ) noexcept
{
    bool nonzero = false;
    if ( value.size() != 16 ) return false;
    for ( char c : value )
    {
        if ( !( ( c >= '0' && c <= '9' ) || ( c >= 'a' && c <= 'f' ) || ( c >= 'A' && c <= 'F' ) ) ) return false;
        nonzero |= c != '0';
    }
    return nonzero;
}

inline void SanitizeConfigVersion( std::string_view value, char output[17] ) noexcept
{
    if ( value.empty() )
    {
        strcpy( output, "none" );
        return;
    }
    if ( value.size() > 16 )
    {
        strcpy( output, "invalid" );
        return;
    }
    for ( char c : value )
    {
        if ( !( ( c >= '0' && c <= '9' ) || ( c >= 'a' && c <= 'z' ) || ( c >= 'A' && c <= 'Z' ) || c == '.' ||
                c == '_' || c == '-' ) )
        {
            strcpy( output, "invalid" );
            return;
        }
    }
    size_t length = value.size();
    memcpy( output, value.data(), length );
    output[length] = 0;
}

inline void SanitizeClientId( std::string_view value, char output[17] ) noexcept
{
    if ( value.empty() )
    {
        strcpy( output, "none" );
        return;
    }
    if ( !IsHex16( value ) )
    {
        strcpy( output, "invalid" );
        return;
    }
    for ( size_t i = 0; i < 16; ++i )
        output[i] = value[i] >= 'A' && value[i] <= 'F' ? static_cast<char>( value[i] - 'A' + 'a' ) : value[i];
    output[16] = 0;
}

inline const char *FileState( const WCHAR *path ) noexcept
{
    if ( !path || !*path ) return "none";
    DWORD attributes = GetFileAttributesW( path );
    if ( attributes == INVALID_FILE_ATTRIBUTES ) return "missing";
    return ( attributes & FILE_ATTRIBUTE_DIRECTORY ) ? "directory" : "present";
}

inline const char *SiblingState( const WCHAR *directory, const WCHAR *name ) noexcept
{
    WCHAR path[32768];
    if ( !directory || !*directory ) return "none";
    size_t directoryLength = wcslen( directory ), nameLength = wcslen( name );
    if ( directoryLength + 1 + nameLength >= ARRAYSIZE( path ) ) return "unknown";
    memcpy( path, directory, directoryLength * sizeof( WCHAR ) );
    path[directoryLength] = L'\\';
    memcpy( path + directoryLength + 1, name, ( nameLength + 1 ) * sizeof( WCHAR ) );
    return FileState( path );
}

inline const char *ExecutableSiblingState( const WCHAR *name ) noexcept
{
    WCHAR path[32768];
    DWORD length = GetModuleFileNameW( nullptr, path, ARRAYSIZE( path ) );
    if ( !length || length >= ARRAYSIZE( path ) ) return "unknown";
    WCHAR *slash = wcsrchr( path, L'\\' );
    if ( !slash ) return "unknown";
    *slash = 0;
    return SiblingState( path, name );
}

/* The opt-in gate is read before any formatting or filesystem probing. Normal
 * game starts only pay for this environment lookup. */
inline bool Enabled() noexcept
{
    char path[MAX_PATH];
    DWORD length = GetEnvironmentVariableA( "NEXUS_TITLE_IDENTITY_LOG", path, sizeof( path ) );
    return length && length < sizeof( path );
}

inline void WriteLine( const char *line ) noexcept
{
    static SRWLOCK lock = SRWLOCK_INIT;
    DWORD saved_error = GetLastError(), length, written;
    char path[MAX_PATH];
    LARGE_INTEGER size, end;
    HANDLE file;
    if ( !line ) goto done;
    length = GetEnvironmentVariableA( "NEXUS_TITLE_IDENTITY_LOG", path, sizeof( path ) );
    if ( !length || length >= sizeof( path ) ) goto done;
    length = static_cast<DWORD>( strlen( line ) );
    if ( !length || length >= 240 ) goto done;
    AcquireSRWLockExclusive( &lock );
    file = CreateFileA( path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
    if ( file != INVALID_HANDLE_VALUE )
    {
        if ( GetFileType( file ) == FILE_TYPE_DISK && GetFileSizeEx( file, &size ) &&
             size.QuadPart + length <= 32768 )
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

inline void WriteConfig( const GameConfiguration &config ) noexcept
{
    if ( !Enabled() ) return;
    char version[17], client[17], line[256];
    SanitizeConfigVersion( config.game.attribute( "configVersion" ), version );
    SanitizeClientId( config.msaAppId, client );
    snprintf( line, sizeof( line ),
              "TITLE_IDENTITY_CONFIG source=%s version=%s title=%08lx msa=%s client=%s legacy_root=%s legacy_exe=%s\n",
              ConfigSourceName( config.configSource ), version, static_cast<unsigned long>( config.titleId ), client,
              ClientSourceName( config ), SiblingState( config.directory.c_str(), L"xboxservices.config" ),
              ExecutableSiblingState( L"xboxservices.config" ) );
    WriteLine( line );
}

inline void WriteBinding( const GameConfiguration *config, HRESULT claimHr, UINT32 claimedTitle,
                          const char *binding ) noexcept
{
    if ( !Enabled() ) return;
    char claimed[12], line[256];
    if ( claimedTitle )
        snprintf( claimed, sizeof( claimed ), "%lu", static_cast<unsigned long>( claimedTitle ) );
    else
        strcpy( claimed, "none" );
    snprintf( line, sizeof( line ), "TITLE_IDENTITY_BINDING source=%s client=%s claim_hr=%08lx claimed=%s binding=%s\n",
              config ? ConfigSourceName( config->configSource ) : "none",
              config ? ClientSourceName( *config ) : "none", static_cast<unsigned long>( static_cast<UINT32>( claimHr ) ),
              claimed, binding ? binding : "invalid" );
    WriteLine( line );
}
}
