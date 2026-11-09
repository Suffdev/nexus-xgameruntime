// SPDX-License-Identifier: LGPL-2.1-or-later
// Package-family derivation preserves the original Wine/Olivia Ryan algorithm.
#include "../private.h"
#include "Configuration.h"
#include "LegacyServiceClient.h"
#include "TitleIdentityDiagnostics.h"
#include <bcrypt.h>
#include <charconv>
#include <atomic>
#include <memory>
#include <mutex>
#include <algorithm>
#include <cstring>

namespace nexus
{
static std::mutex initializationMutex;
static std::unique_ptr<GameConfiguration> owner;
static std::atomic<const GameConfiguration *> published{ nullptr };
const GameConfiguration *GetGameConfiguration() noexcept
{
    return published.load( std::memory_order_acquire );
}

static bool IsValidStoreId( std::string_view value )
{
    if ( value.size() != 12 ) return false;
    return std::all_of( value.begin(), value.end(),
                        []( char c ) { return ( c >= '0' && c <= '9' ) || ( c >= 'A' && c <= 'Z' ); } );
}

static bool IsValidScid( std::string_view value ) noexcept
{
    if ( value.size() != 36 ) return false;
    for ( size_t i = 0; i < value.size(); ++i )
    {
        const char c = value[i];
        if ( i == 8 || i == 13 || i == 18 || i == 23 )
        {
            if ( c != '-' ) return false;
        }
        else if ( !( ( c >= '0' && c <= '9' ) || ( c >= 'a' && c <= 'f' ) || ( c >= 'A' && c <= 'F' ) ) )
            return false;
    }
    return true;
}

HRESULT GetGameScid( const GameConfiguration &config, std::string &scid ) noexcept
{
    scid.clear();
    const XmlNode *storage = config.game.child( "SaveGameStorage" );
    const XmlNode *node = storage ? storage->child( "SCID" ) : nullptr;
    if ( !node ) return E_INVALIDARG;
    std::string_view value = node->text;
    const auto first = value.find_first_not_of( " \t\r\n" ), last = value.find_last_not_of( " \t\r\n" );
    if ( first == std::string_view::npos ) return E_INVALIDARG;
    value = value.substr( first, last - first + 1 );
    if ( !IsValidScid( value ) ) return E_INVALIDARG;
    try
    {
        scid.assign( value );
        return S_OK;
    }
    catch ( const std::bad_alloc & )
    {
        scid.clear();
        return E_OUTOFMEMORY;
    }
}

HRESULT GetGameScid( std::string &scid ) noexcept
{
    scid.clear();
    const GameConfiguration *config = GetGameConfiguration();
    return config ? GetGameScid( *config, scid ) : E_INVALIDARG;
}

HRESULT GetPackageFamilyName( std::string_view name, std::string_view publisher, std::string &result ) noexcept
{
    if ( name.empty() || publisher.empty() ) return E_INVALIDARG;
    // This name is also a single on-disk directory, never an arbitrary path.
    if ( name.find_first_of( "/\\:<>\"|?*" ) != std::string_view::npos || name == "." || name == ".." )
        return E_INVALIDARG;
    try
    {
        std::wstring wide;
        HRESULT hr = ToUtf16( publisher, wide );
        if ( FAILED( hr ) ) return hr;
        BYTE digest[32];
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider( &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0 );
        if ( status < 0 ) return E_FAIL;
        status = BCryptHash( algorithm, nullptr, 0, reinterpret_cast<BYTE *>( wide.data() ),
                             static_cast<ULONG>( wide.size() * sizeof( WCHAR ) ), digest, sizeof( digest ) );
        BCryptCloseAlgorithmProvider( algorithm, 0 );
        if ( status < 0 ) return E_FAIL;
        constexpr char alphabet[] = "0123456789abcdefghjkmnpqrstvwxyz";
        UINT64 bits = 0;
        for ( unsigned i = 0; i < 8; ++i )
            bits = ( bits << 8 ) | digest[i];
        result.assign( name );
        result += '_';
        for ( unsigned i = 0; i < 13; ++i )
        {
            int shift = 64 - 5 * static_cast<int>( i + 1 );
            UINT32 value = shift >= 0 ? ( bits >> shift ) & 31 : ( bits << -shift ) & 31;
            result += alphabet[value];
        }
        return S_OK;
    }
    catch ( const std::bad_alloc & )
    {
        return E_OUTOFMEMORY;
    }
}

static HRESULT LoadDefaultConfiguration( GameConfiguration &config )
{
    std::wstring executable( 32768, L'\0' );
    DWORD count = GetModuleFileNameW( nullptr, executable.data(), static_cast<DWORD>( executable.size() ) );
    if ( !count ) return HRESULT_FROM_WIN32( GetLastError() );
    if ( count >= executable.size() ) return HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER );
    executable.resize( count );
    for ( ;; )
    {
        auto slash = executable.find_last_of( L"\\/" );
        if ( slash == std::wstring::npos ) return E_GAME_MISSING_GAME_CONFIG;
        executable.resize( slash );
        std::wstring file = executable + L"\\MicrosoftGame.config";
        DWORD attributes = GetFileAttributesW( file.c_str() );
        if ( attributes != INVALID_FILE_ATTRIBUTES )
        {
            if ( attributes & FILE_ATTRIBUTE_DIRECTORY ) return E_GAMERUNTIME_GAMECONFIG_BAD_FORMAT;
            config.directory = executable;
            return ReadXmlFile( file, config.game );
        }
    }
}

static HRESULT load( GameConfiguration &config, const INITIALIZE_OPTIONS *options )
{
    HRESULT hr;
    if ( options && ( options->gameConfig || options->isInlineConfig ) )
    {
        if ( !options->gameConfig ) return E_GAMERUNTIME_GAMECONFIG_BAD_FORMAT;
        config.configSource = options->isInlineConfig ? GameConfigSource::Inline : GameConfigSource::File;
        if ( options->isInlineConfig )
        {
            size_t length = strnlen( options->gameConfig, 4 * 1024 * 1024 + 1 );
            hr = ParseXml( std::string_view( options->gameConfig, length ), config.game );
        }
        else
        {
            std::wstring file;
            hr = ToUtf16( options->gameConfig, file );
            if ( FAILED( hr ) ) return hr;
            hr = ReadXmlFile( file, config.game );
            // Retain the containing GetGameConfiguration path for package metadata.
            std::wstring absolute( 32768, L'\0' );
            DWORD length =
                GetFullPathNameW( file.c_str(), static_cast<DWORD>( absolute.size() ), absolute.data(), nullptr );
            if ( length && length < absolute.size() )
            {
                absolute.resize( length );
                config.directory = absolute.substr( 0, absolute.find_last_of( L"\\/" ) );
            }
        }
    }
    else
        hr = LoadDefaultConfiguration( config );
    if ( FAILED( hr ) )
        return hr == E_OUTOFMEMORY || hr == E_GAME_MISSING_GAME_CONFIG ? hr : E_GAMERUNTIME_GAMECONFIG_BAD_FORMAT;
    if ( config.game.name != "Game" ) return E_GAMERUNTIME_GAMECONFIG_BAD_FORMAT;
    for ( const auto &node : config.game.children )
    {
        if ( node.name == "Identity" )
        {
            auto name = node.attribute( "Name" ), publisher = node.attribute( "Publisher" );
            if ( !name.empty() && !publisher.empty() )
            {
                hr = GetPackageFamilyName( name, publisher, config.packageFamilyName );
                if ( FAILED( hr ) ) return hr == E_OUTOFMEMORY ? hr : E_GAMERUNTIME_GAMECONFIG_BAD_FORMAT;
            }
        }
        else if ( node.name == "MSAAppId" )
            config.msaAppId = node.text;
        else if ( node.name == "StoreId" )
            config.storeId = node.text;
        else if ( node.name == "TitleId" )
        {
            auto value = std::string_view( node.text );
            const auto first = value.find_first_not_of( " \t\r\n" ), last = value.find_last_not_of( " \t\r\n" );
            if ( first == std::string_view::npos ) return E_GAMERUNTIME_GAMECONFIG_BAD_FORMAT;
            value = value.substr( first, last - first + 1 );
            if ( value.starts_with( "0x" ) || value.starts_with( "0X" ) ) value.remove_prefix( 2 );
            auto [end, error] = std::from_chars( value.data(), value.data() + value.size(), config.titleId, 16 );
            if ( error != std::errc{} || end != value.data() + value.size() )
                return E_GAMERUNTIME_GAMECONFIG_BAD_FORMAT;
        }
        else if ( node.name == "MSAFullTrust" )
            config.fullTrust = node.text == "true" || node.text == "1";
        else if ( node.name == "RelatedProducts" )
        {
            for ( const auto &product : node.children )
            {
                if ( product.name != "RelatedProduct" ) continue;
                if ( !IsValidStoreId( product.text ) ) return E_GAMERUNTIME_GAMECONFIG_BAD_FORMAT;
                if ( std::find( config.relatedProducts.begin(), config.relatedProducts.end(), product.text ) ==
                     config.relatedProducts.end() )
                {
                    if ( config.relatedProducts.size() >= 256 ) return E_GAMERUNTIME_GAMECONFIG_BAD_FORMAT;
                    config.relatedProducts.push_back( product.text );
                }
            }
        }
    }
    if ( !config.msaAppId.empty() && config.msaAppIdSource == MsaAppIdSource::None )
        config.msaAppIdSource = MsaAppIdSource::Explicit;
    if ( config.msaAppId.empty() ) config.msaAppIdSource = MsaAppIdSource::None;
    hr = LoadLegacyServiceClient( config );
    if ( FAILED( hr ) ) return hr == E_OUTOFMEMORY ? hr : E_GAMERUNTIME_GAMECONFIG_BAD_FORMAT;
    if ( !config.msaAppId.empty() && config.msaAppIdSource == MsaAppIdSource::None )
        config.msaAppIdSource = MsaAppIdSource::Explicit;
    // Launcher discovery hints cannot grant rights. Malformed hints are ignored
    // atomically, without discarding the manifest list or creating entitlements.
    char hint[256 * 13];
    DWORD count = GetEnvironmentVariableA( "NEXUS_RELATED_PRODUCT_IDS", hint, sizeof( hint ) );
    if ( count && count < sizeof( hint ) )
    {
        auto merged = config.relatedProducts;
        std::string_view remaining( hint, count );
        bool valid = true;
        while ( !remaining.empty() )
        {
            auto comma = remaining.find( ',' );
            auto id = remaining.substr( 0, comma );
            if ( !IsValidStoreId( id ) )
            {
                valid = false;
                break;
            }
            if ( std::find( merged.begin(), merged.end(), id ) == merged.end() )
            {
                if ( merged.size() >= 256 )
                {
                    valid = false;
                    break;
                }
                merged.emplace_back( id );
            }
            if ( comma == std::string_view::npos ) break;
            remaining.remove_prefix( comma + 1 );
            if ( remaining.empty() )
            {
                valid = false;
                break;
            }
        }
        if ( valid ) config.relatedProducts = std::move( merged );
    }
    title_identity::WriteConfig( config );
    return S_OK;
}

HRESULT InitializeGameConfiguration( const INITIALIZE_OPTIONS *options ) noexcept
{
    try
    {
        std::lock_guard lock( initializationMutex );
        if ( GetGameConfiguration() ) return S_OK;
        auto candidate = std::make_unique<GameConfiguration>();
        HRESULT hr = load( *candidate, options );
        if ( FAILED( hr ) ) return hr;
        owner = std::move( candidate );
        published.store( owner.get(), std::memory_order_release );
        return S_OK;
    }
    catch ( const std::bad_alloc & )
    {
        return E_OUTOFMEMORY;
    }
}
}
