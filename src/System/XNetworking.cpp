/*
 * Xbox Game runtime Library
 *  GDK Component: Networking API -> XNetworking
 *
 * Written by Weather
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

#include "XNetworking.h"
#include "Networking/Connectivity.h"
#include "User/OfflineIdentity.h"
#include "../Runtime/Configuration.h"
#include "winhttp.h"
#include "wincrypt.h"

HRESULT WINAPI
XNetworkingImpl::XNetworkingQueryPreferredLocalUdpMultiplayerPort( UINT16 *preferredLocalUdpMultiplayerPort )
{
    ( void )0;
    return E_NOTIMPL;
}

/* The platform has no actual port preference on this runtime; completing
 * with 0 lets the caller's socket bind choose freely, which is what native
 * GDK reports when no preference applies. */
static HRESULT WINAPI XNetworkingPreferredPortProvider( XAsyncOp op, const XAsyncProviderData *data )
{
    IXThreadingImpl *threading;
    HRESULT hr;

    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&threading ) ) ) return hr;
    switch ( op )
    {
    case XAsyncOp::Begin:
        hr = ( threading )->XAsyncSchedule( data->async, 0 );
        break;
    case XAsyncOp::DoWork:
        ( threading )->XAsyncComplete( data->async, S_OK, sizeof( UINT16 ) );
        hr = S_OK;
        break;
    case XAsyncOp::GetResult:
        if ( !data->buffer || data->bufferSize < sizeof( UINT16 ) )
            hr = HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER );
        else
        {
            *( UINT16 * )data->buffer = 0;
            hr = S_OK;
        }
        break;
    default:
        hr = S_OK;
        break;
    }
    ( threading )->Release();
    return hr;
}

HRESULT WINAPI XNetworkingImpl::XNetworkingQueryPreferredLocalUdpMultiplayerPortAsync( XAsyncBlock *asyncBlock )
{
    IXThreadingImpl *threading;
    HRESULT hr;

    ( void )0;

    if ( !asyncBlock ) return E_INVALIDARG;
    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&threading ) ) ) return hr;
    hr = ( threading )
             ->XAsyncBegin( asyncBlock, NULL, NULL, "XNetworkingQueryPreferredLocalUdpMultiplayerPort",
                            XNetworkingPreferredPortProvider );
    ( threading )->Release();
    return hr;
}

HRESULT WINAPI XNetworkingImpl::XNetworkingQueryPreferredLocalUdpMultiplayerPortAsyncResult(
    XAsyncBlock *asyncBlock, UINT16 *preferredLocalUdpMultiplayerPort )
{
    IXThreadingImpl *threading;
    HRESULT hr;

    ( void )0;

    if ( !preferredLocalUdpMultiplayerPort ) return E_INVALIDARG;
    if ( FAILED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, ( void ** )&threading ) ) ) return hr;
    hr = ( threading )->XAsyncGetResult( asyncBlock, NULL, sizeof( UINT16 ), preferredLocalUdpMultiplayerPort, NULL );
    ( threading )->Release();
    return hr;
}

HRESULT WINAPI XNetworkingImpl::XNetworkingRegisterPreferredLocalUdpMultiplayerPortChanged(
    XTaskQueueHandle queue, void *context, XNetworkingPreferredLocalUdpMultiplayerPortChangedCallback *callback,
    XTaskQueueRegistrationToken *token )
{
    static LONG64 next_token;
    ( void )0;
    if ( !callback || !token ) return E_POINTER;
    token->token = InterlockedIncrement64( &next_token );
    return S_OK;
}

BOOLEAN WINAPI XNetworkingImpl::XNetworkingUnregisterPreferredLocalUdpMultiplayerPortChanged(
    XTaskQueueRegistrationToken token, BOOLEAN wait )
{
    ( void )0;
    return TRUE;
}

static const char security_information_identity[] = "XNetworkingSecurityInformation";

static HRESULT WINAPI security_information_provider( XAsyncOp op, const XAsyncProviderData *data )
{
    XNetworkingSecurityInformation *information;
    switch ( op )
    {
    case XAsyncOp::Begin:
        return ( x_threading_impl )->XAsyncSchedule( data->async, 0 );
    case XAsyncOp::DoWork:
        ( x_threading_impl )->XAsyncComplete( data->async, S_OK, sizeof( *information ) );
        break;
    case XAsyncOp::GetResult:
        information = static_cast<XNetworkingSecurityInformation *>( data->buffer );
        memset( information, 0, sizeof( *information ) );
        /* Default HTTPS policy used by the community implementations.
         * WinHTTP still validates the server chain and hostname. No
         * title-specific pin policy has been loaded by this runtime. */
        information->enabledHttpSecurityProtocolFlags =
            WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
        break;
    default:
        break;
    }
    return S_OK;
}

static HRESULT begin_security_information( const WCHAR *url, XAsyncBlock *async )
{
    URL_COMPONENTS components = { sizeof( components ) };
    WCHAR *https_url = NULL;
    SIZE_T length;
    BOOL valid;
    if ( !url || !async ) return E_INVALIDARG;
    /* WSS uses the same TLS endpoint/certificate policy as HTTPS. WinHTTP's
     * URL parser does not recognize the websocket scheme; normalize only
     * for parsing the policy query, not for issuing a request. */
    length = wcslen( url );
    if ( length >= 6 && CompareStringOrdinal( url, 6, L"wss://", 6, TRUE ) == CSTR_EQUAL )
    {
        if ( length > ( SIZE_T )-1 / sizeof( *https_url ) - 3 ) return E_INVALIDARG;
        if ( !( https_url = static_cast<std::remove_reference_t<decltype( https_url )>>(
                    malloc( ( length + 3 ) * sizeof( *https_url ) ) ) ) )
            return E_OUTOFMEMORY;
        memcpy( https_url, L"https://", 8 * sizeof( *https_url ) );
        memcpy( https_url + 8, url + 6, ( length - 5 ) * sizeof( *https_url ) );
        url = https_url;
    }
    components.dwHostNameLength = 1;
    valid = WinHttpCrackUrl( url, 0, 0, &components ) && components.nScheme == INTERNET_SCHEME_HTTPS &&
            components.dwHostNameLength;
    free( https_url );
    if ( !valid )
    {
        return E_INVALIDARG;
    }
    return ( x_threading_impl )
        ->XAsyncBegin( async, NULL, security_information_identity, "XNetworkingSecurityInformation",
                       security_information_provider );
}

HRESULT WINAPI XNetworkingImpl::XNetworkingQuerySecurityInformationForUrlAsync( const char *url,
                                                                                XAsyncBlock *asyncBlock )
{
    WCHAR *wide;
    int length;
    HRESULT hr;
    ( void )0;
    if ( !url || !( length = MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, url, -1, NULL, 0 ) ) )
        return E_INVALIDARG;
    if ( !( wide = static_cast<std::remove_reference_t<decltype( wide )>>( malloc( length * sizeof( *wide ) ) ) ) )
        return E_OUTOFMEMORY;
    MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, url, -1, wide, length );
    hr = begin_security_information( wide, asyncBlock );
    free( wide );
    return hr;
}

HRESULT WINAPI XNetworkingImpl::XNetworkingQuerySecurityInformationForUrlAsyncResultSize(
    XAsyncBlock *asyncBlock, SIZE_T *securityInformationBufferByteCount )
{
    return ( x_threading_impl )->XAsyncGetResultSize( asyncBlock, securityInformationBufferByteCount );
}

HRESULT WINAPI XNetworkingImpl::XNetworkingQuerySecurityInformationForUrlAsyncResult(
    XAsyncBlock *asyncBlock, SIZE_T securityInformationBufferByteCount, SIZE_T *securityInformationBufferByteCountUsed,
    UINT8 *securityInformationBuffer, XNetworkingSecurityInformation **securityInformation )
{
    HRESULT hr;
    if ( !securityInformation ) return E_POINTER;
    *securityInformation = NULL;
    hr = ( x_threading_impl )
             ->XAsyncGetResult( asyncBlock, security_information_identity, securityInformationBufferByteCount,
                                securityInformationBuffer, securityInformationBufferByteCountUsed );
    if ( SUCCEEDED( hr ) ) *securityInformation = ( XNetworkingSecurityInformation * )securityInformationBuffer;
    return hr;
}

HRESULT WINAPI XNetworkingImpl::XNetworkingQuerySecurityInformationForUrlUtf16Async( const WCHAR *url,
                                                                                     XAsyncBlock *asyncBlock )
{
    ( void )0;
    return begin_security_information( url, asyncBlock );
}

HRESULT WINAPI XNetworkingImpl::XNetworkingQuerySecurityInformationForUrlUtf16AsyncResultSize(
    XAsyncBlock *asyncBlock, SIZE_T *securityInformationBufferByteCount )
{
    return XNetworkingQuerySecurityInformationForUrlAsyncResultSize( asyncBlock, securityInformationBufferByteCount );
}

HRESULT WINAPI XNetworkingImpl::XNetworkingQuerySecurityInformationForUrlUtf16AsyncResult(
    XAsyncBlock *asyncBlock, SIZE_T securityInformationBufferByteCount, SIZE_T *securityInformationBufferByteCountUsed,
    UINT8 *securityInformationBuffer, XNetworkingSecurityInformation **securityInformation )
{
    return XNetworkingQuerySecurityInformationForUrlAsyncResult( asyncBlock, securityInformationBufferByteCount,
                                                                 securityInformationBufferByteCountUsed,
                                                                 securityInformationBuffer, securityInformation );
}

static BOOL security_pin_matches( PCCERT_CHAIN_CONTEXT chain, const XNetworkingThumbprint *pin )
{
    ALG_ID algorithm;
    DWORD length;
    BYTE digest[32];
    if ( !pin->thumbprintBuffer || pin->thumbprintType < XNetworkingThumbprintType::Leaf ||
         pin->thumbprintType > XNetworkingThumbprintType::Root )
        return FALSE;
    if ( pin->thumbprintBufferByteCount == 20 )
        algorithm = CALG_SHA1;
    else if ( pin->thumbprintBufferByteCount == 32 )
        algorithm = CALG_SHA_256;
    else
        return FALSE;
    for ( DWORD i = 0; i < chain->cChain; ++i )
    {
        PCERT_SIMPLE_CHAIN simple = chain->rgpChain[i];
        DWORD index;
        PCCERT_CONTEXT certificate;
        if ( !simple->cElement ) continue;
        if ( pin->thumbprintType == XNetworkingThumbprintType::Leaf )
            index = 0;
        else if ( pin->thumbprintType == XNetworkingThumbprintType::Root )
            index = simple->cElement - 1;
        else
        {
            if ( simple->cElement < 2 ) continue;
            index = 1;
        }
        certificate = simple->rgpElement[index]->pCertContext;
        length = sizeof( digest );
        if ( CryptHashCertificate( 0, algorithm, 0, certificate->pbCertEncoded, certificate->cbCertEncoded, digest,
                                   &length ) &&
             length == pin->thumbprintBufferByteCount && !memcmp( digest, pin->thumbprintBuffer, length ) )
            return TRUE;
    }
    return FALSE;
}

HRESULT WINAPI XNetworkingImpl::XNetworkingVerifyServerCertificate(
    void *requestHandle, const XNetworkingSecurityInformation *securityInformation )
{
    PCCERT_CONTEXT certificate = NULL;
    PCCERT_CHAIN_CONTEXT chain = NULL;
    CERT_CHAIN_PARA chain_parameters = { sizeof( chain_parameters ) };
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl = { { sizeof( ssl ) }, AUTHTYPE_SERVER, 0, NULL };
    CERT_CHAIN_POLICY_PARA parameters = { sizeof( parameters ), 0, &ssl };
    CERT_CHAIN_POLICY_STATUS status = { sizeof( status ) };
    URL_COMPONENTS components = { sizeof( components ) };
    DWORD flags, length = sizeof( flags );
    WCHAR *url = NULL, *host = NULL;
    BOOL match = FALSE;
    HRESULT hr = HRESULT_FROM_WIN32( ERROR_WINHTTP_SECURE_FAILURE );
    ( void )0;
    if ( !requestHandle || !securityInformation || securityInformation->thumbprintCount > 128 ||
         ( securityInformation->thumbprintCount && !securityInformation->thumbprints ) )
        return E_INVALIDARG;
    /* Never approve an explicitly weakened WinHTTP connection. */
    if ( !WinHttpQueryOption( requestHandle, WINHTTP_OPTION_SECURITY_FLAGS, &flags, &length ) ) goto win32_error;
    if ( flags & ( SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                   SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE ) )
        goto done;
    length = sizeof( certificate );
    if ( !WinHttpQueryOption( requestHandle, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &certificate, &length ) )
        goto win32_error;
    length = 0;
    if ( WinHttpQueryOption( requestHandle, WINHTTP_OPTION_URL, NULL, &length ) ||
         GetLastError() != ERROR_INSUFFICIENT_BUFFER || length > 65536 || !length )
        goto win32_error;
    if ( !( url = static_cast<std::remove_reference_t<decltype( url )>>( malloc( length ) ) ) )
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    if ( !WinHttpQueryOption( requestHandle, WINHTTP_OPTION_URL, url, &length ) ) goto win32_error;
    components.dwHostNameLength = ( DWORD )-1;
    if ( !WinHttpCrackUrl( url, 0, 0, &components ) ) goto win32_error;
    if ( components.nScheme != INTERNET_SCHEME_HTTPS || !components.dwHostNameLength ) goto done;
    if ( !( host = static_cast<std::remove_reference_t<decltype( host )>>(
                malloc( ( components.dwHostNameLength + 1 ) * sizeof( *host ) ) ) ) )
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    memcpy( host, components.lpszHostName, components.dwHostNameLength * sizeof( *host ) );
    host[components.dwHostNameLength] = 0;
    ssl.pwszServerName = host;
    if ( !CertGetCertificateChain( NULL, certificate, NULL, certificate->hCertStore, &chain_parameters, 0, NULL,
                                   &chain ) )
        goto win32_error;
    if ( !CertVerifyCertificateChainPolicy( CERT_CHAIN_POLICY_SSL, chain, &parameters, &status ) ) goto win32_error;
    if ( status.dwError )
    {
        hr = status.dwError;
        goto done;
    }
    if ( securityInformation->thumbprintCount )
    {
        for ( SIZE_T i = 0; i < securityInformation->thumbprintCount; ++i )
            if ( security_pin_matches( chain, &securityInformation->thumbprints[i] ) )
            {
                match = TRUE;
                break;
            }
        if ( !match ) goto done;
    }
    hr = S_OK;
    goto done;
win32_error:
    hr = HRESULT_FROM_WIN32( GetLastError() );
    if ( SUCCEEDED( hr ) ) hr = HRESULT_FROM_WIN32( ERROR_WINHTTP_SECURE_FAILURE );
done:
    if ( chain ) CertFreeCertificateChain( chain );
    if ( certificate ) CertFreeCertificateContext( certificate );
    free( host );
    free( url );
    return hr;
}

HRESULT WINAPI XNetworkingImpl::XNetworkingGetConnectivityHint( XNetworkingConnectivityHint *connectivityHint )
{
    HRESULT hr = nexus::networking::ReadConnectivity( connectivityHint );
    if ( SUCCEEDED( hr ) ) nexus::networking::CapForOfflineIdentity( connectivityHint, nexus::user::offlineIdentityInUse );
    return hr;
}

static HRESULT connectivity_read_hint( XNetworkingConnectivityHint *hint )
{
    return GetNetworkingInterface()->XNetworkingGetConnectivityHint( hint );
}
#include "Networking/ConnectivityEvents.h"

HRESULT WINAPI XNetworkingImpl::XNetworkingRegisterConnectivityHintChanged(
    XTaskQueueHandle queue, void *context, XNetworkingConnectivityHintChangedCallback *callback,
    XTaskQueueRegistrationToken *token )
{
    return connectivity_register( queue, context, callback, token );
}

BOOLEAN WINAPI XNetworkingImpl::XNetworkingUnregisterConnectivityHintChanged( XTaskQueueRegistrationToken token,
                                                                              BOOLEAN wait )
{
    return connectivity_unregister( token, wait );
}

HRESULT WINAPI XNetworkingImpl::XNetworkingQueryConfigurationSetting(
    XNetworkingConfigurationSetting configurationSetting, UINT64 *value )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XNetworkingImpl::XNetworkingSetConfigurationSetting(
    XNetworkingConfigurationSetting configurationParameter, UINT64 value )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XNetworkingImpl::XNetworkingQueryStatistics( XNetworkingStatisticsType statisticsType,
                                                            XNetworkingStatisticsBuffer *statisticsBuffer )
{
    ( void )0;
    return E_NOTIMPL;
}

IXNetworkingImpl2 *GetNetworkingInterface() noexcept
{
    static XNetworkingImpl value;
    return &value;
}
