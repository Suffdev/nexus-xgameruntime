// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include "../../private.h"
#include <atomic>
#include <cstdlib>

// An internal protocol dependency, not an exported runtime hook. The default
// implementation always uses the actual local backend and Microsoft transport.
class UserTransport
{
public:
    virtual ~UserTransport() = default;
    virtual void WaitForSignInRetry( DWORD milliseconds ) noexcept
    {
        Sleep( milliseconds );
    }
    virtual HRESULT Backend( UINT16 type, const char *body, UINT16 size, char **response, UINT16 *responseSize ) = 0;
    virtual HRESULT Http( const WCHAR *method, const WCHAR *url, char *body, const WCHAR *headers, const WCHAR **accept,
                          BYTE **response, SIZE_T *responseSize ) = 0;
    virtual HRESULT HttpRaw( const WCHAR *method, const WCHAR *url, const WCHAR *headers, const void *body,
                             DWORD bodySize, DWORD *status, BYTE **response, SIZE_T *responseSize ) = 0;
    // Appended private slot preserves existing transport methods. Legacy custom
    // calls cannot be interrupted: their worker retains ownership until return.
    // Returned buffers use the same malloc/free contract as Backend.
    virtual HRESULT BackendCancellable( UINT16 type, const char *body, UINT16 size, char **response,
                                        UINT16 *responseSize, const std::atomic<bool> &cancel )
    {
        if ( !response || !responseSize ) return E_INVALIDARG;
        *response = nullptr; *responseSize = 0;
        if ( cancel.load( std::memory_order_acquire ) ) return E_ABORT;
        HRESULT hr = Backend( type, body, size, response, responseSize );
        if ( cancel.load( std::memory_order_acquire ) ) hr = E_ABORT;
        if ( FAILED( hr ) ) { free( *response ); *response = nullptr; *responseSize = 0; }
        return hr;
    }
    // As with BackendCancellable, the compatibility fallback cannot interrupt
    // an existing custom transport's synchronous call or release its inputs early.
    virtual HRESULT HttpCancellable( const WCHAR *method, const WCHAR *url, char *body, const WCHAR *headers,
                                     const WCHAR **accept, BYTE **response, SIZE_T *responseSize,
                                     const std::atomic<bool> &cancel )
    {
        if ( !response || !responseSize ) return E_INVALIDARG;
        *response = nullptr; *responseSize = 0;
        if ( cancel.load( std::memory_order_acquire ) ) return E_ABORT;
        HRESULT hr = Http( method, url, body, headers, accept, response, responseSize );
        if ( cancel.load( std::memory_order_acquire ) ) hr = E_ABORT;
        if ( FAILED( hr ) ) { free( *response ); *response = nullptr; *responseSize = 0; }
        return hr;
    }

};

UserTransport &GetUserTransport() noexcept;
