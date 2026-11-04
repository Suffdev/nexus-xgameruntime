// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <atomic>
#include <windows.h>
#include <winhttp.h>

/* Private, versioned Wine/XGR contract. The abort operation preserves the
 * public HINTERNET; only its owner closes it, after joining this monitor.
 * This avoids numeric-handle reuse between synchronous WinHTTP API calls. */
class HttpCancellationMonitor
{
    using AbortRequest = BOOL (WINAPI *)( HINTERNET );
    const std::atomic<bool> *cancel = nullptr;
    AbortRequest abort = nullptr;
    HINTERNET request = nullptr;
    HANDLE stop = nullptr;
    HANDLE thread = nullptr;

    static DWORD WINAPI run( void *context )
    {
        auto self = static_cast<HttpCancellationMonitor *>( context );
        while ( WaitForSingleObject( self->stop, 25 ) == WAIT_TIMEOUT )
        {
            if ( self->cancel->load( std::memory_order_acquire ) )
            {
                self->abort( self->request );
                break;
            }
        }
        return 0;
    }

public:
    HttpCancellationMonitor() = default;
    HttpCancellationMonitor( const HttpCancellationMonitor & ) = delete;
    HttpCancellationMonitor &operator=( const HttpCancellationMonitor & ) = delete;
    ~HttpCancellationMonitor() { join(); }

    HRESULT start( HINTERNET handle, const std::atomic<bool> *token )
    {
        if ( !token ) return S_OK;
        auto module = GetModuleHandleW( L"winhttp.dll" );
        abort = reinterpret_cast<AbortRequest>( GetProcAddress( module, "__wine_winhttp_cancel_request_v1" ) );
        if ( !abort )
        {
            /* Older Wine and native Windows keep the existing cooperative
             * cancellation path. No in-flight interruption is promised there. */
            WARN( "WinHTTP in-flight cancellation is unavailable; using cooperative cancellation.\n" );
            return S_OK;
        }
        cancel = token;
        request = handle;
        if ( !( stop = CreateEventW( nullptr, TRUE, FALSE, nullptr ) ) ) return HRESULT_FROM_WIN32( GetLastError() );
        if ( !( thread = CreateThread( nullptr, 0, run, this, 0, nullptr ) ) )
        {
            HRESULT hr = HRESULT_FROM_WIN32( GetLastError() );
            CloseHandle( stop );
            stop = nullptr;
            return hr;
        }
        return S_OK;
    }

    void join()
    {
        if ( !thread ) return;
        SetEvent( stop );
        WaitForSingleObject( thread, INFINITE );
        CloseHandle( thread );
        CloseHandle( stop );
        thread = stop = nullptr;
    }
};
