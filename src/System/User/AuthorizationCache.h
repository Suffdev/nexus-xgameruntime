// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::user
{
// XSTS NotAfter is UTC ISO 8601. Ignore fractional seconds conservatively,
// but never infer a lifetime from a missing or malformed server timestamp.
inline UINT64 AuthorizationExpiry( std::wstring_view text ) noexcept
{
    if ( text.size() < 20 || text[4] != '-' || text[7] != '-' || text[10] != 'T' || text[13] != ':' ||
         text[16] != ':' || text.back() != 'Z' ) return 0;
    if ( text.size() != 20 )
    {
        if ( text.size() < 22 || text.size() > 29 || text[19] != '.' ) return 0;
        for ( size_t i = 20; i + 1 < text.size(); ++i ) if ( text[i] < '0' || text[i] > '9' ) return 0;
    }
    auto number = [&]( size_t start, size_t length ) -> WORD {
        WORD result = 0;
        for ( size_t i = start; i < start + length; ++i )
        {
            if ( text[i] < '0' || text[i] > '9' ) return 0xffff;
            result = result * 10 + text[i] - '0';
        }
        return result;
    };
    SYSTEMTIME time{};
    time.wYear = number( 0, 4 ); time.wMonth = number( 5, 2 ); time.wDay = number( 8, 2 );
    time.wHour = number( 11, 2 ); time.wMinute = number( 14, 2 ); time.wSecond = number( 17, 2 );
    FILETIME file{};
    SYSTEMTIME roundtrip{};
    if ( !SystemTimeToFileTime( &time, &file ) || !FileTimeToSystemTime( &file, &roundtrip ) ||
         time.wYear != roundtrip.wYear || time.wMonth != roundtrip.wMonth || time.wDay != roundtrip.wDay ||
         time.wHour != roundtrip.wHour || time.wMinute != roundtrip.wMinute || time.wSecond != roundtrip.wSecond ) return 0;
    return ( UINT64( file.dwHighDateTime ) << 32 ) | file.dwLowDateTime;
}

struct AuthorizationClock
{
    struct Time { UINT64 wall, tick; };
    Time operator()() const noexcept
    {
        FILETIME now{};
        GetSystemTimeAsFileTime( &now );
        return { ( UINT64( now.dwHighDateTime ) << 32 ) | now.dwLowDateTime, GetTickCount64() };
    }
};

// Owned by exactly one signed-in XUser, whose credentials are immutable after
// initialization. Reset before replacing those credentials. This caches only
// ordinary title-bound authorization, never privilege/presence claims or signatures.
class AuthorizationCache
{
    struct Entry
    {
        std::string audience, token;
        UINT64 expires{}, wall{}, tick{}, used{};
        HRESULT result{ E_PENDING };
        bool done{}, invalid{};
    };
    std::mutex mutex;
    std::condition_variable changed;
    std::vector<std::shared_ptr<Entry>> entries;
    UINT64 sequence{}, generation{};
    static constexpr size_t capacity = 32;
    static constexpr UINT64 skew = 60ull * 10000000;
    static constexpr UINT64 maxAge = 10 * 60 * 1000;
    static bool Fresh( const Entry &entry, AuthorizationClock::Time now ) noexcept
    {
        return SUCCEEDED( entry.result ) && entry.done && !entry.invalid && entry.expires > skew &&
               now.wall >= entry.wall && now.wall < entry.expires - skew && now.tick >= entry.tick &&
               now.tick - entry.tick < maxAge;
    }
public:
    void Clear() noexcept
    {
        std::lock_guard<std::mutex> lock( mutex );
        for ( auto &entry : entries ) entry->invalid = true;
        entries.clear();
        ++generation;
        changed.notify_all();
    }

    template<typename Fetch, typename Clock = AuthorizationClock>
    HRESULT Get( const char *audience, bool force, const std::atomic<bool> &cancelled, Fetch fetch,
                 std::string &token, Clock clock = {} ) noexcept
    {
        token.clear();
        try
        {
            std::unique_lock<std::mutex> lock( mutex );
            if ( cancelled ) return E_ABORT;
            if ( force ) ++generation;
            auto found = std::find_if( entries.begin(), entries.end(), [&]( const auto &e ) { return e->audience == audience; } );
            if ( found != entries.end() && force )
            {
                // A 401-driven refresh must not join or accept an older request.
                ( *found )->invalid = true;
                entries.erase( found );
                found = entries.end();
                changed.notify_all();
            }
            if ( found != entries.end() )
            {
                auto entry = *found;
                if ( !entry->done )
                {
                    const auto start = GetTickCount64();
                    while ( !entry->done && !entry->invalid && !cancelled )
                    {
                        if ( GetTickCount64() - start >= 120000 ) return HRESULT_FROM_WIN32( ERROR_TIMEOUT );
                        changed.wait_for( lock, std::chrono::milliseconds( 50 ) );
                    }
                    if ( cancelled || entry->invalid ) return E_ABORT;
                    if ( SUCCEEDED( entry->result ) && entry->expires && !Fresh( *entry, clock() ) )
                        return HRESULT_FROM_WIN32( ERROR_RETRY );
                    if ( SUCCEEDED( entry->result ) ) token = entry->token;
                    return entry->result;
                }
                if ( Fresh( *entry, clock() ) )
                {
                    entry->used = ++sequence;
                    token = entry->token;
                    return S_OK;
                }
                entries.erase( found );
            }
            if ( entries.size() == capacity )
            {
                auto oldest = entries.end();
                for ( auto i = entries.begin(); i != entries.end(); ++i )
                    if ( ( *i )->done && ( oldest == entries.end() || ( *i )->used < ( *oldest )->used ) ) oldest = i;
                if ( oldest != entries.end() ) entries.erase( oldest );
            }
            // Saturated by distinct requests: retain no additional cache entry.
            if ( entries.size() == capacity )
            {
                const auto started = generation;
                lock.unlock();
                UINT64 expires = 0;
                HRESULT hr = fetch( token, expires );
                lock.lock();
                if ( cancelled || started != generation ) { token.clear(); return E_ABORT; }
                if ( FAILED( hr ) ) token.clear();
                return hr;
            }
            auto entry = std::make_shared<Entry>();
            entry->audience = audience;
            entry->used = ++sequence;
            entries.push_back( entry );
            lock.unlock();
            HRESULT hr;
            try { hr = fetch( entry->token, entry->expires ); }
            catch ( const std::bad_alloc & ) { hr = E_OUTOFMEMORY; }
            catch ( ... ) { hr = E_FAIL; }
            lock.lock();
            if ( cancelled || entry->invalid ) hr = E_ABORT;
            if ( FAILED( hr ) ) entry->token.clear();
            const auto now = clock();
            entry->wall = now.wall; entry->tick = now.tick; entry->result = hr; entry->done = true;
            if ( !Fresh( *entry, now ) || entry->token.size() > 1024 * 1024 )
                entries.erase( std::remove( entries.begin(), entries.end(), entry ), entries.end() );
            changed.notify_all();
            if ( SUCCEEDED( hr ) ) token = entry->token;
            return hr;
        }
        catch ( const std::bad_alloc & ) { return E_OUTOFMEMORY; }
        catch ( ... ) { return E_FAIL; }
    }
};
}
