// SPDX-License-Identifier: MIT
#ifndef __WINESRC__
#define __WINESRC__
#endif
#include <cstddef>
#include <type_traits>
#include <xgamesave.h>
#include <xappcapture.h>

// Microsoft GDK uses the default signed 64-bit MSVC time_t ABI. Do not use
// the build host's CRT time_t: MinGW i686 can legitimately keep that at 32 bits.
// https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/xgamesave/structs/xgamesavecontainerinfo
// https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/xappcapture/structs/xappcapturerecordclipresult
// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/time-time32-time64
static_assert( sizeof( XGameSaveContainerInfo::lastModifiedTime ) == 8 );
static_assert( std::is_signed_v<decltype( XGameSaveContainerInfo::lastModifiedTime )> );
static_assert( sizeof( XAppCaptureRecordClipResult::startTime ) == 8 );
static_assert( std::is_signed_v<decltype( XAppCaptureRecordClipResult::startTime )> );
static_assert( offsetof( XGameSaveContainerInfo, totalSize ) == ( sizeof( void * ) == 8 ? 24 : 16 ) );
static_assert( offsetof( XGameSaveContainerInfo, lastModifiedTime ) == ( sizeof( void * ) == 8 ? 32 : 24 ) );
static_assert( offsetof( XGameSaveContainerInfo, needsSync ) == ( sizeof( void * ) == 8 ? 40 : 32 ) );
static_assert( sizeof( XGameSaveContainerInfo ) == ( sizeof( void * ) == 8 ? 48 : 40 ) );
static_assert( offsetof( XAppCaptureRecordClipResult, startTime ) == ( sizeof( void * ) == 8 ? 272 : 264 ) );
static_assert( offsetof( XAppCaptureRecordClipResult, durationInMs ) == ( sizeof( void * ) == 8 ? 280 : 272 ) );
static_assert( sizeof( XAppCaptureRecordClipResult ) == ( sizeof( void * ) == 8 ? 296 : 288 ) );

// Independent fixed-width caller contract includes the x86 stdcall stack width.
using CaptureRecordClip = HRESULT ( WINAPI IXAppCaptureImpl::* )( INT64, UINT32, const char *,
                                                                XAppCaptureRecordClipResult * );
static_assert( std::is_same_v<decltype( &IXAppCaptureImpl::XAppCaptureRecordDiagnosticClip ), CaptureRecordClip> );

// This API projection must preserve a post-2038 timestamp and the next member.
constexpr auto futureSave = [] {
    XGameSaveContainerInfo value{};
    value.lastModifiedTime = 4102444800LL; // 2100-01-01 UTC
    value.needsSync = TRUE;
    return value;
}();
static_assert( futureSave.lastModifiedTime == 4102444800LL && futureSave.needsSync == TRUE );
constexpr auto futureCapture = [] {
    XAppCaptureRecordClipResult value{};
    value.startTime = 4102444800LL;
    value.durationInMs = 1234;
    return value;
}();
static_assert( futureCapture.startTime == 4102444800LL && futureCapture.durationInMs == 1234 );
