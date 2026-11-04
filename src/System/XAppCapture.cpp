/*
 * Xbox Game runtime Library
 *  GDK Component: System API -> XAppCapture
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

#include "XAppCapture.h"

HRESULT WINAPI XAppCaptureImpl::XAppCaptureTakeDiagnosticScreenshot( BOOLEAN gamescreenOnly,
                                                                     XAppCaptureScreenshotFormatFlag captureFlags,
                                                                     const char *filenamePrefix,
                                                                     XAppCaptureDiagnosticScreenshotResult *result )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureImpl::XAppCaptureRecordDiagnosticClip( INT64 startTime, UINT32 durationInMs,
                                                                 const char *filenamePrefix,
                                                                 XAppCaptureRecordClipResult *result )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureImpl::XAppCaptureTakeScreenshot( XUserHandle requestingUser,
                                                           XAppCaptureTakeScreenshotResult *result )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureImpl::XAppCaptureOpenScreenshotStream( const char *localId,
                                                                 XAppCaptureScreenshotFormatFlag screenshotFormat,
                                                                 XAppCaptureScreenshotStreamHandle *handle,
                                                                 UINT64 *totalBytes )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureImpl::XAppCaptureReadScreenshotStream( XAppCaptureScreenshotStreamHandle handle,
                                                                 UINT64 startPosition, UINT32 bytesToRead, UINT8 *bytes,
                                                                 UINT32 *bytesWritten )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureImpl::XAppCaptureCloseScreenshotStream( XAppCaptureScreenshotStreamHandle handle )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureImpl::XAppCaptureEnableRecord()
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureImpl::XAppCaptureDisableRecord()
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI
XAppCaptureImpl::XAppCaptureGetVideoCaptureSettings( XAppCaptureVideoCaptureSettings *userCaptureSettings )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureImpl::XAppCaptureRecordTimespan( const SYSTEMTIME *startTimestamp,
                                                           UINT64 durationInMilliseconds,
                                                           XAppCaptureLocalResult *result )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureImpl::XAppCaptureReadLocalStream( XAppCaptureLocalStreamHandle handle, SIZE_T startPosition,
                                                            UINT32 bytesToRead, UINT8 *bytes, UINT32 *bytesWritten )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureImpl::XAppCaptureCloseLocalStream( XAppCaptureLocalStreamHandle handle )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureImpl::XAppCaptureStartUserRecord( XUserHandle requestingUser, UINT32 localIdBufferLength,
                                                            char *localIdBuffer )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureImpl::XAppCaptureStopUserRecord( const char *localId, XAppCaptureUserRecordingResult *result )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureImpl::XAppCaptureCancelUserRecord( const char *localId )
{
    ( void )0;
    return E_NOTIMPL;
}

BOOLEAN WINAPI XAppCaptureMetadataImpl::XAppBroadcastIsAppBroadcasting()
{
    ( void )0;
    return FALSE;
}

HRESULT WINAPI XAppCaptureMetadataImpl::XAppBroadcastShowUI( XUserHandle requestingUser )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureMetadataImpl::XAppBroadcastGetStatus( XUserHandle requestingUser,
                                                                XAppBroadcastStatus *appBroadcastStatus )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureMetadataImpl::XAppBroadcastRegisterIsAppBroadcastingChanged(
    XTaskQueueHandle queue, void *context, XAppBroadcastMonitorCallback *appBroadcastMonitorCallback,
    XTaskQueueRegistrationToken *token )
{
    ( void )0;
    return E_NOTIMPL;
}

BOOLEAN WINAPI XAppCaptureMetadataImpl::XAppBroadcastUnregisterIsAppBroadcastingChanged(
    XTaskQueueRegistrationToken token, BOOLEAN wait )
{
    ( void )0;
    return TRUE;
}

HRESULT WINAPI XAppCaptureMetadataImpl::XAppCaptureMetadataAddStringEvent( const char *name, const char *value,
                                                                           XAppCaptureMetadataPriority priority )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureMetadataImpl::XAppCaptureMetadataAddInt32Event( const char *name, INT32 value,
                                                                          XAppCaptureMetadataPriority priority )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureMetadataImpl::XAppCaptureMetadataAddDoubleEvent( const char *name, double value,
                                                                           XAppCaptureMetadataPriority priority )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureMetadataImpl::XAppCaptureMetadataStartStringState( const char *name, const char *value,
                                                                             XAppCaptureMetadataPriority priority )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureMetadataImpl::XAppCaptureMetadataStartInt32State( const char *name, INT32 value,
                                                                            XAppCaptureMetadataPriority priority )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureMetadataImpl::XAppCaptureMetadataStartDoubleState( const char *name, double value,
                                                                             XAppCaptureMetadataPriority priority )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureMetadataImpl::XAppCaptureMetadataStopState( const char *name )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureMetadataImpl::XAppCaptureMetadataStopAllStates()
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureMetadataImpl::XAppCaptureMetadataRemainingStorageBytesAvailable( UINT64 *value )
{
    ( void )0;
    return E_NOTIMPL;
}

HRESULT WINAPI XAppCaptureMetadataImpl::XAppCaptureRegisterMetadataPurged( XTaskQueueHandle queue, void *context,
                                                                           XAppCaptureMetadataPurgedCallback *callback,
                                                                           XTaskQueueRegistrationToken *token )
{
    ( void )0;
    return E_NOTIMPL;
}

BOOLEAN WINAPI XAppCaptureMetadataImpl::XAppCaptureUnRegisterMetadataPurged( XTaskQueueRegistrationToken token,
                                                                             BOOLEAN wait )
{
    ( void )0;
    return TRUE;
}

IUnknown *GetAppCaptureInterface() noexcept
{
    static XAppCaptureImpl value;
    return &value;
}

IUnknown *GetAppCaptureMetadataInterface() noexcept
{
    static XAppCaptureMetadataImpl value;
    return &value;
}
