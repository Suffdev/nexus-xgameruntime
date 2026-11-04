// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include "../private.h"
#include "StaticComObject.h"
#include <xappcapture.h>
class XAppCaptureImpl final
    : public nexus::StaticComObject<IXAppCaptureImpl4, IXAppCaptureImpl3, IXAppCaptureImpl2, IXAppCaptureImpl>
{
public:
    HRESULT WINAPI XAppCaptureTakeDiagnosticScreenshot( BOOLEAN gamescreenOnly,
                                                        XAppCaptureScreenshotFormatFlag captureFlags,
                                                        const char *filenamePrefix,
                                                        XAppCaptureDiagnosticScreenshotResult *result ) override;
    HRESULT WINAPI XAppCaptureRecordDiagnosticClip( INT64 startTime, UINT32 durationInMs, const char *filenamePrefix,
                                                    XAppCaptureRecordClipResult *result ) override;
    HRESULT WINAPI XAppCaptureTakeScreenshot( XUserHandle requestingUser,
                                              XAppCaptureTakeScreenshotResult *result ) override;
    HRESULT WINAPI XAppCaptureOpenScreenshotStream( const char *localId,
                                                    XAppCaptureScreenshotFormatFlag screenshotFormat,
                                                    XAppCaptureScreenshotStreamHandle *handle,
                                                    UINT64 *totalBytes ) override;
    HRESULT WINAPI XAppCaptureReadScreenshotStream( XAppCaptureScreenshotStreamHandle handle, UINT64 startPosition,
                                                    UINT32 bytesToRead, UINT8 *bytes, UINT32 *bytesWritten ) override;
    HRESULT WINAPI XAppCaptureCloseScreenshotStream( XAppCaptureScreenshotStreamHandle handle ) override;
    HRESULT WINAPI XAppCaptureEnableRecord() override;
    HRESULT WINAPI XAppCaptureDisableRecord() override;
    HRESULT WINAPI XAppCaptureGetVideoCaptureSettings( XAppCaptureVideoCaptureSettings *userCaptureSettings ) override;
    HRESULT WINAPI XAppCaptureRecordTimespan( const SYSTEMTIME *startTimestamp, UINT64 durationInMilliseconds,
                                              XAppCaptureLocalResult *result ) override;
    HRESULT WINAPI XAppCaptureReadLocalStream( XAppCaptureLocalStreamHandle handle, SIZE_T startPosition,
                                               UINT32 bytesToRead, UINT8 *bytes, UINT32 *bytesWritten ) override;
    HRESULT WINAPI XAppCaptureCloseLocalStream( XAppCaptureLocalStreamHandle handle ) override;
    HRESULT WINAPI XAppCaptureStartUserRecord( XUserHandle requestingUser, UINT32 localIdBufferLength,
                                               char *localIdBuffer ) override;
    HRESULT WINAPI XAppCaptureStopUserRecord( const char *localId, XAppCaptureUserRecordingResult *result ) override;
    HRESULT WINAPI XAppCaptureCancelUserRecord( const char *localId ) override;
};
IUnknown *GetAppCaptureInterface() noexcept;

class XAppCaptureMetadataImpl final : public nexus::StaticComObject<IXAppCaptureMetadataImpl>
{
public:
    BOOLEAN WINAPI XAppBroadcastIsAppBroadcasting() override;
    HRESULT WINAPI XAppBroadcastShowUI( XUserHandle requestingUser ) override;
    HRESULT WINAPI XAppBroadcastGetStatus( XUserHandle requestingUser,
                                           XAppBroadcastStatus *appBroadcastStatus ) override;
    HRESULT WINAPI XAppBroadcastRegisterIsAppBroadcastingChanged(
        XTaskQueueHandle queue, void *context, XAppBroadcastMonitorCallback *appBroadcastMonitorCallback,
        XTaskQueueRegistrationToken *token ) override;
    BOOLEAN WINAPI XAppBroadcastUnregisterIsAppBroadcastingChanged( XTaskQueueRegistrationToken token,
                                                                    BOOLEAN wait ) override;
    HRESULT WINAPI XAppCaptureMetadataAddStringEvent( const char *name, const char *value,
                                                      XAppCaptureMetadataPriority priority ) override;
    HRESULT WINAPI XAppCaptureMetadataAddInt32Event( const char *name, INT32 value,
                                                     XAppCaptureMetadataPriority priority ) override;
    HRESULT WINAPI XAppCaptureMetadataAddDoubleEvent( const char *name, double value,
                                                      XAppCaptureMetadataPriority priority ) override;
    HRESULT WINAPI XAppCaptureMetadataStartStringState( const char *name, const char *value,
                                                        XAppCaptureMetadataPriority priority ) override;
    HRESULT WINAPI XAppCaptureMetadataStartInt32State( const char *name, INT32 value,
                                                       XAppCaptureMetadataPriority priority ) override;
    HRESULT WINAPI XAppCaptureMetadataStartDoubleState( const char *name, double value,
                                                        XAppCaptureMetadataPriority priority ) override;
    HRESULT WINAPI XAppCaptureMetadataStopState( const char *name ) override;
    HRESULT WINAPI XAppCaptureMetadataStopAllStates() override;
    HRESULT WINAPI XAppCaptureMetadataRemainingStorageBytesAvailable( UINT64 *value ) override;
    HRESULT WINAPI XAppCaptureRegisterMetadataPurged( XTaskQueueHandle queue, void *context,
                                                      XAppCaptureMetadataPurgedCallback *callback,
                                                      XTaskQueueRegistrationToken *token ) override;
    BOOLEAN WINAPI XAppCaptureUnRegisterMetadataPurged( XTaskQueueRegistrationToken token, BOOLEAN wait ) override;
};
IUnknown *GetAppCaptureMetadataInterface() noexcept;
