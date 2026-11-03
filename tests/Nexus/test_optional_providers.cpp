// SPDX-License-Identifier: LGPL-2.1-or-later
#include "../test_fixtures.h"
#include <windows.h>
#include <inspectable.h>
#include <xaccessibility.h>
#include <xappcapture.h>
#include <xdisplay.h>
#include <xerror.h>
#include <xgameactivation.h>
#include <xgameevent.h>
#include <xgameinvite.h>
#include <xgameprotocol.h>
#include <xgameruntimefeature.h>
#include <xgamestreaming.h>
#include <xgameui.h>
#include <xgameerr.h>
#include <atomic>
#include <thread>

namespace
{
class Module
{
public:
    Module() : module_( LoadLibraryW( L"xgameruntime.dll" ) )
    {
        EXPECT_NE( module_, nullptr );
        if ( module_ ) query_ = reinterpret_cast<QueryFunction>( GetProcAddress( module_, "QueryApiImpl" ) );
        EXPECT_NE( query_, nullptr );
    }
    ~Module()
    {
        if ( module_ ) FreeLibrary( module_ );
    }
    HRESULT Query( REFCLSID clsid, REFIID iid, void **out )
    {
        return query_ ? query_( clsid, iid, out ) : E_FAIL;
    }
    IUnknown *Query( REFCLSID clsid, REFIID iid )
    {
        void *result = nullptr;
        EXPECT_EQ( Query( clsid, iid, &result ), S_OK );
        return static_cast<IUnknown *>( result );
    }

private:
    using QueryFunction = HRESULT( WINAPI * )( REFCLSID, REFIID, void ** );
    HMODULE module_{};
    QueryFunction query_{};
};
template<class Interface> void CheckInterface( Module &module, REFCLSID clsid )
{
    auto object = module.Query( clsid, __uuidof( Interface ) );
    ASSERT_NE( object, nullptr );
    auto before = object->AddRef();
    object->Release();
    for ( unsigned i = 0; i < 8; ++i )
    {
        auto again = module.Query( clsid, __uuidof( Interface ) );
        ASSERT_EQ( again, object );
        again->Release();
    }
    auto after = object->AddRef();
    object->Release();
    EXPECT_EQ( before, after );
    EXPECT_EQ( module.Query( clsid, __uuidof( Interface ), nullptr ), E_POINTER );
    EXPECT_EQ( object->QueryInterface( __uuidof( IUnknown ), nullptr ), E_POINTER );
    void *output = reinterpret_cast<void *>( 1 );
    EXPECT_EQ( object->QueryInterface( __uuidof( IInspectable ), &output ), E_NOINTERFACE );
    EXPECT_EQ( output, nullptr );
    IUnknown *identity = nullptr;
    ASSERT_EQ( object->QueryInterface( __uuidof( IUnknown ), reinterpret_cast<void **>( &identity ) ), S_OK );
    void *roundtrip = nullptr;
    ASSERT_EQ( identity->QueryInterface( __uuidof( Interface ), &roundtrip ), S_OK );
    EXPECT_EQ( roundtrip, object );
    static_cast<Interface *>( roundtrip )->Release();
    identity->Release();
    object->Release();
}
}

TEST( NexusOptional, EveryVersionReturnsOwnedActualCppInterfaces )
{
    Module module;
    CheckInterface<IXAccessibilityImpl>( module, CLSID_XAccessibilityImpl );
    CheckInterface<IXAccessibilityImpl2>( module, CLSID_XAccessibilityImpl );
    CheckInterface<IXAppCaptureImpl>( module, CLSID_XAppCaptureImpl );
    CheckInterface<IXAppCaptureImpl2>( module, CLSID_XAppCaptureImpl );
    CheckInterface<IXAppCaptureImpl3>( module, CLSID_XAppCaptureImpl );
    CheckInterface<IXAppCaptureImpl4>( module, CLSID_XAppCaptureImpl );
    CheckInterface<IXAppCaptureMetadataImpl>( module, CLSID_XAppCaptureMetadataImpl );
    CheckInterface<IXErrorImpl>( module, CLSID_XErrorImpl );
    CheckInterface<IXDisplayImpl>( module, CLSID_XDisplayImpl );
    CheckInterface<IXLauncherImpl>( module, CLSID_XLauncherImpl );
    CheckInterface<IXGameActivationImpl>( module, CLSID_XGameActivationImpl );
    CheckInterface<IXGameEventImpl>( module, CLSID_XGameEventImpl );
    CheckInterface<IXGameInviteImpl>( module, CLSID_XGameInviteImpl );
    CheckInterface<IXGameInviteImpl2>( module, CLSID_XGameInviteImpl );
    CheckInterface<IXGameProtocolImpl>( module, CLSID_XGameProtocolImpl );
    CheckInterface<IXGameRuntimeFeatureImpl>( module, CLSID_XGameRuntimeFeatureImpl );
    CheckInterface<IXGameStreamingImpl>( module, CLSID_XGameStreamingImpl );
    CheckInterface<IXGameStreamingImpl2>( module, CLSID_XGameStreamingImpl );
    CheckInterface<IXGameStreamingImpl3>( module, CLSID_XGameStreamingImpl );
    CheckInterface<IXGameUiImpl>( module, CLSID_XGameUiImpl );
    CheckInterface<IXGameUiImpl2>( module, CLSID_XGameUiImpl );
    CheckInterface<IXGameUiImpl3>( module, CLSID_XGameUiImpl );
    CheckInterface<IXGameUiImpl4>( module, CLSID_XGameUiImpl );
}

TEST( NexusOptional, DisplayAndLauncherShareCanonicalIUnknown )
{
    Module module;
    auto display = module.Query( CLSID_XDisplayImpl, __uuidof( IXDisplayImpl ) );
    auto launcher = module.Query( CLSID_XLauncherImpl, __uuidof( IXLauncherImpl ) );
    ASSERT_NE( display, nullptr );
    ASSERT_NE( launcher, nullptr );
    IUnknown *a = nullptr, *b = nullptr;
    ASSERT_EQ( display->QueryInterface( __uuidof( IUnknown ), reinterpret_cast<void **>( &a ) ), S_OK );
    ASSERT_EQ( launcher->QueryInterface( __uuidof( IUnknown ), reinterpret_cast<void **>( &b ) ), S_OK );
    EXPECT_EQ( a, b );
    IXLauncherImpl *other = nullptr;
    ASSERT_EQ( a->QueryInterface( __uuidof( IXLauncherImpl ), reinterpret_cast<void **>( &other ) ), S_OK );
    EXPECT_EQ( other, static_cast<IXLauncherImpl *>( launcher ) );
    XDisplayTimeoutDeferralHandle handle = reinterpret_cast<XDisplayTimeoutDeferralHandle>( 1 );
    EXPECT_EQ( other->XDisplayAcquireTimeoutDeferral( &handle ), E_NOTIMPL );
    EXPECT_EQ( handle, nullptr );
    EXPECT_EQ( other->XDisplayAcquireTimeoutDeferral( nullptr ), E_POINTER );
    EXPECT_EQ( other->XLaunchUri( nullptr, "https://invalid.example/" ), E_NOTIMPL );
    XDisplayHdrModeInfo info{ 1, 2, 3 };
    EXPECT_EQ( static_cast<IXDisplayImpl *>( display )->XDisplayTryEnableHdrMode( XDisplayHdrModePreference::PreferHdr,
                                                                                  &info ),
               XDisplayHdrModeResult::Unknown );
    EXPECT_EQ( info.minToneMapLuminance, 0 );
    EXPECT_EQ( info.maxToneMapLuminance, 0 );
    other->Release();
    a->Release();
    b->Release();
    display->Release();
    launcher->Release();
}

TEST( NexusOptional, FeatureQueryNeverAdvertisesStubOnlyOrUnknownFamilies )
{
    Module module;
    auto object = module.Query( CLSID_XGameRuntimeFeatureImpl, __uuidof( IXGameRuntimeFeatureImpl ) );
    ASSERT_NE( object, nullptr );
    auto api = static_cast<IXGameRuntimeFeatureImpl *>( object );
    const bool expected[] = { false, false, true,  true, false, true, false, true, false, false, true,
                              true,  true,  false, true, true,  true, true,  true, false, false, false };
    for ( unsigned i = 0; i < sizeof( expected ) / sizeof( expected[0] ); ++i )
        EXPECT_EQ( !!api->XGameRuntimeIsFeatureAvailable( static_cast<XGameRuntimeFeature>( i ) ), expected[i] ) << i;
    EXPECT_FALSE( api->XGameRuntimeIsFeatureAvailable( static_cast<XGameRuntimeFeature>( 0xffffffff ) ) );
    EXPECT_FALSE( api->XGameRuntimeIsFeatureAvailable( static_cast<XGameRuntimeFeature>( 22 ) ) );
    api->Release();
}

static void WINAPI Activation( void *, const XGameActivationInfo * )
{
    ADD_FAILURE() << "No activation source exists";
}
static void WINAPI Invite( void *, const char * )
{
    ADD_FAILURE() << "No invite source exists";
}
static void WINAPI Protocol( void *, const char * )
{
    ADD_FAILURE() << "No protocol source exists";
}

TEST( NexusOptional, UnsupportedEventsNeverReturnInventedRegistrationTokens )
{
    Module module;
    auto activation = static_cast<IXGameActivationImpl *>(
        module.Query( CLSID_XGameActivationImpl, __uuidof( IXGameActivationImpl ) ) );
    auto invite =
        static_cast<IXGameInviteImpl2 *>( module.Query( CLSID_XGameInviteImpl, __uuidof( IXGameInviteImpl2 ) ) );
    auto protocol =
        static_cast<IXGameProtocolImpl *>( module.Query( CLSID_XGameProtocolImpl, __uuidof( IXGameProtocolImpl ) ) );
    ASSERT_NE( activation, nullptr );
    ASSERT_NE( invite, nullptr );
    ASSERT_NE( protocol, nullptr );
    XTaskQueueRegistrationToken token{ 123 };
    EXPECT_EQ( activation->XGameActivationRegisterForEvent( nullptr, nullptr, Activation, &token ), E_NOTIMPL );
    EXPECT_EQ( token.token, 0 );
    token.token = 123;
    EXPECT_EQ( activation->XGameActivationRegisterForEvent( nullptr, nullptr, nullptr, &token ), E_INVALIDARG );
    EXPECT_EQ( token.token, 0 );
    token.token = 123;
    EXPECT_EQ( invite->XGameInviteRegisterForEvent( nullptr, nullptr, Invite, &token ), E_NOTIMPL );
    EXPECT_EQ( token.token, 0 );
    token.token = 123;
    EXPECT_EQ( invite->XGameInviteRegisterForPendingEvent( nullptr, nullptr, Invite, &token ), E_NOTIMPL );
    EXPECT_EQ( token.token, 0 );
    token.token = 123;
    EXPECT_EQ( protocol->XGameProtocolRegisterForActivation( nullptr, nullptr, Protocol, &token ), E_NOTIMPL );
    EXPECT_EQ( token.token, 0 );
    EXPECT_FALSE( activation->XGameActivationUnregisterForEvent( token, FALSE ) );
    EXPECT_FALSE( invite->XGameInviteUnregisterForEvent( token, FALSE ) );
    EXPECT_FALSE( invite->XGameInviteUnregisterForPendingEvent( token, FALSE ) );
    EXPECT_FALSE( protocol->XGameProtocolUnregisterForActivation( token, FALSE ) );
    activation->Release();
    invite->Release();
    protocol->Release();
}

TEST( NexusOptionalAbi, IXAccessibilityImpl2OriginalSlotsRemainCallable )
{
    Module module;
    auto object = module.Query( CLSID_XAccessibilityImpl, __uuidof( IXAccessibilityImpl2 ) );
    ASSERT_NE( object, nullptr );
    auto table = *reinterpret_cast<void ***>( object );
    {
        // Frozen original C table slot 3: x_accessibility_XClosedCaptionGetProperties
        using Function = HRESULT( WINAPI * )( void *self, XClosedCaptionProperties *properties );
        auto call = reinterpret_cast<Function>( table[3] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 4: x_accessibility_XClosedCaptionSetEnabled
        using Function = HRESULT( WINAPI * )( void *self, BOOLEAN enabled );
        auto call = reinterpret_cast<Function>( table[4] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 5: x_accessibility_XHighContrastGetMode
        using Function = HRESULT( WINAPI * )( void *self, XHighContrastMode *mode );
        auto call = reinterpret_cast<Function>( table[5] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 6: x_accessibility_XSpeechToTextSetPositionHint
        using Function = HRESULT( WINAPI * )( void *self, XSpeechToTextPositionHint position );
        auto call = reinterpret_cast<Function>( table[6] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 7: x_accessibility_XSpeechToTextSendString
        using Function =
            HRESULT( WINAPI * )( void *self, const char *speakerName, const char *content, XSpeechToTextType type );
        auto call = reinterpret_cast<Function>( table[7] );
        EXPECT_EQ( call( object, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 8: x_accessibility_XSpeechSynthesizerEnumerateInstalledVoices
        using Function =
            HRESULT( WINAPI * )( void *self, void *context, XSpeechSynthesizerInstalledVoicesCallback *callback );
        auto call = reinterpret_cast<Function>( table[8] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 9: x_accessibility_XSpeechSynthesizerCreate
        using Function = HRESULT( WINAPI * )( void *self, XSpeechSynthesizerHandle *speechSynthesizer );
        auto call = reinterpret_cast<Function>( table[9] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 10: x_accessibility_XSpeechSynthesizerCloseHandle
        using Function = HRESULT( WINAPI * )( void *self, XSpeechSynthesizerHandle speechSynthesizer );
        auto call = reinterpret_cast<Function>( table[10] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 11: x_accessibility_XSpeechSynthesizerSetDefaultVoice
        using Function = HRESULT( WINAPI * )( void *self, XSpeechSynthesizerHandle speechSynthesizer );
        auto call = reinterpret_cast<Function>( table[11] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 12: x_accessibility_XSpeechSynthesizerSetCustomVoice
        using Function =
            HRESULT( WINAPI * )( void *self, XSpeechSynthesizerHandle speechSynthesizer, const char *voiceId );
        auto call = reinterpret_cast<Function>( table[12] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 13: x_accessibility_XSpeechSynthesizerCreateStreamFromText
        using Function = HRESULT( WINAPI * )( void *self, XSpeechSynthesizerHandle speechSynthesizer, const char *text,
                                              XSpeechSynthesizerStreamHandle *speechSynthesisStream );
        auto call = reinterpret_cast<Function>( table[13] );
        EXPECT_EQ( call( object, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 14: x_accessibility_XSpeechSynthesizerCloseStreamHandle
        using Function = HRESULT( WINAPI * )( void *self, XSpeechSynthesizerStreamHandle speechSynthesisStream );
        auto call = reinterpret_cast<Function>( table[14] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 15: x_accessibility_XSpeechSynthesizerGetStreamDataSize
        using Function =
            HRESULT( WINAPI * )( void *self, XSpeechSynthesizerStreamHandle speechSynthesisStream, SIZE_T *bufferSize );
        auto call = reinterpret_cast<Function>( table[15] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 16: x_accessibility_XSpeechSynthesizerGetStreamData
        using Function = HRESULT( WINAPI * )( void *self, XSpeechSynthesizerStreamHandle speechSynthesisStream,
                                              SIZE_T bufferSize, void *buffer, SIZE_T *bufferUsed );
        auto call = reinterpret_cast<Function>( table[16] );
        EXPECT_EQ( call( object, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 17: x_accessibility_XSpeechToTextBeginHypothesisString
        using Function = HRESULT( WINAPI * )( void *self, const char *speakerName, const char *content,
                                              XSpeechToTextType type, UINT32 *hypothesisId );
        auto call = reinterpret_cast<Function>( table[17] );
        EXPECT_EQ( call( object, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 18: x_accessibility_XSpeechToTextUpdateHypothesisString
        using Function = HRESULT( WINAPI * )( void *self, UINT32 hypothesisId, const char *content );
        auto call = reinterpret_cast<Function>( table[18] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 19: x_accessibility_XSpeechToTextFinalizeHypothesisString
        using Function = HRESULT( WINAPI * )( void *self, UINT32 hypothesisId, const char *content );
        auto call = reinterpret_cast<Function>( table[19] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 20: x_accessibility_XSpeechToTextCancelHypothesisString
        using Function = HRESULT( WINAPI * )( void *self, UINT32 hypothesisId );
        auto call = reinterpret_cast<Function>( table[20] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 21: x_accessibility_XSpeechSynthesizerCreateStreamFromSsml
        using Function = HRESULT( WINAPI * )( void *self, XSpeechSynthesizerHandle speechSynthesizer, const char *ssml,
                                              XSpeechSynthesizerStreamHandle *speechSynthesisStream );
        auto call = reinterpret_cast<Function>( table[21] );
        EXPECT_EQ( call( object, {}, {}, {} ), E_NOTIMPL );
    }
    object->Release();
}

TEST( NexusOptionalAbi, IXAppCaptureImpl4OriginalSlotsRemainCallable )
{
    Module module;
    auto object = module.Query( CLSID_XAppCaptureImpl, __uuidof( IXAppCaptureImpl4 ) );
    ASSERT_NE( object, nullptr );
    auto table = *reinterpret_cast<void ***>( object );
    {
        // Frozen original C table slot 3: capture_XAppCaptureTakeDiagnosticScreenshot
        using Function =
            HRESULT( WINAPI * )( void *self, BOOLEAN gamescreenOnly, XAppCaptureScreenshotFormatFlag captureFlags,
                                 const char *filenamePrefix, XAppCaptureDiagnosticScreenshotResult *result );
        auto call = reinterpret_cast<Function>( table[3] );
        EXPECT_EQ( call( object, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 4: capture_XAppCaptureRecordDiagnosticClip
        using Function = HRESULT( WINAPI * )( void *self, INT64 startTime, UINT32 durationInMs,
                                              const char *filenamePrefix, XAppCaptureRecordClipResult *result );
        auto call = reinterpret_cast<Function>( table[4] );
        EXPECT_EQ( call( object, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 5: capture_XAppCaptureTakeScreenshot
        using Function =
            HRESULT( WINAPI * )( void *self, XUserHandle requestingUser, XAppCaptureTakeScreenshotResult *result );
        auto call = reinterpret_cast<Function>( table[5] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 6: capture_XAppCaptureOpenScreenshotStream
        using Function =
            HRESULT( WINAPI * )( void *self, const char *localId, XAppCaptureScreenshotFormatFlag screenshotFormat,
                                 XAppCaptureScreenshotStreamHandle *handle, UINT64 *totalBytes );
        auto call = reinterpret_cast<Function>( table[6] );
        EXPECT_EQ( call( object, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 7: capture_XAppCaptureReadScreenshotStream
        using Function =
            HRESULT( WINAPI * )( void *self, XAppCaptureScreenshotStreamHandle handle, UINT64 startPosition,
                                 UINT32 bytesToRead, UINT8 *bytes, UINT32 *bytesWritten );
        auto call = reinterpret_cast<Function>( table[7] );
        EXPECT_EQ( call( object, {}, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 8: capture_XAppCaptureCloseScreenshotStream
        using Function = HRESULT( WINAPI * )( void *self, XAppCaptureScreenshotStreamHandle handle );
        auto call = reinterpret_cast<Function>( table[8] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 9: capture_XAppCaptureEnableRecord
        using Function = HRESULT( WINAPI * )( void *self );
        auto call = reinterpret_cast<Function>( table[9] );
        EXPECT_EQ( call( object ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 10: capture_XAppCaptureDisableRecord
        using Function = HRESULT( WINAPI * )( void *self );
        auto call = reinterpret_cast<Function>( table[10] );
        EXPECT_EQ( call( object ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 11: capture_XAppCaptureGetVideoCaptureSettings
        using Function = HRESULT( WINAPI * )( void *self, XAppCaptureVideoCaptureSettings *userCaptureSettings );
        auto call = reinterpret_cast<Function>( table[11] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 12: capture_XAppCaptureRecordTimespan
        using Function = HRESULT( WINAPI * )( void *self, const SYSTEMTIME *startTimestamp,
                                              UINT64 durationInMilliseconds, XAppCaptureLocalResult *result );
        auto call = reinterpret_cast<Function>( table[12] );
        EXPECT_EQ( call( object, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 13: capture_XAppCaptureReadLocalStream
        using Function = HRESULT( WINAPI * )( void *self, XAppCaptureLocalStreamHandle handle, SIZE_T startPosition,
                                              UINT32 bytesToRead, UINT8 *bytes, UINT32 *bytesWritten );
        auto call = reinterpret_cast<Function>( table[13] );
        EXPECT_EQ( call( object, {}, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 14: capture_XAppCaptureCloseLocalStream
        using Function = HRESULT( WINAPI * )( void *self, XAppCaptureLocalStreamHandle handle );
        auto call = reinterpret_cast<Function>( table[14] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 15: capture_XAppCaptureStartUserRecord
        using Function = HRESULT( WINAPI * )( void *self, XUserHandle requestingUser, UINT32 localIdBufferLength,
                                              char *localIdBuffer );
        auto call = reinterpret_cast<Function>( table[15] );
        EXPECT_EQ( call( object, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 16: capture_XAppCaptureStopUserRecord
        using Function = HRESULT( WINAPI * )( void *self, const char *localId, XAppCaptureUserRecordingResult *result );
        auto call = reinterpret_cast<Function>( table[16] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 17: capture_XAppCaptureCancelUserRecord
        using Function = HRESULT( WINAPI * )( void *self, const char *localId );
        auto call = reinterpret_cast<Function>( table[17] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    object->Release();
}

TEST( NexusOptionalAbi, IXAppCaptureMetadataImplOriginalSlotsRemainCallable )
{
    Module module;
    auto object = module.Query( CLSID_XAppCaptureMetadataImpl, __uuidof( IXAppCaptureMetadataImpl ) );
    ASSERT_NE( object, nullptr );
    auto table = *reinterpret_cast<void ***>( object );
    {
        // Frozen original C table slot 4: metadata_XAppBroadcastShowUI
        using Function = HRESULT( WINAPI * )( void *self, XUserHandle requestingUser );
        auto call = reinterpret_cast<Function>( table[4] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 5: metadata_XAppBroadcastGetStatus
        using Function =
            HRESULT( WINAPI * )( void *self, XUserHandle requestingUser, XAppBroadcastStatus *appBroadcastStatus );
        auto call = reinterpret_cast<Function>( table[5] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 6: metadata_XAppBroadcastRegisterIsAppBroadcastingChanged
        using Function = HRESULT( WINAPI * )( void *self, XTaskQueueHandle queue, void *context,
                                              XAppBroadcastMonitorCallback *appBroadcastMonitorCallback,
                                              XTaskQueueRegistrationToken *token );
        auto call = reinterpret_cast<Function>( table[6] );
        EXPECT_EQ( call( object, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 8: metadata_XAppCaptureMetadataAddStringEvent
        using Function = HRESULT( WINAPI * )( void *self, const char *name, const char *value,
                                              XAppCaptureMetadataPriority priority );
        auto call = reinterpret_cast<Function>( table[8] );
        EXPECT_EQ( call( object, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 9: metadata_XAppCaptureMetadataAddInt32Event
        using Function =
            HRESULT( WINAPI * )( void *self, const char *name, INT32 value, XAppCaptureMetadataPriority priority );
        auto call = reinterpret_cast<Function>( table[9] );
        EXPECT_EQ( call( object, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 10: metadata_XAppCaptureMetadataAddDoubleEvent
        using Function =
            HRESULT( WINAPI * )( void *self, const char *name, double value, XAppCaptureMetadataPriority priority );
        auto call = reinterpret_cast<Function>( table[10] );
        EXPECT_EQ( call( object, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 11: metadata_XAppCaptureMetadataStartStringState
        using Function = HRESULT( WINAPI * )( void *self, const char *name, const char *value,
                                              XAppCaptureMetadataPriority priority );
        auto call = reinterpret_cast<Function>( table[11] );
        EXPECT_EQ( call( object, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 12: metadata_XAppCaptureMetadataStartInt32State
        using Function =
            HRESULT( WINAPI * )( void *self, const char *name, INT32 value, XAppCaptureMetadataPriority priority );
        auto call = reinterpret_cast<Function>( table[12] );
        EXPECT_EQ( call( object, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 13: metadata_XAppCaptureMetadataStartDoubleState
        using Function =
            HRESULT( WINAPI * )( void *self, const char *name, double value, XAppCaptureMetadataPriority priority );
        auto call = reinterpret_cast<Function>( table[13] );
        EXPECT_EQ( call( object, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 14: metadata_XAppCaptureMetadataStopState
        using Function = HRESULT( WINAPI * )( void *self, const char *name );
        auto call = reinterpret_cast<Function>( table[14] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 15: metadata_XAppCaptureMetadataStopAllStates
        using Function = HRESULT( WINAPI * )( void *self );
        auto call = reinterpret_cast<Function>( table[15] );
        EXPECT_EQ( call( object ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 16: metadata_XAppCaptureMetadataRemainingStorageBytesAvailable
        using Function = HRESULT( WINAPI * )( void *self, UINT64 *value );
        auto call = reinterpret_cast<Function>( table[16] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 17: metadata_XAppCaptureRegisterMetadataPurged
        using Function =
            HRESULT( WINAPI * )( void *self, XTaskQueueHandle queue, void *context,
                                 XAppCaptureMetadataPurgedCallback *callback, XTaskQueueRegistrationToken *token );
        auto call = reinterpret_cast<Function>( table[17] );
        EXPECT_EQ( call( object, {}, {}, {}, {} ), E_NOTIMPL );
    }
    object->Release();
}

TEST( NexusOptionalAbi, IXGameEventImplOriginalSlotsRemainCallable )
{
    Module module;
    auto object = module.Query( CLSID_XGameEventImpl, __uuidof( IXGameEventImpl ) );
    ASSERT_NE( object, nullptr );
    auto table = *reinterpret_cast<void ***>( object );
    {
        // Frozen original C table slot 3: x_game_event_XGameEventWrite
        using Function =
            HRESULT( WINAPI * )( void *self, XUserHandle user, const char *serviceConfigId, const char *playSessionId,
                                 const char *eventName, const char *dimensionsJson, const char *measurementsJson );
        auto call = reinterpret_cast<Function>( table[3] );
        EXPECT_EQ( call( object, {}, {}, {}, {}, {}, {} ), E_NOTIMPL );
    }
    object->Release();
}

TEST( NexusDesktopStreaming, LifecycleSharesAnEmptyDesktopContextAcrossInterfaces )
{
    Module module;
    auto api = static_cast<IXGameStreamingImpl3 *>(
        module.Query( CLSID_XGameStreamingImpl, __uuidof( IXGameStreamingImpl3 ) ) );
    auto base = static_cast<IXGameStreamingImpl *>(
        module.Query( CLSID_XGameStreamingImpl, __uuidof( IXGameStreamingImpl ) ) );
    ASSERT_NE( api, nullptr );
    ASSERT_NE( base, nullptr );
    api->XGameStreamingUninitialize();
    UINT32 used = 17;
    EXPECT_EQ( api->XGameStreamingGetClients( 0, nullptr, &used ), E_GAMESTREAMING_NOT_INITIALIZED );
    EXPECT_EQ( used, 0u );
    EXPECT_FALSE( api->XGameStreamingIsStreaming() );
    EXPECT_EQ( api->XGameStreamingGetClientCount(), 0u );
    SetLastError( 0x12345678 );
    EXPECT_EQ( api->XGameStreamingInitialize(), S_OK );
    EXPECT_EQ( GetLastError(), 0x12345678u );
    EXPECT_EQ( base->XGameStreamingInitialize(), S_OK );
    used = 17;
    EXPECT_EQ( base->XGameStreamingGetClients( 0, nullptr, &used ), S_OK );
    EXPECT_EQ( used, 0u );
    EXPECT_FALSE( api->XGameStreamingIsStreaming() );
    EXPECT_EQ( api->XGameStreamingGetClientCount(), 0u );
    base->XGameStreamingUninitialize();
    used = 17;
    EXPECT_EQ( api->XGameStreamingGetClients( 0, nullptr, &used ), E_GAMESTREAMING_NOT_INITIALIZED );
    EXPECT_EQ( used, 0u );
    api->XGameStreamingUninitialize();
    EXPECT_EQ( api->XGameStreamingInitialize(), S_OK );
    EXPECT_EQ( api->XGameStreamingGetClients( 0, nullptr, nullptr ), S_OK );
    auto feature = static_cast<IXGameRuntimeFeatureImpl *>(
        module.Query( CLSID_XGameRuntimeFeatureImpl, __uuidof( IXGameRuntimeFeatureImpl ) ) );
    ASSERT_NE( feature, nullptr );
    EXPECT_FALSE( feature->XGameRuntimeIsFeatureAvailable( XGameRuntimeFeature::XGameStreaming ) );
    feature->Release();
    api->XGameStreamingUninitialize();
    base->Release();
    api->Release();
}

TEST( NexusDesktopStreaming, EmptyEnumerationDoesNotWriteClientIdsOrInventRemoteData )
{
    Module module;
    auto api = static_cast<IXGameStreamingImpl3 *>(
        module.Query( CLSID_XGameStreamingImpl, __uuidof( IXGameStreamingImpl3 ) ) );
    ASSERT_NE( api, nullptr );
    EXPECT_EQ( api->XGameStreamingInitialize(), S_OK );
    XGameStreamingClientId clients[] = { 0x123456789abcdef0ULL, 0xfedcba9876543210ULL };
    UINT32 used = 17;
    EXPECT_EQ( api->XGameStreamingGetClients( 2, clients, &used ), S_OK );
    EXPECT_EQ( used, 0u );
    EXPECT_EQ( clients[0], 0x123456789abcdef0ULL );
    EXPECT_EQ( clients[1], 0xfedcba9876543210ULL );
    EXPECT_EQ( api->XGameStreamingGetClients( UINT32_MAX, clients, &used ), S_OK );
    EXPECT_EQ( used, 0u );
    EXPECT_EQ( clients[0], 0x123456789abcdef0ULL );
    EXPECT_EQ( clients[1], 0xfedcba9876543210ULL );
    used = 17;
    EXPECT_EQ( api->XGameStreamingGetClients( 1, nullptr, &used ), E_INVALIDARG );
    EXPECT_EQ( used, 0u );
    EXPECT_EQ( api->XGameStreamingGetConnectionState( 0x1234 ), XGameStreamingConnectionState::Disconnected );
    XTaskQueueRegistrationToken token{};
    EXPECT_EQ( api->XGameStreamingRegisterConnectionStateChanged( nullptr, nullptr, nullptr, &token ), E_NOTIMPL );
    EXPECT_EQ( token.token, 0u );
    UINT32 horizontal = 123, vertical = 456;
    EXPECT_EQ( api->XGameStreamingGetStreamPhysicalDimensions( 0x1234, &horizontal, &vertical ), E_NOTIMPL );
    EXPECT_EQ( horizontal, 123u );
    EXPECT_EQ( vertical, 456u );
    EXPECT_FALSE( api->XGameStreamingUnregisterConnectionStateChanged( token, TRUE ) );
    api->XGameStreamingUninitialize();
    api->Release();
}

TEST( NexusDesktopStreaming, ConcurrentInitializationAndTeardownNeverInventClients )
{
    Module module;
    auto api = static_cast<IXGameStreamingImpl3 *>(
        module.Query( CLSID_XGameStreamingImpl, __uuidof( IXGameStreamingImpl3 ) ) );
    ASSERT_NE( api, nullptr );
    api->XGameStreamingUninitialize();
    std::atomic<unsigned> failures{};
    std::thread workers[8];
    for ( auto &worker : workers ) worker = std::thread( [&]
    {
        for ( unsigned i = 0; i < 200; ++i )
        {
            if ( api->XGameStreamingInitialize() != S_OK ) ++failures;
            XGameStreamingClientId client = 0x123456789abcdef0ULL;
            UINT32 used = 17;
            const HRESULT hr = api->XGameStreamingGetClients( 1, &client, &used );
            if ( ( hr != S_OK && hr != E_GAMESTREAMING_NOT_INITIALIZED ) || used ||
                 client != 0x123456789abcdef0ULL || api->XGameStreamingIsStreaming() ||
                 api->XGameStreamingGetClientCount() ) ++failures;
            api->XGameStreamingUninitialize();
        }
    } );
    for ( auto &worker : workers ) worker.join();
    EXPECT_EQ( failures.load(), 0u );
    api->XGameStreamingUninitialize();
    UINT32 used = 17;
    EXPECT_EQ( api->XGameStreamingGetClients( 0, nullptr, &used ), E_GAMESTREAMING_NOT_INITIALIZED );
    EXPECT_EQ( used, 0u );
    api->Release();
}

TEST( NexusOptionalAbi, IXGameStreamingImpl3OriginalSlotsRemainCallable )
{
    Module module;
    auto object = module.Query( CLSID_XGameStreamingImpl, __uuidof( IXGameStreamingImpl3 ) );
    ASSERT_NE( object, nullptr );
    auto table = *reinterpret_cast<void ***>( object );
    {
        // Frozen original C table slot 3: x_game_streaming_XGameStreamingInitialize
        using Function = HRESULT( WINAPI * )( void *self );
        auto call = reinterpret_cast<Function>( table[3] );
        // The ABI slot is unchanged, its desktop lifecycle is now implemented.
        EXPECT_EQ( call( object ), S_OK );
    }
    {
        // Frozen original C table slot 6: x_game_streaming_XGameStreamingRegisterClientPropertiesChanged
        using Function = HRESULT( WINAPI * )( void *self, XGameStreamingClientId client, XTaskQueueHandle queue,
                                              void *context, XGameStreamingClientPropertiesChangedCallback *callback,
                                              XTaskQueueRegistrationToken *token );
        auto call = reinterpret_cast<Function>( table[6] );
        EXPECT_EQ( call( object, {}, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 8: x_game_streaming_XGameStreamingGetStreamPhysicalDimensions
        using Function =
            HRESULT( WINAPI * )( void *self, XGameStreamingClientId client, UINT32 *horizontalMm, UINT32 *verticalMm );
        auto call = reinterpret_cast<Function>( table[8] );
        EXPECT_EQ( call( object, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 10: x_game_streaming_XGameStreamingGetClients
        using Function =
            HRESULT( WINAPI * )( void *self, UINT32 clientCount, XGameStreamingClientId *clients, UINT32 *clientsUsed );
        auto call = reinterpret_cast<Function>( table[10] );
        EXPECT_EQ( call( object, {}, {}, {} ), S_OK );
    }
    {
        // Frozen original C table slot 12: x_game_streaming_XGameStreamingRegisterConnectionStateChanged
        using Function = HRESULT( WINAPI * )( void *self, XTaskQueueHandle queue, void *context,
                                              XGameStreamingConnectionStateChangedCallback *callback,
                                              XTaskQueueRegistrationToken *token );
        auto call = reinterpret_cast<Function>( table[12] );
        EXPECT_EQ( call( object, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 14: x_game_streaming_XGameStreamingGetStreamAddedLatency
        using Function = HRESULT( WINAPI * )( void *self, XGameStreamingClientId client, UINT32 *averageInputLatencyUs,
                                              UINT32 *averageOutputLatencyUs, UINT32 *standardDeviationUs );
        auto call = reinterpret_cast<Function>( table[14] );
        EXPECT_EQ( call( object, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 16: x_game_streaming_XGameStreamingGetServerLocationName
        using Function = HRESULT( WINAPI * )( void *self, SIZE_T serverLocationNameSize, char *serverLocationName );
        auto call = reinterpret_cast<Function>( table[16] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 21: x_game_streaming_XGameStreamingIsTouchInputEnabled
        using Function = HRESULT( WINAPI * )( void *self, XGameStreamingClientId client, BOOLEAN *touchInputEnabled );
        auto call = reinterpret_cast<Function>( table[21] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 22: x_game_streaming_XGameStreamingGetLastFrameDisplayed
        using Function = HRESULT( WINAPI * )( void *self, XGameStreamingClientId client,
                                              D3D12XBOX_FRAME_PIPELINE_TOKEN *framePipelineToken );
        auto call = reinterpret_cast<Function>( table[22] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 23: x_game_streaming_XGameStreamingGetAssociatedFrame
        using Function = HRESULT( WINAPI * )( void *self, IGameInputReading *gamepadReading,
                                              D3D12XBOX_FRAME_PIPELINE_TOKEN *framePipelineToken );
        auto call = reinterpret_cast<Function>( table[23] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 24: x_game_streaming_XGameStreamingGetGamepadPhysicality
        using Function = HRESULT( WINAPI * )( void *self, IGameInputReading *gamepadReading,
                                              XGameStreamingGamepadPhysicality *gamepadPhysicality );
        auto call = reinterpret_cast<Function>( table[24] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 25: x_game_streaming_XGameStreamingUpdateTouchControlsState
        using Function = HRESULT( WINAPI * )( void *self, SIZE_T operationCount,
                                              const XGameStreamingTouchControlsStateOperation *operations );
        auto call = reinterpret_cast<Function>( table[25] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 26: x_game_streaming_XGameStreamingUpdateTouchControlsStateOnClient
        using Function = HRESULT( WINAPI * )( void *self, XGameStreamingClientId client, SIZE_T operationCount,
                                              const XGameStreamingTouchControlsStateOperation *operations );
        auto call = reinterpret_cast<Function>( table[26] );
        EXPECT_EQ( call( object, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 27: x_game_streaming_XGameStreamingShowTouchControlsWithStateUpdate
        using Function = HRESULT( WINAPI * )( void *self, const char *layout, SIZE_T operationCount,
                                              const XGameStreamingTouchControlsStateOperation *operations );
        auto call = reinterpret_cast<Function>( table[27] );
        EXPECT_EQ( call( object, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 28: x_game_streaming_XGameStreamingShowTouchControlsWithStateUpdateOnClient
        using Function =
            HRESULT( WINAPI * )( void *self, XGameStreamingClientId client, const char *layout, SIZE_T operationCount,
                                 const XGameStreamingTouchControlsStateOperation *operations );
        auto call = reinterpret_cast<Function>( table[28] );
        EXPECT_EQ( call( object, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 30: x_game_streaming_XGameStreamingGetTouchBundleVersion
        using Function = HRESULT( WINAPI * )( void *self, XGameStreamingClientId client, XVersion *version,
                                              SIZE_T versionNameSize, char *versionName );
        auto call = reinterpret_cast<Function>( table[30] );
        EXPECT_EQ( call( object, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 31: x_game_streaming_XGameStreamingGetClientIPAddress
        using Function =
            HRESULT( WINAPI * )( void *self, XGameStreamingClientId client, SIZE_T ipAddressSize, char *ipAddress );
        auto call = reinterpret_cast<Function>( table[31] );
        EXPECT_EQ( call( object, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 32: x_game_streaming_XGameStreamingGetSessionId
        using Function = HRESULT( WINAPI * )( void *self, XGameStreamingClientId client, SIZE_T sessionIdSize,
                                              char *sessionId, SIZE_T *sessionIdUsed );
        auto call = reinterpret_cast<Function>( table[32] );
        EXPECT_EQ( call( object, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 33: x_game_streaming_XGameStreamingGetDisplayDetails
        using Function = HRESULT( WINAPI * )( void *self, XGameStreamingClientId client, UINT32 maxSupportedPixels,
                                              float widestSupportedAspectRatio, float tallestSupportedAspectRatio,
                                              XGameStreamingDisplayDetails *displayDetails );
        auto call = reinterpret_cast<Function>( table[33] );
        EXPECT_EQ( call( object, {}, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 34: x_game_streaming_XGameStreamingSetResolution
        using Function = HRESULT( WINAPI * )( void *self, UINT32 width, UINT32 height );
        auto call = reinterpret_cast<Function>( table[34] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    static_cast<IXGameStreamingImpl3 *>( object )->XGameStreamingUninitialize();
    object->Release();
}

TEST( NexusOptionalAbi, IXGameUiImpl4OriginalSlotsRemainCallable )
{
    Module module;
    auto object = module.Query( CLSID_XGameUiImpl, __uuidof( IXGameUiImpl4 ) );
    ASSERT_NE( object, nullptr );
    auto table = *reinterpret_cast<void ***>( object );
    {
        // Frozen original C table slot 3: x_game_ui_XGameUiShowMessageDialogAsync
        using Function =
            HRESULT( WINAPI * )( void *self, XAsyncBlock *async, const char *titleText, const char *contentText,
                                 const char *firstButtonText, const char *secondButtonText, const char *thirdButtonText,
                                 XGameUiMessageDialogButton defaultButton, XGameUiMessageDialogButton cancelButton );
        auto call = reinterpret_cast<Function>( table[3] );
        EXPECT_EQ( call( object, {}, {}, {}, {}, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 4: x_game_ui_XGameUiShowMessageDialogResult
        using Function =
            HRESULT( WINAPI * )( void *self, XAsyncBlock *async, XGameUiMessageDialogButton *resultButton );
        auto call = reinterpret_cast<Function>( table[4] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 5: x_game_ui_XGameUiShowSendGameInviteAsync
        using Function = HRESULT( WINAPI * )( void *self, XAsyncBlock *async, XUserHandle requestingUser,
                                              const char *sessionConfigurationId, const char *sessionTemplateName,
                                              const char *sessionId, const char *invitationText,
                                              const char *customActivationContext );
        auto call = reinterpret_cast<Function>( table[5] );
        EXPECT_EQ( call( object, {}, {}, {}, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 6: x_game_ui_XGameUiShowSendGameInviteResult
        using Function = HRESULT( WINAPI * )( void *self, XAsyncBlock *async );
        auto call = reinterpret_cast<Function>( table[6] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 7: x_game_ui_XGameUiShowPlayerProfileCardAsync
        using Function =
            HRESULT( WINAPI * )( void *self, XAsyncBlock *async, XUserHandle requestingUser, UINT64 targetPlayer );
        auto call = reinterpret_cast<Function>( table[7] );
        EXPECT_EQ( call( object, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 8: x_game_ui_XGameUiShowPlayerProfileCardResult
        using Function = HRESULT( WINAPI * )( void *self, XAsyncBlock *async );
        auto call = reinterpret_cast<Function>( table[8] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 9: x_game_ui_XGameUiShowAchievementsAsync
        using Function =
            HRESULT( WINAPI * )( void *self, XAsyncBlock *async, XUserHandle requestingUser, UINT32 titleId );
        auto call = reinterpret_cast<Function>( table[9] );
        EXPECT_EQ( call( object, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 10: x_game_ui_XGameUiShowAchievementsResult
        using Function = HRESULT( WINAPI * )( void *self, XAsyncBlock *async );
        auto call = reinterpret_cast<Function>( table[10] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 11: x_game_ui_XGameUiShowPlayerPickerAsync
        using Function = HRESULT( WINAPI * )(
            void *self, XAsyncBlock *async, XUserHandle requestingUser, const char *promptText,
            UINT32 selectFromPlayersCount, const UINT64 *selectFromPlayers, UINT32 preSelectedPlayersCount,
            UINT64 *preSelectedPlayers, UINT32 minSelectionCount, UINT32 maxSelectionCount );
        auto call = reinterpret_cast<Function>( table[11] );
        EXPECT_EQ( call( object, {}, {}, {}, {}, {}, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 12: x_game_ui_XGameUiShowPlayerPickerResultCount
        using Function = HRESULT( WINAPI * )( void *self, XAsyncBlock *async, UINT32 *resultPlayersCount );
        auto call = reinterpret_cast<Function>( table[12] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 13: x_game_ui_XGameUiShowPlayerPickerResult
        using Function = HRESULT( WINAPI * )( void *self, XAsyncBlock *async, UINT32 resultPlayersCount,
                                              UINT64 *resultPlayers, UINT32 *resultPlayersUsed );
        auto call = reinterpret_cast<Function>( table[13] );
        EXPECT_EQ( call( object, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 14: x_game_ui_XGameUiShowErrorDialogAsync
        using Function = HRESULT( WINAPI * )( void *self, XAsyncBlock *async, HRESULT errorCode, const char *context );
        auto call = reinterpret_cast<Function>( table[14] );
        EXPECT_EQ( call( object, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 15: x_game_ui_XGameUiShowErrorDialogResult
        using Function = HRESULT( WINAPI * )( void *self, XAsyncBlock *async );
        auto call = reinterpret_cast<Function>( table[15] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 16: x_game_ui_XGameUiSetNotificationPositionHint
        using Function = HRESULT( WINAPI * )( void *self, XGameUiNotificationPositionHint position );
        auto call = reinterpret_cast<Function>( table[16] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 17: x_game_ui_XGameUiShowTextEntryAsync
        using Function =
            HRESULT( WINAPI * )( void *self, XAsyncBlock *async, const char *titleText, const char *descriptionText,
                                 const char *defaultText, XGameUiTextEntryInputScope inputScope, UINT32 maxTextLength );
        auto call = reinterpret_cast<Function>( table[17] );
        EXPECT_EQ( call( object, {}, {}, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 18: x_game_ui_XGameUiShowTextEntryResultSize
        using Function = HRESULT( WINAPI * )( void *self, XAsyncBlock *async, UINT32 *resultTextBufferSize );
        auto call = reinterpret_cast<Function>( table[18] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 19: x_game_ui_XGameUiShowTextEntryResult
        using Function = HRESULT( WINAPI * )( void *self, XAsyncBlock *async, UINT32 resultTextBufferSize,
                                              char *resultTextBuffer, UINT32 *resultTextBufferUsed );
        auto call = reinterpret_cast<Function>( table[19] );
        EXPECT_EQ( call( object, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 20: __PADDING__
        using Function = HRESULT( WINAPI * )( void *self );
        auto call = reinterpret_cast<Function>( table[20] );
        EXPECT_EQ( call( object ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 21: __PADDING_2__
        using Function = HRESULT( WINAPI * )( void *self );
        auto call = reinterpret_cast<Function>( table[21] );
        EXPECT_EQ( call( object ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 22: __PADDING_3__
        using Function = HRESULT( WINAPI * )( void *self );
        auto call = reinterpret_cast<Function>( table[22] );
        EXPECT_EQ( call( object ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 23: __PADDING_4__
        using Function = HRESULT( WINAPI * )( void *self );
        auto call = reinterpret_cast<Function>( table[23] );
        EXPECT_EQ( call( object ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 24: x_game_ui_XGameUiShowWebAuthenticationAsync
        using Function = HRESULT( WINAPI * )( void *self, XAsyncBlock *async, XUserHandle requestingUser,
                                              const char *requestUri, const char *completionUri );
        auto call = reinterpret_cast<Function>( table[24] );
        EXPECT_EQ( call( object, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 25: x_game_ui_XGameUiShowWebAuthenticationResultSize
        using Function = HRESULT( WINAPI * )( void *self, XAsyncBlock *async, SIZE_T *bufferSize );
        auto call = reinterpret_cast<Function>( table[25] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 26: x_game_ui_XGameUiShowWebAuthenticationResult
        using Function = HRESULT( WINAPI * )( void *self, XAsyncBlock *async, SIZE_T bufferSize, void *buffer,
                                              XGameUiWebAuthenticationResultData **ptrToBuffer, SIZE_T *bufferUsed );
        auto call = reinterpret_cast<Function>( table[26] );
        EXPECT_EQ( call( object, {}, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 27: x_game_ui_XGameUiShowWebAuthenticationWithOptionsAsync
        using Function =
            HRESULT( WINAPI * )( void *self, XAsyncBlock *async, XUserHandle requestingUser, const char *requestUri,
                                 const char *completionUri, XGameUiWebAuthenticationOptions options );
        auto call = reinterpret_cast<Function>( table[27] );
        EXPECT_EQ( call( object, {}, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 28: __PADDING_5__
        using Function = HRESULT( WINAPI * )( void *self );
        auto call = reinterpret_cast<Function>( table[28] );
        EXPECT_EQ( call( object ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 29: __PADDING_6__
        using Function = HRESULT( WINAPI * )( void *self );
        auto call = reinterpret_cast<Function>( table[29] );
        EXPECT_EQ( call( object ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 30: x_game_ui_XGameUiShowMultiplayerActivityGameInviteAsync
        using Function = HRESULT( WINAPI * )( void *self, XAsyncBlock *async, XUserHandle requestingUser );
        auto call = reinterpret_cast<Function>( table[30] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 31: x_game_ui_XGameUiShowMultiplayerActivityGameInviteResult
        using Function = HRESULT( WINAPI * )( void *self, XAsyncBlock *async );
        auto call = reinterpret_cast<Function>( table[31] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 32: __PADDING_7__
        using Function = HRESULT( WINAPI * )( void *self );
        auto call = reinterpret_cast<Function>( table[32] );
        EXPECT_EQ( call( object ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 33: __PADDING_8__
        using Function = HRESULT( WINAPI * )( void *self );
        auto call = reinterpret_cast<Function>( table[33] );
        EXPECT_EQ( call( object ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 34: x_game_ui_XGameUiTextEntryOpen
        using Function =
            HRESULT( WINAPI * )( void *self, const XGameUiTextEntryOptions *options, UINT32 maxLength,
                                 const char *initialText, UINT32 initialCursorIndex, XGameUiTextEntryHandle *handle );
        auto call = reinterpret_cast<Function>( table[34] );
        EXPECT_EQ( call( object, {}, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 35: x_game_ui_XGameUiTextEntryClose
        using Function = HRESULT( WINAPI * )( void *self, XGameUiTextEntryHandle handle );
        auto call = reinterpret_cast<Function>( table[35] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 36: x_game_ui_XGameUiTextEntryGetState
        using Function = HRESULT( WINAPI * )(
            void *self, XGameUiTextEntryHandle handle, XGameUiTextEntryChangeTypeFlags *changeType, UINT32 *cursorIndex,
            UINT32 *imeClauseStartIndex, UINT32 *imeClauseEndIndex, UINT32 bufferSize, char *buffer );
        auto call = reinterpret_cast<Function>( table[36] );
        EXPECT_EQ( call( object, {}, {}, {}, {}, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 37: x_game_ui_XGameUiTextEntryGetExtents
        using Function =
            HRESULT( WINAPI * )( void *self, XGameUiTextEntryHandle handle, XGameUiTextEntryExtents *extents );
        auto call = reinterpret_cast<Function>( table[37] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 38: x_game_ui_XGameUiTextEntryUpdatePositionHint
        using Function =
            HRESULT( WINAPI * )( void *self, XGameUiTextEntryHandle handle, XGameUiTextEntryPositionHint positionHint );
        auto call = reinterpret_cast<Function>( table[38] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 39: x_game_ui_XGameUiTextEntryUpdateVisibility
        using Function = HRESULT( WINAPI * )( void *self, XGameUiTextEntryHandle handle,
                                              XGameUiTextEntryVisibilityFlags visibilityFlags );
        auto call = reinterpret_cast<Function>( table[39] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 40: x_game_ui_XGameUiShowStateShareAsync
        using Function =
            HRESULT( WINAPI * )( void *self, XAsyncBlock *async, XUserHandle requestingUser, const char *linkToken );
        auto call = reinterpret_cast<Function>( table[40] );
        EXPECT_EQ( call( object, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 41: x_game_ui_XGameUiShowStateShareResult
        using Function = HRESULT( WINAPI * )( void *self, XAsyncBlock *async );
        auto call = reinterpret_cast<Function>( table[41] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 42: x_game_ui_XGameUiSetUiCallbacks
        using Function =
            HRESULT( WINAPI * )( void *self, const XGameUiUiCallbacks *callbacks, BOOLEAN useSystemUiIfAvailable );
        auto call = reinterpret_cast<Function>( table[42] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 43: x_game_ui_XGameUiSetMessageDialogUiResponse
        using Function = HRESULT( WINAPI * )( void *self, XGameUiCallbackHandle callbackHandle,
                                              XGameUiMessageDialogButton response );
        auto call = reinterpret_cast<Function>( table[43] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 44: x_game_ui_XGameUiSetPlayerPickerUiResponse
        using Function = HRESULT( WINAPI * )( void *self, XGameUiCallbackHandle callbackHandle, UINT32 playerCount,
                                              const UINT64 *players );
        auto call = reinterpret_cast<Function>( table[44] );
        EXPECT_EQ( call( object, {}, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 45: x_game_ui_XGameUiSetTextEntryUiResponse
        using Function = HRESULT( WINAPI * )( void *self, XGameUiCallbackHandle callbackHandle, const char *response );
        auto call = reinterpret_cast<Function>( table[45] );
        EXPECT_EQ( call( object, {}, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 46: x_game_ui_XGameUiSetPlayerProfileCardUiResponse
        using Function = HRESULT( WINAPI * )( void *self, XGameUiCallbackHandle callbackHandle );
        auto call = reinterpret_cast<Function>( table[46] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 47: x_game_ui_XGameUiSetSendGameInviteUiResponse
        using Function = HRESULT( WINAPI * )( void *self, XGameUiCallbackHandle callbackHandle );
        auto call = reinterpret_cast<Function>( table[47] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 48: x_game_ui_XGameUiSetAchievementsUiResponse
        using Function = HRESULT( WINAPI * )( void *self, XGameUiCallbackHandle callbackHandle );
        auto call = reinterpret_cast<Function>( table[48] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 49: x_game_ui_XGameUiSetMultiplayerActivityGameInviteUiResponse
        using Function = HRESULT( WINAPI * )( void *self, XGameUiCallbackHandle callbackHandle );
        auto call = reinterpret_cast<Function>( table[49] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    {
        // Frozen original C table slot 50: x_game_ui_XGameUiSetErrorDialogUiResponse
        using Function = HRESULT( WINAPI * )( void *self, XGameUiCallbackHandle callbackHandle );
        auto call = reinterpret_cast<Function>( table[50] );
        EXPECT_EQ( call( object, {} ), E_NOTIMPL );
    }
    object->Release();
}
