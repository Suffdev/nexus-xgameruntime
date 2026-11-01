/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <xinput.h>

struct SaveConflictDialog
{
    const WCHAR *details;
    HMODULE xinput;
    DWORD ( WINAPI *get_state )( DWORD, XINPUT_STATE * );
    DWORD previous[4];
    bool connected[4];
};

static void save_conflict_pad( HWND window, SaveConflictDialog *dialog )
{
    if ( !dialog || !dialog->get_state ) return;
    HWND foreground = GetForegroundWindow();
    bool active = foreground == window || IsChild( window, foreground );
    for ( DWORD index = 0; index < 4; index++ )
    {
        XINPUT_STATE state = {};
        if ( dialog->get_state( index, &state ) != ERROR_SUCCESS ) { dialog->connected[index] = false; continue; }
        DWORD buttons = state.Gamepad.wButtons;
        if ( state.Gamepad.sThumbLX < -XINPUT_GAMEPAD_LEFT_THUMB_DEADZONE ) buttons |= XINPUT_GAMEPAD_DPAD_LEFT;
        if ( state.Gamepad.sThumbLX > XINPUT_GAMEPAD_LEFT_THUMB_DEADZONE ) buttons |= XINPUT_GAMEPAD_DPAD_RIGHT;
        if ( state.Gamepad.sThumbLY < -XINPUT_GAMEPAD_LEFT_THUMB_DEADZONE ) buttons |= XINPUT_GAMEPAD_DPAD_DOWN;
        if ( state.Gamepad.sThumbLY > XINPUT_GAMEPAD_LEFT_THUMB_DEADZONE ) buttons |= XINPUT_GAMEPAD_DPAD_UP;
        DWORD pressed = active && dialog->connected[index] ? buttons & ~dialog->previous[index] : 0;
        dialog->previous[index] = buttons;
        dialog->connected[index] = true;
        // A held launch/confirm button or reconnection cannot choose a save.
        if ( pressed & XINPUT_GAMEPAD_B ) { EndDialog( window, IDCANCEL ); return; }
        const int ids[] = { 100, 101, IDCANCEL };
        int position = 2;
        for ( int i = 0; i < 3; i++ ) if ( GetFocus() == GetDlgItem( window, ids[i] ) ) position = i;
        if ( pressed & ( XINPUT_GAMEPAD_DPAD_LEFT | XINPUT_GAMEPAD_DPAD_UP | XINPUT_GAMEPAD_DPAD_RIGHT | XINPUT_GAMEPAD_DPAD_DOWN ) )
        {
            position = ( position + ( pressed & ( XINPUT_GAMEPAD_DPAD_LEFT | XINPUT_GAMEPAD_DPAD_UP ) ? 2 : 1 ) ) % 3;
            SendMessageW( window, WM_NEXTDLGCTL, ( WPARAM )GetDlgItem( window, ids[position] ), TRUE );
        }
        else if ( pressed & XINPUT_GAMEPAD_A )
        {
            // Only the three explicit buttons can be confirmed with A.
            if ( GetFocus() == GetDlgItem( window, ids[position] ) ) { EndDialog( window, ids[position] ); return; }
        }
    }
}

static INT_PTR CALLBACK save_conflict_proc( HWND window, UINT message, WPARAM wparam, LPARAM lparam )
{
    if ( message == WM_TIMER && wparam == 1 )
    { save_conflict_pad( window, ( SaveConflictDialog * )GetWindowLongPtrW( window, DWLP_USER ) ); return TRUE; }
    if ( message == WM_INITDIALOG )
    {
        auto *dialog = ( SaveConflictDialog * )lparam;
        SetWindowLongPtrW( window, DWLP_USER, lparam );
        HFONT font = ( HFONT )GetStockObject( DEFAULT_GUI_FONT );
        RECT work = { 0 }, measured = { 0 };
        SystemParametersInfoW( SPI_GETWORKAREA, 0, &work, 0 );
        int width = std::min( 620L, work.right - work.left - 32 );
        measured.right = width - 36;
        HDC dc = GetDC( window );
        HGDIOBJ old = SelectObject( dc, font );
        DrawTextW( dc, dialog->details, -1, &measured, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX );
        SelectObject( dc, old ); ReleaseDC( window, dc );
        int body_height = std::min( measured.bottom + 20, work.bottom - work.top - 150 );
        RECT rect = { 0, 0, width, body_height + 78 };
        AdjustWindowRectEx( &rect, GetWindowLongW( window, GWL_STYLE ), FALSE, GetWindowLongW( window, GWL_EXSTYLE ) );
        int height = rect.bottom - rect.top;
        SetWindowPos( window, HWND_TOP, work.left + ( work.right - work.left - width ) / 2,
                      work.top + ( work.bottom - work.top - height ) / 2, rect.right - rect.left, height, 0 );
        HWND body = CreateWindowExW( 0, L"EDIT", dialog->details,
                         WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                         18, 16, width - 36, body_height, window, ( HMENU )200, NULL, NULL );
        SendMessageW( body, WM_SETFONT, ( WPARAM )font, TRUE );
        const WCHAR *labels[] = { L"Use local save", L"Use cloud save", L"Cancel" };
        const int ids[] = { 100, 101, IDCANCEL };
        int button_width = ( width - 52 ) / 3;
        HWND cancel = NULL;
        for ( int i = 0; i < 3; i++ )
        {
            HWND button = CreateWindowExW( 0, L"BUTTON", labels[i], WS_CHILD | WS_VISIBLE | WS_TABSTOP |
                              ( i == 2 ? BS_DEFPUSHBUTTON : BS_PUSHBUTTON ),
                              18 + i * ( button_width + 8 ), body_height + 32, button_width, 30,
                              window, ( HMENU )( INT_PTR )ids[i], NULL, NULL );
            SendMessageW( button, WM_SETFONT, ( WPARAM )font, TRUE );
            if ( i == 2 ) cancel = button;
        }
        SendMessageW( window, DM_SETDEFID, IDCANCEL, 0 );
        SetForegroundWindow( window );
        SetFocus( cancel );
        SetTimer( window, 1, 80, NULL );
        return FALSE;
    }
    if ( message == WM_COMMAND && ( LOWORD( wparam ) == 100 || LOWORD( wparam ) == 101 || LOWORD( wparam ) == IDCANCEL ) )
    { EndDialog( window, LOWORD( wparam ) ); return TRUE; }
    if ( message == WM_CLOSE ) { EndDialog( window, IDCANCEL ); return TRUE; }
    return FALSE;
}

static SaveConflictChoice show_save_conflict_fallback( const WCHAR *details )
{
    // Use explicit choices without depending on the game activating comctl32 v6.
    // The body can scroll on small screens, and Cancel is the safe default.
    struct { DLGTEMPLATE dialog; WORD menu, window_class; WCHAR title[32]; } data = {};
    data.dialog.style = WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME;
    data.dialog.cx = 320; data.dialog.cy = 200;
    wcscpy( data.title, L"Nexus - Cloud saves" );
    DWORD owner_pid = 0;
    HWND owner = GetForegroundWindow();
    if ( owner ) GetWindowThreadProcessId( owner, &owner_pid );
    SaveConflictDialog state = {};
    state.details = details;
    state.xinput = LoadLibraryW( L"xinput1_4.dll" );
    if ( state.xinput ) state.get_state = ( decltype( state.get_state ) )GetProcAddress( state.xinput, "XInputGetState" );
    INT_PTR selected = DialogBoxIndirectParamW( GetModuleHandleW( NULL ), &data.dialog,
                          owner_pid == GetCurrentProcessId() ? owner : NULL, save_conflict_proc, ( LPARAM )&state );
    if ( state.xinput ) FreeLibrary( state.xinput );
    return selected == 100 ? SaveConflictChoice::Local :
           selected == 101 ? SaveConflictChoice::Cloud : SaveConflictChoice::Cancel;
}

static SaveConflictChoice show_save_conflict( const WCHAR *details )
{
    static SRWLOCK lock = SRWLOCK_INIT;
    AcquireSRWLockExclusive( &lock );
    SaveConflictChoice choice = show_save_conflict_fallback( details );
    ReleaseSRWLockExclusive( &lock );
    return choice;
}

