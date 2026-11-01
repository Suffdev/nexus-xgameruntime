// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include "../../private.h"

// Internal save-session dependencies. There are no exported hooks, environment
// overrides or success fallbacks. The default performs genuine signed requests.
enum class SaveConflictChoice { Cancel, Local, Cloud };

class SaveTransport
{
public:
    virtual ~SaveTransport() = default;
    virtual HRESULT Authorization( XUserHandle user, const char *audience, char **authorization ) = 0;
    virtual HRESULT SignedRequest( XUserHandle user, const char *method, const char *url, const char *authorization,
                                   const char *headers, const void *body, DWORD bodySize, DWORD *status, BYTE **output,
                                   SIZE_T *size ) = 0;
    virtual HRESULT DirectRequest( const WCHAR *method, const WCHAR *url, const WCHAR *headers, const void *body,
                                   DWORD bodySize, DWORD *status, BYTE **output, SIZE_T *size ) = 0;
    virtual void CloseUser( XUserHandle user ) = 0;
    virtual bool CanResolveConflicts() const { return false; }
    virtual SaveConflictChoice ResolveConflict( const WCHAR *details ) { return SaveConflictChoice::Cancel; }
};
