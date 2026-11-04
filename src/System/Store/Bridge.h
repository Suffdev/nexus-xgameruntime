// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include <windows.h>
HRESULT xodus_store_package_updates_xml( const char *, SIZE_T, char **, UINT16 * );
HRESULT xodus_store_license_body( const char **, SIZE_T, const char *, char ** );
HRESULT xodus_store_license_xml( const char *, SIZE_T, char ** );
HRESULT xodus_store_license_xml( const char *, SIZE_T, char **, LONG *, ULONGLONG );
void xodus_store_license_note( const char *, HRESULT );
