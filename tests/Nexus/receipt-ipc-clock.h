// SPDX-License-Identifier: LGPL-2.1-or-later
// Force-included only for the dedicated receipt IPC fixture and its XUser TU.
// Production targets never select this clock.
#pragma once
#include "../../src/private.h"
ULONGLONG WINAPI FixtureReceiptTick();
#define GetTickCount64 FixtureReceiptTick
