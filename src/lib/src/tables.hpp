// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Internal header: table registration functions.

#pragma once

namespace r2sql {

class Session;

// Each register_X function builds a virtual table definition that closes
// over a long-lived state object owned by the Session, and registers it
// with `session.db()`. All tables are read-only by default; writable
// tables (comments, flags, bookmarks) additionally route mutations
// through `session.backend()`.

void register_welcome_table(Session& s);
void register_funcs_table(Session& s);
void register_blocks_table(Session& s);
void register_instructions_table(Session& s);
void register_xrefs_table(Session& s);
void register_strings_table(Session& s);
void register_imports_table(Session& s);
void register_exports_table(Session& s);
void register_sections_table(Session& s);
void register_segments_table(Session& s);
void register_flags_table(Session& s);
void register_comments_table(Session& s);
void register_bookmarks_table(Session& s);
void register_grep_table(Session& s);
void register_decompiler_table_if_available(Session& s);
void register_types_table(Session& s);
void register_types_members_table(Session& s);
void register_projects_table(Session& s);

}  // namespace r2sql
