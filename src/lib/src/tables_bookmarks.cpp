// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// bookmarks — backed by the `bookmarks` flag space. Each row is one flag
// inside that space. Writable: UPDATE name → `fr`; DELETE → `f- @ addr`;
// INSERT (addr, name) → `f <name> @ <addr>`. Every write is scoped to the
// `bookmarks` flagspace (save/select/restore), mirroring the read path, so
// it never touches flags in other spaces.

#include <vector>

#include <r2sql/session.hpp>
#include <r2sql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"

namespace r2sql {

namespace {
struct BookmarkRow {
  int64_t     id = 0;
  int64_t     addr = 0;
  std::string name;
};
}  // namespace

void register_bookmarks_table(Session& s) {
  auto def = xsql::cached_table<BookmarkRow>("bookmarks")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 128; })
    .cache_builder([be = s.backend_ptr()](std::vector<BookmarkRow>& rows) {
      // Save current flagspace, switch to bookmarks, list, restore.
      (void)be->cmd("fss*");          // save flagspace stack
      (void)be->cmd("fs bookmarks");  // select the bookmarks space
      auto arr = be->cmd_json("fj");
      (void)be->cmd("fsr-");          // restore flagspace stack
      if (!arr.is_array()) return;
      int64_t id = 0;
      for (auto& j : arr) {
        BookmarkRow r;
        r.id   = ++id;
        r.addr = json_utils::i64_addr(j);
        r.name = json_utils::str(j, "name");
        rows.push_back(std::move(r));
      }
    })
    .column_int64("id",   [](const BookmarkRow& r) { return r.id; })
    .column_int64("addr", [](const BookmarkRow& r) { return r.addr; })
    .column_text_rw("name",
      [](const BookmarkRow& r) { return r.name; },
      [be = s.backend_ptr()](BookmarkRow& r, const char* v) -> bool {
        if (!v || !*v) return false;
        if (!json_utils::valid_flag_name(v)) {
          xsql::set_vtab_error(
              "bookmarks: name must be [A-Za-z0-9._$] (no spaces or r2 metacharacters)");
          return false;
        }
        (void)be->cmd("fss*");
        (void)be->cmd("fs bookmarks");
        (void)be->cmd("fr " + r.name + " " + v);
        (void)be->cmd("fsr-");
        r.name = v;
        return true;
      })
    .deletable([be = s.backend_ptr()](BookmarkRow& r) -> bool {
      (void)be->cmd("fss*");
      (void)be->cmd("fs bookmarks");
      (void)be->cmd("f- @ " + json_utils::hex_addr(r.addr));
      (void)be->cmd("fsr-");
      return true;
    })
    .insertable([be = s.backend_ptr()](int argc, xsql::FunctionArg* argv) -> bool {
      // columns in declared order: id(0), addr(1), name(2).
      if (argc < 3 || argv[1].is_null() || argv[2].is_null()) {
        xsql::set_vtab_error("bookmarks: INSERT requires addr and name");
        return false;
      }
      const int64_t addr = argv[1].as_int64();
      const char* name = argv[2].as_c_str();
      if (!name || !*name) {
        xsql::set_vtab_error("bookmarks: INSERT requires a non-empty name");
        return false;
      }
      if (!json_utils::valid_flag_name(name)) {
        xsql::set_vtab_error(
            "bookmarks: name must be [A-Za-z0-9._$] (no spaces or r2 metacharacters)");
        return false;
      }
      (void)be->cmd("fss*");
      (void)be->cmd("fs bookmarks");
      (void)be->cmd(std::string("f ") + name + " @ " + json_utils::hex_addr(addr));
      (void)be->cmd("fsr-");
      return true;
    })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2sql
