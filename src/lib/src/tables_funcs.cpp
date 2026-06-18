// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// funcs — function inventory via `aflj`. Each row is one analysed function;
// the JSON is re-issued per query so the view is always live.

#include <r2sql/session.hpp>
#include <r2sql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2sql {

namespace {
struct FuncRow {
  int64_t     addr = 0;
  std::string name;
  int64_t     size = 0;
  int64_t     nbbs = 0;
  int64_t     edges = 0;
  int64_t     cc = 0;
  std::string type;
  std::string calltype;
};
}  // namespace

void register_funcs_table(Session& s) {
  auto def = xsql::cached_table<FuncRow>("funcs")
    .no_shared_cache()
    .estimate_rows([be = s.backend_ptr()]() -> size_t {
      return table_utils::quick_count(be, "afl~?", 1000);
    })
    .cache_builder([be = s.backend_ptr()](std::vector<FuncRow>& rows) {
      auto arr = be->cmd_json("aflj");
      if (!arr.is_array()) return;
      rows.reserve(arr.size());
      for (auto& j : arr) {
        FuncRow r;
        r.addr     = json_utils::i64_addr(j);
        r.name     = json_utils::str(j, "name");
        r.size     = json_utils::i64(j, "size");
        r.nbbs     = json_utils::i64(j, "nbbs");
        r.edges    = json_utils::i64(j, "edges");
        r.cc       = json_utils::i64(j, "cc");
        r.type     = json_utils::str(j, "type");
        r.calltype = json_utils::str(j, "calltype");
        rows.push_back(std::move(r));
      }
    })
    .column_int64("addr",  [](const FuncRow& r) { return r.addr; })
    // Writable: UPDATE funcs SET name='x' WHERE addr=... renames the function
    // via `afn` (radare2's function-rename). The dummy `fcn.<addr>` names are
    // the common thing to fix during analysis.
    .column_text_rw("name",
      [](const FuncRow& r) { return r.name; },
      [be = s.backend_ptr()](FuncRow& r, const char* v) -> bool {
        if (!v || !*v) return false;
        if (!json_utils::valid_flag_name(v)) {
          xsql::set_vtab_error(
              "funcs: name must be [A-Za-z0-9._$] (no spaces or r2 metacharacters)");
          return false;
        }
        (void)be->cmd(std::string("afn ") + v + " @ " + json_utils::hex_addr(r.addr));
        r.name = v;
        return true;
      })
    .column_int64("size",  [](const FuncRow& r) { return r.size; })
    .column_int64("nbbs",  [](const FuncRow& r) { return r.nbbs; })
    .column_int64("edges", [](const FuncRow& r) { return r.edges; })
    .column_int64("cc",    [](const FuncRow& r) { return r.cc; })
    .column_text ("type",  [](const FuncRow& r) { return r.type; })
    .column_text ("calltype", [](const FuncRow& r) { return r.calltype; })
    .deletable([be = s.backend_ptr()](FuncRow& r) -> bool {
      // Remove the function definition at this address (analysis only).
      (void)be->cmd("af- " + json_utils::hex_addr(r.addr));
      return true;
    })
    .insertable([be = s.backend_ptr()](int argc, xsql::FunctionArg* argv) -> bool {
      // columns: addr(0), name(1), size(2), nbbs(3), edges(4), cc(5),
      // type(6), calltype(7). Defines a function at addr (`af`), optionally
      // naming it (`afn`).
      if (argc < 1 || argv[0].is_null()) {
        xsql::set_vtab_error("funcs: INSERT requires addr");
        return false;
      }
      const int64_t addr = argv[0].as_int64();
      const std::string at = json_utils::hex_addr(addr);
      (void)be->cmd("af @ " + at);
      if (argc > 1 && !argv[1].is_null()) {
        const char* name = argv[1].as_c_str();
        if (name && *name && json_utils::valid_flag_name(name)) {
          (void)be->cmd(std::string("afn ") + name + " @ " + at);
        }
      }
      return true;
    })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2sql
