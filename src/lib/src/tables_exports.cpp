// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// exports — `iEj`.

#include <r2sql/session.hpp>
#include <r2sql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2sql {

namespace {
struct ExportRow {
  int64_t     addr = 0;
  int64_t     size = 0;
  std::string type;
  std::string bind;
  std::string name;
};
}  // namespace

void register_exports_table(Session& s) {
  auto def = xsql::cached_table<ExportRow>("exports")
    .no_shared_cache()
    .estimate_rows([be = s.backend_ptr()]() -> size_t {
      return table_utils::quick_count(be, "iE~?", 256);
    })
    .cache_builder([be = s.backend_ptr()](std::vector<ExportRow>& rows) {
      auto arr = be->cmd_json("iEj");
      if (!arr.is_array()) return;
      rows.reserve(arr.size());
      for (auto& j : arr) {
        ExportRow r;
        r.addr = json_utils::i64(j, "vaddr");
        r.size = json_utils::i64(j, "size");
        r.type = json_utils::str(j, "type");
        r.bind = json_utils::str(j, "bind");
        r.name = json_utils::str(j, "name");
        rows.push_back(std::move(r));
      }
    })
    .column_int64("addr", [](const ExportRow& r) { return r.addr; })
    .column_int64("size", [](const ExportRow& r) { return r.size; })
    .column_text ("type", [](const ExportRow& r) { return r.type; })
    .column_text ("bind", [](const ExportRow& r) { return r.bind; })
    .column_text ("name", [](const ExportRow& r) { return r.name; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2sql

