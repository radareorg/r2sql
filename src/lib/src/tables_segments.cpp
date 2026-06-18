// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// segments — `iSSj`.

#include <r2sql/session.hpp>
#include <r2sql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"
#include "table_utils.hpp"

namespace r2sql {

namespace {
struct SegmentRow {
  int64_t     addr = 0;
  int64_t     vsize = 0;
  int64_t     paddr = 0;
  int64_t     size = 0;
  std::string name;
  std::string perm;
};
}  // namespace

void register_segments_table(Session& s) {
  auto def = xsql::cached_table<SegmentRow>("segments")
    .no_shared_cache()
    .estimate_rows([be = s.backend_ptr()]() -> size_t {
      return table_utils::quick_count(be, "iSS~?", 64);
    })
    .cache_builder([be = s.backend_ptr()](std::vector<SegmentRow>& rows) {
      auto arr = be->cmd_json("iSSj");
      if (!arr.is_array()) return;
      rows.reserve(arr.size());
      for (auto& j : arr) {
        SegmentRow r;
        r.addr  = json_utils::i64(j, "vaddr");
        r.vsize = json_utils::i64(j, "vsize");
        r.paddr = json_utils::i64(j, "paddr");
        r.size  = json_utils::i64(j, "size");
        r.name  = json_utils::str(j, "name");
        r.perm  = json_utils::str(j, "perm");
        rows.push_back(std::move(r));
      }
    })
    .column_int64("addr",  [](const SegmentRow& r) { return r.addr; })
    .column_int64("vsize", [](const SegmentRow& r) { return r.vsize; })
    .column_int64("paddr", [](const SegmentRow& r) { return r.paddr; })
    .column_int64("size",  [](const SegmentRow& r) { return r.size; })
    .column_text ("name",  [](const SegmentRow& r) { return r.name; })
    .column_text ("perm",  [](const SegmentRow& r) { return r.perm; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2sql

