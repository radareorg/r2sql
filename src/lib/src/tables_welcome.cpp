// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// welcome — binary info summary, key/value shape (one row per fact).
//
// Carries the bin-info fields from `iIj` (arch, bits, bintype, os, baddr,
// endian, compiler, lang, ...) plus these r2sql identity / entry / count keys:
//   r2sql_version  — tool version
//   file           — input file path (ij -> core.file)
//   entry          — program entry vaddr (iej[0].vaddr)
//   entry_name     — flag/name at the entry (fd @ entry)
//   func_count / string_count / import_count / section_count / segment_count /
//   symbol_count   — JSON-array lengths, so they match the corresponding tables
//   summary        — a one-line synthesized digest
//
// Only what radare2 exposes natively is surfaced: there is no min/max-EA key
// (radare2 has no such command) and no md5/sha256 (radare2's `it` hashing is
// best-effort and often skipped).

#include <r2sql/session.hpp>
#include <r2sql/backend.hpp>
#include <r2sql/version.hpp>
#include <xsql/vtable.hpp>

#include <cstdint>
#include <cstdio>

#include "tables.hpp"
#include "json_utils.hpp"

namespace r2sql {

namespace {
struct WelcomeRow {
  std::string key;
  std::string value;
};

std::string hex_u64(uint64_t v) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

std::string chomp(std::string s) {
  while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
  return s;
}
}  // namespace

void register_welcome_table(Session& s) {
  auto def = xsql::cached_table<WelcomeRow>("welcome")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 28; })
    .cache_builder([be = s.backend_ptr()](std::vector<WelcomeRow>& rows) {
      // --- bin info (iIj): arch, bits, bintype, os, baddr, ... ---
      auto info = be->cmd_json("iIj");
      std::string arch, bits;
      if (info.is_object()) {
        for (auto& [k, v] : info.items()) {
          WelcomeRow r;
          r.key = k;
          if (v.is_string())       r.value = v.get<std::string>();
          else if (v.is_boolean()) r.value = v.get<bool>() ? "true" : "false";
          else if (v.is_number())  r.value = v.dump();
          else                     r.value = v.dump();
          rows.push_back(std::move(r));
        }
        arch = info.value("arch", std::string());
        if (info.contains("bits")) {
          bits = info["bits"].is_number() ? std::to_string(info["bits"].get<long long>())
                                          : info["bits"].dump();
        }
      }

      // --- tool identity ---
      rows.push_back({"r2sql_version", r2sql::version()});

      // --- input file path (ij -> core.file) ---
      {
        auto j = be->cmd_json("ij");
        if (j.is_object() && j.contains("core") && j["core"].is_object()) {
          auto& core = j["core"];
          if (core.contains("file") && core["file"].is_string())
            rows.push_back({"file", core["file"].get<std::string>()});
        }
      }

      // --- entry point + name (iej[0]) ---
      std::string entry_hex, entry_name;
      {
        auto j = be->cmd_json("iej");
        if (j.is_array() && !j.empty() && j[0].is_object() && j[0].contains("vaddr") &&
            j[0]["vaddr"].is_number()) {
          entry_hex = hex_u64(j[0]["vaddr"].get<uint64_t>());
          rows.push_back({"entry", entry_hex});
          entry_name = chomp(be->cmd("fd @ " + entry_hex));
          if (!entry_name.empty()) rows.push_back({"entry_name", entry_name});
        }
      }

      // --- counts (JSON array lengths, so they agree exactly with the
      //     corresponding tables; the `<cmd>~?` text form over-counts header
      //     and formatting lines) ---
      auto add_count = [&](const char* key, const char* cmd) -> std::string {
        auto j = be->cmd_json(cmd);
        std::string v = std::to_string(j.is_array() ? j.size() : 0);
        rows.push_back({key, v});
        return v;
      };
      const std::string func_count    = add_count("func_count",    "aflj");
      const std::string string_count  = add_count("string_count",  "izj");
      add_count("import_count",  "iij");
      const std::string section_count = add_count("section_count", "iSj");
      add_count("segment_count", "iSSj");
      add_count("symbol_count",  "isj");

      // --- one-line summary digest ---
      std::string summary = arch;
      if (!bits.empty()) summary += " " + bits + "-bit";
      if (!entry_name.empty())      summary += " | entry: " + entry_name + " @ " + entry_hex;
      else if (!entry_hex.empty())  summary += " | entry: " + entry_hex;
      summary += " | funcs: " + func_count +
                 " | sections: " + section_count +
                 " | strings: " + string_count;
      rows.push_back({"summary", summary});
    })
    .column_text("key",   [](const WelcomeRow& r) { return r.key; })
    .column_text("value", [](const WelcomeRow& r) { return r.value; })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2sql
