// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
#include <r2sql/session.hpp>
#include <r2sql/backend.hpp>

#include <xsql/functions.hpp>

#include <regex>

#include "tables.hpp"
#include "json_utils.hpp"

namespace r2sql {

Session::Session(std::unique_ptr<Backend> backend) : backend_(std::move(backend)) {
  db_.open(":memory:");
  register_all_tables_();
  register_functions_();
  detect_decompiler_();
}

Session::~Session() = default;

xsql::Result Session::query(std::string_view sql) {
  std::lock_guard<std::mutex> lock(query_mu_);
  std::string s(sql);
  return db_.query(s);
}

std::string Session::raw_cmd(std::string command) {
  std::lock_guard<std::mutex> lock(query_mu_);
  return backend_->cmd(command);
}

void Session::register_all_tables_() {
  register_welcome_table(*this);
  register_funcs_table(*this);
  register_blocks_table(*this);
  register_instructions_table(*this);
  register_xrefs_table(*this);
  register_strings_table(*this);
  register_imports_table(*this);
  register_exports_table(*this);
  register_sections_table(*this);
  register_segments_table(*this);
  register_flags_table(*this);
  register_comments_table(*this);
  register_bookmarks_table(*this);
  register_grep_table(*this);
  register_types_table(*this);
  register_types_members_table(*this);
  register_projects_table(*this);
}

void Session::register_functions_() {
  // regexp(pattern, text) -> 1 if `text` matches the ECMAScript regex
  // `pattern`, else 0. SQLite rewrites `text REGEXP pattern` to this call
  // (pattern first), enabling the documented `WHERE name REGEXP '...'` form.
  // SQLite has no built-in REGEXP, so it must be registered here.
  db_.register_function("regexp", 2, xsql::ScalarFn(
    [](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
      if (argc < 2 || argv[0].is_null() || argv[1].is_null()) {
        ctx.result_int(0);
        return;
      }
      try {
        std::regex re(argv[0].as_text(), std::regex::ECMAScript);
        ctx.result_int(std::regex_search(argv[1].as_text(), re) ? 1 : 0);
      } catch (const std::exception&) {
        ctx.result_int(0);  // invalid pattern -> no match (never throws into SQLite)
      }
    }));

  // Project persistence as a SQL surface — save/open a project mid-session
  // without exiting. These run inside the query lock (db_.query holds
  // query_mu_), so they call the backend directly rather than Session::raw_cmd
  // (which would re-acquire the same lock and deadlock).
  Backend* be = backend_.get();
  db_.register_function("r2sql_project_save", 1, xsql::ScalarFn(
    [be](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
      if (argc < 1 || argv[0].is_null()) { ctx.result_text("error: project name required"); return; }
      std::string name = argv[0].as_text();
      if (!json_utils::valid_flag_name(name)) { ctx.result_text("error: invalid project name"); return; }
      (void)be->cmd("Ps " + name);
      ctx.result_text("saved: " + name);
    }));
  db_.register_function("r2sql_project_open", 1, xsql::ScalarFn(
    [be](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
      if (argc < 1 || argv[0].is_null()) { ctx.result_text("error: project name required"); return; }
      std::string name = argv[0].as_text();
      if (!json_utils::valid_flag_name(name)) { ctx.result_text("error: invalid project name"); return; }
      (void)be->cmd("P " + name);
      ctx.result_text("opened: " + name);
    }));
  // Define a type from a one-line C declaration (`td "<decl>"`), the
  // create-counterpart to DELETE FROM types (a struct decl doesn't fit the
  // types table's columns).
  db_.register_function("r2sql_type_define", 1, xsql::ScalarFn(
    [be](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
      if (argc < 1 || argv[0].is_null()) { ctx.result_text("error: C declaration required"); return; }
      std::string decl = argv[0].as_text();
      // radare2's `td` requires the WHOLE command r2-quoted so the `;`/`{}` in
      // the C declaration aren't treated as command separators/grouping.
      (void)be->cmd("\"td " + decl + "\"");
      ctx.result_text("ok");
    }));
}

void Session::detect_decompiler_() {
  // Probe pdg?, pdd?, pdc? — the first one that produces non-empty help
  // text wins. Commands that aren't registered return empty in r2.
  struct Probe { const char* probe; const char* cmd; DecompilerKind kind; };
  static const Probe probes[] = {
    {"pdg?", "pdg", DecompilerKind::Ghidra},
    {"pdd?", "pdd", DecompilerKind::Dec},
    {"pdc?", "pdc", DecompilerKind::Pdc},
  };
  for (auto& p : probes) {
    auto out = backend_->cmd(p.probe);
    if (!out.empty() && out.find("Usage:") != std::string::npos) {
      decompiler_kind_ = p.kind;
      decompiler_cmd_  = p.cmd;
      register_decompiler_table_if_available(*this);
      return;
    }
  }
}

}  // namespace r2sql
