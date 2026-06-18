// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <r2sql/backend.hpp>

#include <xsql/database.hpp>
#include <xsql/json.hpp>

#include <memory>
#include <mutex>
#include <string>
#include <string_view>

namespace r2sql {

class Session {
public:
  // Create a session bound to a Backend. Registers all virtual tables.
  // Ownership of `backend` is transferred.
  explicit Session(std::unique_ptr<Backend> backend);
  ~Session();

  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;

  // Direct query access via libxsql.
  xsql::Database& db() { return db_; }
  const xsql::Database& db() const { return db_; }

  // The bound backend (never null after construction).
  Backend& backend() { return *backend_; }
  Backend* backend_ptr() { return backend_.get(); }

  // Convenience: execute a SQL statement and return the result.
  // Thread-safe: serialized against other query()/raw_cmd() calls so a shared
  // Session can back an HTTP/MCP server with use_queue=false (concurrent
  // clients) as well as interactive use, without racing SQLite or the backend.
  xsql::Result query(std::string_view sql);

  // Escape hatch: forward an arbitrary r2 command straight to the backend
  // and return its raw textual output. For commands that have no SQL surface
  // (e.g. "aaa", "s 0x401000", "CC text @ addr"). Empty output is valid.
  // Serialized against query()/raw_cmd() (see query()).
  std::string raw_cmd(std::string command);

  // Whether the decompiler was detected at session bootstrap.
  // Populated by tables_decompiler.cpp's runtime probe.
  bool has_decompiler() const { return decompiler_kind_ != DecompilerKind::None; }
  std::string_view decompiler_command() const { return decompiler_cmd_; }

  enum class DecompilerKind { None, Ghidra, Dec, Pdc };
  DecompilerKind decompiler_kind() const { return decompiler_kind_; }

private:
  void register_all_tables_();
  void register_functions_();
  void detect_decompiler_();

  std::unique_ptr<Backend> backend_;
  xsql::Database db_;
  DecompilerKind decompiler_kind_ = DecompilerKind::None;
  std::string decompiler_cmd_;
  // Serializes query()/raw_cmd(): one SQLite/backend operation at a time.
  std::mutex query_mu_;
};

}  // namespace r2sql
