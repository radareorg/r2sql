// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
#include <r2sql/backend.hpp>

namespace r2sql {

nlohmann::json Backend::cmd_json(std::string_view command, BackendError* err) {
  std::string text = cmd(command);
  if (text.empty()) return nlohmann::json::value_t::null;
  // r2 sometimes appends a trailing newline / nul; trim them.
  while (!text.empty() && (text.back() == '\n' || text.back() == '\r' ||
                            text.back() == '\0' || text.back() == ' ')) {
    text.pop_back();
  }
  if (text.empty()) return nlohmann::json::value_t::null;
  try {
    return nlohmann::json::parse(text);
  } catch (const std::exception& e) {
    if (err) err->message = std::string("json parse error: ") + e.what();
    return nlohmann::json::value_t::null;
  }
}

}  // namespace r2sql
