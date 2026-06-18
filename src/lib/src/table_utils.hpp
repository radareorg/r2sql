// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Small helpers shared by table definitions.

#pragma once

#include <r2sql/backend.hpp>

#include <cctype>
#include <cstddef>
#include <string>
#include <string_view>

namespace r2sql::table_utils {

inline std::string trim_ascii(std::string s) {
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) {
    s.pop_back();
  }
  size_t first = 0;
  while (first < s.size() && std::isspace(static_cast<unsigned char>(s[first]))) {
    ++first;
  }
  if (first > 0) s.erase(0, first);
  return s;
}

inline size_t quick_count(Backend* be, std::string_view command, size_t fallback) {
  if (!be) return fallback;
  std::string out = trim_ascii(be->cmd(command));
  if (out.empty()) return fallback;
  try {
    return static_cast<size_t>(std::stoull(out, nullptr, 0));
  } catch (...) {
    return fallback;
  }
}

}  // namespace r2sql::table_utils
