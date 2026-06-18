// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
#include <r2sql/backend_mock.hpp>

namespace r2sql {

MockBackend::MockBackend() = default;

void MockBackend::set_response(std::string command, std::string response) {
  std::lock_guard lock(m_);
  canned_[std::move(command)] = std::move(response);
}

void MockBackend::set_responses(std::initializer_list<std::pair<std::string, std::string>> kvs) {
  std::lock_guard lock(m_);
  for (auto& kv : kvs) canned_[kv.first] = kv.second;
}

const std::vector<std::string>& MockBackend::issued_commands() const {
  return issued_;
}

void MockBackend::clear_issued() {
  std::lock_guard lock(m_);
  issued_.clear();
}

std::string MockBackend::cmd(std::string_view command) {
  std::lock_guard lock(m_);
  std::string key(command);
  issued_.push_back(key);
  auto it = canned_.find(key);
  if (it == canned_.end()) return std::string{};
  return it->second;
}

std::unique_ptr<Backend> make_mock_backend() {
  return std::make_unique<MockBackend>();
}

}  // namespace r2sql
