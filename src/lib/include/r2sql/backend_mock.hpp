// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <r2sql/backend.hpp>

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace r2sql {

// In-memory mock backend: records every command sent to it and replies with
// canned responses. Unknown commands return an empty string (matching r2's
// behaviour for unknown / no-output commands). Useful for embedding r2sql or
// driving it offline without a live radare2.
class MockBackend : public Backend {
public:
  MockBackend();
  ~MockBackend() override = default;

  // Register a canned response for an exact command match.
  void set_response(std::string command, std::string response);

  // Register canned responses for many commands at once.
  void set_responses(std::initializer_list<std::pair<std::string, std::string>> kvs);

  // The list of commands the session has issued, in order.
  const std::vector<std::string>& issued_commands() const;

  void clear_issued();

  // Backend interface
  std::string cmd(std::string_view command) override;
  bool alive() const override { return true; }
  std::string_view name() const override { return "mock"; }

private:
  mutable std::mutex m_;
  std::unordered_map<std::string, std::string> canned_;
  std::vector<std::string> issued_;
};

std::unique_ptr<Backend> make_mock_backend();

}  // namespace r2sql
