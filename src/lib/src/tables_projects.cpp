// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 Elias Bachaalany
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// projects — radare2 project list (`Plj`). SELECT lists saved projects;
// DELETE FROM projects WHERE name='X' removes it on disk (`P- X`). Saving and
// opening a project mid-session are actions, not row states, so they are
// exposed as the r2sql_project_save('name') / r2sql_project_open('name')
// scalar functions (see Session::register_functions_). The CLI `-w --project`
// save-on-exit path is unchanged and complementary.

#include <r2sql/session.hpp>
#include <r2sql/backend.hpp>
#include <xsql/vtable.hpp>

#include "tables.hpp"
#include "json_utils.hpp"

namespace r2sql {

namespace {
struct ProjectRow {
  std::string name;
};
}  // namespace

void register_projects_table(Session& s) {
  auto def = xsql::cached_table<ProjectRow>("projects")
    .no_shared_cache()
    .estimate_rows([]() -> size_t { return 32; })
    .cache_builder([be = s.backend_ptr()](std::vector<ProjectRow>& rows) {
      auto arr = be->cmd_json("Plj");
      if (!arr.is_array()) return;
      for (auto& j : arr) {
        ProjectRow r;
        if (j.is_string())      r.name = j.get<std::string>();
        else if (j.is_object()) r.name = json_utils::str(j, "name");
        if (!r.name.empty()) rows.push_back(std::move(r));
      }
    })
    .column_text("name", [](const ProjectRow& r) { return r.name; })
    .deletable([be = s.backend_ptr()](ProjectRow& r) -> bool {
      if (r.name.empty() || !json_utils::valid_flag_name(r.name)) {
        xsql::set_vtab_error("projects: refusing to delete an unsafe/empty project name");
        return false;
      }
      (void)be->cmd("P- " + r.name);
      return true;
    })
    .build();
  s.db().register_and_create_cached_table(def);
}

}  // namespace r2sql
