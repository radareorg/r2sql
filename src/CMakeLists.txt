# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2024-2026 Elias Bachaalany
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
add_subdirectory(lib)

if(R2SQL_BUILD_CLI AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cli/CMakeLists.txt")
  add_subdirectory(cli)
endif()

if(R2SQL_BUILD_PLUGIN AND R2SQL_FULL_ENABLED AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/plugin/CMakeLists.txt")
  add_subdirectory(plugin)
endif()
