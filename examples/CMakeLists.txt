# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2024-2026 Elias Bachaalany
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
# r2sql examples — minimal consumers of the libr2sql C++ API.

add_executable(list_funcs list_funcs.cpp)
target_link_libraries(list_funcs PRIVATE r2sql::r2sql)
target_compile_features(list_funcs PRIVATE cxx_std_20)

# Auto-copy r2 DLLs (Windows) next to the example exe so it can launch
# when linked against libr.
if(WIN32 AND Radare2_FOUND AND R2SQL_HAVE_LIBR)
  add_custom_command(TARGET list_funcs POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${Radare2_ROOT}/bin" "$<TARGET_FILE_DIR:list_funcs>"
    COMMENT "Copying radare2 DLLs next to list_funcs"
  )
endif()
