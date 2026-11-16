#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# The C-HEADER cc job (ABI-MIN3-INTERFACE §7.8, §14; owner W1-A13; the coordinator adds its CI line). A launcher
# only: it runs the C arms with the job's own CC (default cc): the generated static asserts and the fixture under
# -std=c11 -Wall -Werror, and the fixture driven by its C host against the Rust shim's bytes.
set -eu
exec cargo nextest run --locked -p busbar-plugin-test --test cases --no-tests=fail \
  -E 'test(=c_header::the_static_asserts_compile_with_the_header) | test(=c_error_records::the_c_helpers_write_the_same_bytes_and_arguments_as_the_rust_shim)'
