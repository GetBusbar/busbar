// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub(crate) fn pgo_from_flags(flags: &[&str]) -> bool {
    flag_value(flags, "profile-use").is_some()
}

fn codegen_options<'a>(flags: &'a [&'a str]) -> impl Iterator<Item = &'a str> {
    let mut flags = flags.iter().copied();
    std::iter::from_fn(move || loop {
        let flag = flags.next()?;
        if flag == "-C" {
            return flags.next();
        }
        if let Some(option) = flag.strip_prefix("-C") {
            return Some(option);
        }
    })
}

pub(crate) fn flag_value(flags: &[&str], name: &str) -> Option<String> {
    let mut value = None;
    for option in codegen_options(flags) {
        let found = match option.split_once('=') {
            Some((key, value)) if key == name => value,
            None if option == "lto" && name == "lto" => "fat",
            _ => continue,
        };
        if name == "target-feature" {
            let combined = value.get_or_insert_with(String::new);
            if !combined.is_empty() && !found.is_empty() {
                combined.push(',');
            }
            combined.push_str(found);
        } else {
            value = Some(found.to_string());
        }
    }
    value
}
