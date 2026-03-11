// Copyright (c) 2026 Proton AG
//
// This file is part of ProtonVPN.
//
// ProtonVPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// ProtonVPN is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.

use core::panic;
use std::env::var;
use std::process::Command;
use std::str::RSplitN;
use winresource::{VersionInfo, WindowsResource};

pub fn set_dll_properties() {
    // Produces something like "v0.1-31-gc364e3f0" or "0.1-31-gc364e3f0"
    let output = Command::new("git")
        .args(["describe", "--tags", "--long", "--always", "--abbrev=8"])
        .output()
        .expect("Failed to run git describe");
    let describe: String = String::from_utf8_lossy(&output.stdout).trim().to_string();
    println!("Git describe output: {describe}");

    // Parse "v0.1-31-gc364e3f0" into (tag, commits_since, hash)
    // Split from the right since the tag itself could contain dashes
    let mut parts: RSplitN<'_, char> = describe.rsplitn(3, '-');
    let hash_raw: &str = parts.next().expect("ERROR! Missing hash");       // "gc364e3f0"
    let count_str: &str = parts.next().expect("ERROR! Missing count");     // "31"
    let tag_raw: &str = parts.next().expect("ERROR! Missing tag");         // "v0.1"

    // Strip leading 'v' from tag and 'g' from hash
    let tag: &str = tag_raw.trim_start_matches('v');
    let hash: &str = hash_raw.trim_start_matches('g');
    let commits_since: u16 = count_str.parse().unwrap_or(0);

    // Parse X.Y from tag (or X.Y.Z)
    let tag_parts: Vec<u16> = tag.split('.').filter_map(|s| s.parse().ok()).collect();
    let (major, minor, patch, release) = match tag_parts.as_slice() {
        [x, y, z, ..] => (*x, *y, *z, commits_since),
        [x, y] => (*x, *y, commits_since, 0),
        [x] => (*x, 0, commits_since, 0),
        _ => (0, 0, commits_since, 0),
    };

    // Final product version string: "0.1.31.0-c364e3f0"
    let product_version_string: String = format!("{major}.{minor}.{patch}.{release}-{hash}");
    println!("Product version: {product_version_string}");

    // Get architecture
    let architecture: String = var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let architecture: &str = match architecture.as_str() {
        "x86_64" => "x64",
        "x86" => "x32",
        "aarch64" => "arm64",
        "arm" => "arm32",
        _ => panic!("ERROR! The following architecture is not recognized: {architecture}"),
    };
    let file_description: String = format!("ProTUN Windows {architecture}");
    println!("File description: {file_description}");

    let mut res: WindowsResource = WindowsResource::new();

    res.set_version_info(
        VersionInfo::FILEVERSION,
        ((major as u64) << 48) | ((minor as u64) << 32) | ((patch as u64) << 16) | (release as u64),
    );

    res.set("ProductVersion", &product_version_string);
    res.set("FileDescription", &file_description);
    res.set("ProductName", "Proton VPN");
    res.set("LegalCopyright", "Copyright © 2026 Proton AG");

    res.compile().expect("Failed to compile Windows resource");
}