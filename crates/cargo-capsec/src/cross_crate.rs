//! Cross-crate authority propagation.
//!
//! Converts export maps from dependency crates into [`CustomAuthority`] values
//! that can be injected into the detector. This bridges dependency analysis
//! (Phase 1) with workspace crate analysis (Phase 2).

use crate::authorities::CustomAuthority;
use crate::export_map::CrateExportMap;

/// Converts a collection of export maps into [`CustomAuthority`] values for
/// injection into the detector.
///
/// For each entry in each export map, creates a `CustomAuthority` with the
/// module-qualified path split into segments. The suffix matching in
/// [`Detector::matches_custom_path`](crate::detector) handles both
/// fully-qualified calls and imported calls.
#[must_use]
pub fn export_map_to_custom_authorities(export_maps: &[CrateExportMap]) -> Vec<CustomAuthority> {
    let mut customs = Vec::new();

    for map in export_maps {
        for (key, authorities) in &map.exports {
            let path: Vec<String> = key.split("::").map(String::from).collect();

            for auth in authorities {
                customs.push(CustomAuthority {
                    path: path.clone(),
                    category: auth.category.clone(),
                    risk: auth.risk,
                    description: format!(
                        "Cross-crate: {}() → {} [{}]",
                        key,
                        auth.leaf_call,
                        auth.category.label(),
                    ),
                });
            }
        }
    }

    customs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorities::{Category, Risk};
    use crate::export_map::{CrateExportMap, ExportedAuthority};
    use std::collections::HashMap;

    fn make_export_map(
        crate_name: &str,
        entries: Vec<(&str, Category, Risk, &str)>,
    ) -> CrateExportMap {
        let mut exports = HashMap::new();
        for (key, category, risk, leaf_call) in entries {
            exports
                .entry(key.to_string())
                .or_insert_with(Vec::new)
                .push(ExportedAuthority {
                    category,
                    risk,
                    leaf_call: leaf_call.to_string(),
                    is_transitive: false,
                });
        }
        CrateExportMap {
            crate_name: crate_name.to_string(),
            crate_version: "1.0.0".to_string(),
            exports,
        }
    }

    #[test]
    fn single_export_map() {
        let map = make_export_map(
            "reqwest",
            vec![(
                "reqwest::get",
                Category::Net,
                Risk::High,
                "TcpStream::connect",
            )],
        );
        let customs = export_map_to_custom_authorities(&[map]);
        assert_eq!(customs.len(), 1);
        assert_eq!(customs[0].path, vec!["reqwest", "get"]);
        assert_eq!(customs[0].category, Category::Net);
        assert!(customs[0].description.contains("Cross-crate"));
        assert!(customs[0].description.contains("reqwest::get"));
    }

    #[test]
    fn multiple_exports_per_crate() {
        let map = make_export_map(
            "tokio",
            vec![
                (
                    "tokio::fs::read",
                    Category::Fs,
                    Risk::Medium,
                    "std::fs::read",
                ),
                (
                    "tokio::net::connect",
                    Category::Net,
                    Risk::High,
                    "TcpStream::connect",
                ),
            ],
        );
        let customs = export_map_to_custom_authorities(&[map]);
        assert_eq!(customs.len(), 2);
    }

    #[test]
    fn multiple_crates() {
        let map1 = make_export_map(
            "reqwest",
            vec![(
                "reqwest::get",
                Category::Net,
                Risk::High,
                "TcpStream::connect",
            )],
        );
        let map2 = make_export_map(
            "rusqlite",
            vec![(
                "rusqlite::execute",
                Category::Ffi,
                Risk::High,
                "extern sqlite3_exec",
            )],
        );
        let customs = export_map_to_custom_authorities(&[map1, map2]);
        assert_eq!(customs.len(), 2);
    }

    #[test]
    fn empty_export_maps() {
        let customs = export_map_to_custom_authorities(&[]);
        assert!(customs.is_empty());
    }

    #[test]
    fn empty_exports_in_map() {
        let map = CrateExportMap {
            crate_name: "empty".to_string(),
            crate_version: "1.0.0".to_string(),
            exports: HashMap::new(),
        };
        let customs = export_map_to_custom_authorities(&[map]);
        assert!(customs.is_empty());
    }

    #[test]
    fn path_segments_split_correctly() {
        let map = make_export_map(
            "reqwest",
            vec![(
                "reqwest::blocking::client::get",
                Category::Net,
                Risk::High,
                "connect",
            )],
        );
        let customs = export_map_to_custom_authorities(&[map]);
        assert_eq!(
            customs[0].path,
            vec!["reqwest", "blocking", "client", "get"]
        );
    }
}
