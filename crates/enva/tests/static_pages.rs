use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn embedded_ui_contains_selection_controls_for_import_and_export() {
    let html = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("web")
            .join("index.html"),
    )
    .unwrap();

    assert!(html.contains("id=\"exportSelectionList\""));
    assert!(html.contains("id=\"exportSelectionSummary\""));
    assert!(html.contains("id=\"importConflictSummary\""));
    assert!(html.contains("setAllImportRows(true)"));
    assert!(html.contains("setAllExportRows(true)"));
    assert!(html.contains("Replace existing"));
}

#[test]
fn demo_page_contains_matching_selection_controls() {
    let html = fs::read_to_string(repo_root().join("site").join("demo.html")).unwrap();

    assert!(html.contains("id=\"exportSelectionList\""));
    assert!(html.contains("id=\"exportSelectionSummary\""));
    assert!(html.contains("id=\"importConflictSummary\""));
    assert!(html.contains("setAllImportRows(true)"));
    assert!(html.contains("setAllExportRows(true)"));
    assert!(html.contains("Replace existing"));
}
