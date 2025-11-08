use std::path::PathBuf;

use aptos_fuzzer::static_analysis::run_static_analysis;
use aptos_fuzzer::AptosFuzzerState;

#[test]
fn static_analysis_handles_recursive_assignments() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let modules_dir = workspace_root.join("move/overflow/build/overflow");

    let state = AptosFuzzerState::new(modules_dir);
    let _ = run_static_analysis(state.aptos_state(), state.target_modules());
}
