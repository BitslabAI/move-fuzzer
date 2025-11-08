use std::path::PathBuf;

use aptos_fuzzer::static_analysis::run_static_analysis;
use aptos_fuzzer::AptosFuzzerState;

#[test]
fn static_analysis_handles_recursive_assignments() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let abi_path = workspace_root.join("move/overflow/build/overflow/abis");
    let module_path = workspace_root.join("move/overflow/build/overflow/bytecode_modules/math_u256.mv");

    let state = AptosFuzzerState::new(Some(abi_path), Some(module_path));
    let _ = run_static_analysis(state.aptos_state(), state.target_modules());
}
