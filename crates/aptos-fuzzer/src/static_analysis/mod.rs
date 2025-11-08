mod bytecode;
mod detectors;

use std::collections::HashMap;

use aptos_move_binary_format::CompiledModule;
use aptos_move_core_types::language_storage::ModuleId;
pub use bytecode::{
    build_targets_for_module, collect_function_infos, dummy_source_map, get_def_bytecode, FunctionInfo,
};
pub use detectors::{analyze_module, FindingKind, StaticAnalysisFinding};
use move_model::model::GlobalEnv;

use crate::executor::aptos_custom_state::AptosCustomState;

fn build_compiled_map(state: &AptosCustomState, targets: &[ModuleId]) -> HashMap<ModuleId, CompiledModule> {
    let target_set: std::collections::BTreeSet<_> = targets.iter().cloned().collect();
    let mut compiled = HashMap::new();
    for (_module_id, bytes) in state.module_bytes() {
        if let Ok(module) = CompiledModule::deserialize(bytes.as_ref()) {
            if target_set.contains(&module.self_id()) {
                compiled.insert(module.self_id(), module);
            }
        }
    }
    compiled
}

fn find_module_env<'env>(env: &'env GlobalEnv, module_id: &ModuleId) -> Option<move_model::model::ModuleEnv<'env>> {
    for module in env.get_modules() {
        let module_name = module.get_name();
        let address_matches = match module_name.addr() {
            move_model::ast::Address::Numerical(addr) => addr == module_id.address(),
            _ => false,
        };
        if !address_matches {
            continue;
        }
        let name_symbol = module_name.name();
        let name_str = env.symbol_pool().string(name_symbol);
        if name_str.as_str() == module_id.name().as_str() {
            return Some(module);
        }
    }
    None
}

pub fn run_static_analysis(state: &AptosCustomState, targets: &[ModuleId]) -> Vec<StaticAnalysisFinding> {
    let compiled_map = build_compiled_map(state, targets);
    if compiled_map.is_empty() {
        return Vec::new();
    }

    let mut env = GlobalEnv::new();
    for module in compiled_map.values() {
        if let Ok(source_map) = dummy_source_map(module) {
            // ignore errors; we only care about successful loads
            let _ = env.load_compiled_module(true, module.clone(), source_map);
        }
    }

    let mut findings = Vec::new();
    for target in targets {
        if let Some(compiled) = compiled_map.get(target) {
            if let Some(module_env) = find_module_env(&env, &compiled.self_id()) {
                findings.extend(detectors::analyze_module(&module_env, compiled, env.symbol_pool()));
            }
        }
    }

    findings
}
