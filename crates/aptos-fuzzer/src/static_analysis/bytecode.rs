use std::collections::BTreeMap;

use anyhow::Result;
use aptos_move_binary_format::binary_views::BinaryIndexedView;
use aptos_move_binary_format::CompiledModule;
use move_bytecode_source_map::source_map::SourceMap;
use move_command_line_common::files::FileHash;
use move_ir_types::location::Loc as BytecodeLoc;
use move_model::model::{FunctionEnv, GlobalEnv, ModuleEnv};
use move_model::ty::Type;
use move_stackless_bytecode::function_target::FunctionTarget;
use move_stackless_bytecode::function_target_pipeline::{FunctionTargetsHolder, FunctionVariant};
use move_stackless_bytecode::stackless_bytecode::{Bytecode, Operation};

#[derive(Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub index: usize,
    pub bytecode: Vec<Bytecode>,
    pub local_types: Vec<Type>,
    pub def_sites: Vec<Vec<usize>>,
}

impl FunctionInfo {
    pub fn from_target(fun_env: &FunctionEnv, target: &FunctionTarget) -> Self {
        let bytecode = target.get_bytecode().to_vec();
        let local_count = target.get_local_count();
        let mut local_types = Vec::with_capacity(local_count);
        for i in 0..local_count {
            local_types.push(target.get_local_type(i).clone());
        }
        let def_sites = compute_def_sites(&bytecode, local_count);
        let index = fun_env.get_def_idx().map(|idx| idx.0 as usize).unwrap_or(usize::MAX);
        Self {
            name: fun_env.get_name_str().to_string(),
            index,
            bytecode,
            local_types,
            def_sites,
        }
    }
}

pub fn get_def_bytecode<'a>(function: &'a FunctionInfo, temp: usize, offset: usize) -> Option<&'a Bytecode> {
    if temp >= function.def_sites.len() {
        return None;
    }
    let defs = &function.def_sites[temp];
    if defs.is_empty() {
        return None;
    }
    let mut candidates: Vec<_> = defs.iter().copied().filter(|idx| *idx < offset).collect();
    candidates.sort_unstable();
    let chosen = candidates.last().copied().unwrap_or(defs[0]);
    function.bytecode.get(chosen)
}

pub fn compute_def_sites(code: &[Bytecode], locals: usize) -> Vec<Vec<usize>> {
    let mut defs = vec![Vec::new(); locals];
    for (offset, instr) in code.iter().enumerate() {
        match instr {
            Bytecode::Assign(_, dst, _, _) => {
                defs[*dst].push(offset);
            }
            Bytecode::Call(_, dests, oper, _, abort) => {
                for dst in dests {
                    defs[*dst].push(offset);
                }
                if let Some(move_stackless_bytecode::stackless_bytecode::AbortAction(_, temp)) = abort {
                    defs[*temp].push(offset);
                }
                if matches!(oper, Operation::BorrowLoc | Operation::BorrowField(..)) {
                    // borrow ops do not define new values beyond dests
                }
            }
            Bytecode::Load(_, dst, _) => {
                defs[*dst].push(offset);
            }
            _ => {}
        }
    }
    defs
}

pub fn collect_function_infos(module_env: &ModuleEnv, holder: &FunctionTargetsHolder) -> BTreeMap<usize, FunctionInfo> {
    let mut infos = BTreeMap::new();
    for fun_env in module_env.get_functions() {
        if fun_env.is_native() || fun_env.is_inline() {
            continue;
        }
        if !holder.has_target(&fun_env, &FunctionVariant::Baseline) {
            continue;
        }
        let target = holder.get_target(&fun_env, &FunctionVariant::Baseline);
        let info = FunctionInfo::from_target(&fun_env, &target);
        infos.insert(info.index, info);
    }
    infos
}

pub fn build_targets_for_module(_env: &GlobalEnv, module_env: &ModuleEnv) -> FunctionTargetsHolder {
    let mut holder = FunctionTargetsHolder::default();
    for fun_env in module_env.get_functions() {
        if fun_env.is_native() || fun_env.is_inline() {
            continue;
        }
        holder.add_target(&fun_env);
    }
    holder
}

pub fn dummy_source_map(module: &CompiledModule) -> Result<SourceMap> {
    let view = BinaryIndexedView::Module(module);
    SourceMap::dummy_from_view(&view, BytecodeLoc::new(FileHash::empty(), 0, 0))
}
