use std::collections::{BTreeMap, HashSet};

use aptos_move_binary_format::access::ModuleAccess;
use aptos_move_binary_format::internals::ModuleIndex;
use aptos_move_binary_format::CompiledModule;
use move_model::model::ModuleEnv;
use move_model::symbol::SymbolPool;
use move_model::ty::{PrimitiveType, Type};
use move_stackless_bytecode::stackless_bytecode::{Bytecode, Constant, Operation};

use super::bytecode::{collect_function_infos, get_def_bytecode, FunctionInfo};

#[derive(Debug, Clone)]
pub enum FindingKind {
    BoolJudgement,
    InfiniteLoop,
    PrecisionLoss,
    TypeConversion,
    UncheckedReturn,
    UnusedConst,
    UnusedPrivateFunction,
    UnusedFriendFunction,
    UnusedStruct,
}

impl FindingKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            FindingKind::BoolJudgement => "UnnecessaryBoolComparison",
            FindingKind::InfiniteLoop => "PotentialInfiniteLoop",
            FindingKind::PrecisionLoss => "PrecisionLoss",
            FindingKind::TypeConversion => "RedundantTypeConversion",
            FindingKind::UncheckedReturn => "UncheckedReturnValue",
            FindingKind::UnusedConst => "UnusedConstant",
            FindingKind::UnusedPrivateFunction => "UnusedPrivateFunction",
            FindingKind::UnusedFriendFunction => "UnusedFriendFunction",
            FindingKind::UnusedStruct => "UnusedStruct",
        }
    }
}

#[derive(Debug, Clone)]
pub struct StaticAnalysisFinding {
    pub kind: FindingKind,
    pub module: String,
    pub function: Option<String>,
    pub detail: String,
}

impl StaticAnalysisFinding {
    pub fn new(kind: FindingKind, module: String, function: Option<String>, detail: String) -> Self {
        Self {
            kind,
            module,
            function,
            detail,
        }
    }
}

pub fn analyze_module(
    module_env: &ModuleEnv,
    compiled: &CompiledModule,
    symbol_pool: &SymbolPool,
) -> Vec<StaticAnalysisFinding> {
    let mut findings = Vec::new();
    let module_name = module_env.get_full_name_str().to_string();
    let holder = super::bytecode::build_targets_for_module(module_env.env, module_env);
    let functions = collect_function_infos(module_env, &holder);
    println!("Analyzing module: {}", module_name);

    analyze_bool_judgement(&module_name, &functions, &mut findings);
    analyze_infinite_loop(&module_name, &functions, &mut findings);
    analyze_precision_loss(&module_name, &functions, symbol_pool, &mut findings);
    analyze_type_conversion(&module_name, &functions, &mut findings);
    analyze_unchecked_return(&module_name, &functions, symbol_pool, &mut findings);
    analyze_unused_const(&module_name, compiled, &mut findings);
    analyze_unused_private_fun(&module_name, compiled, &mut findings);
    analyze_unused_struct(&module_name, compiled, &mut findings);

    findings
}

fn analyze_unused_private_fun(module_name: &str, compiled: &CompiledModule, findings: &mut Vec<StaticAnalysisFinding>) {
    use aptos_move_binary_format::file_format::Visibility;
    let mut private = BTreeMap::new();
    let mut friend = BTreeMap::new();
    for (idx, def) in compiled.function_defs().iter().enumerate() {
        let handle = compiled.function_handle_at(def.function);
        let name = compiled.identifier_at(handle.name).to_string();
        match def.visibility {
            Visibility::Private => {
                if name != "init" && !def.is_entry {
                    private.insert(idx as u16, name);
                }
            }
            Visibility::Friend => {
                if !def.is_entry {
                    friend.insert(idx as u16, name);
                }
            }
            _ => {}
        }
    }

    let mut used = HashSet::new();
    for func in compiled.function_defs() {
        if let Some(code) = &func.code {
            for instr in &code.code {
                match instr {
                    aptos_move_binary_format::file_format::Bytecode::Call(idx) => {
                        if let Some(def_idx) = find_function_definition(compiled, *idx) {
                            used.insert(def_idx.0);
                        }
                    }
                    aptos_move_binary_format::file_format::Bytecode::CallGeneric(idx) => {
                        let handle = compiled.function_instantiation_at(*idx).handle;
                        if let Some(def_idx) = find_function_definition(compiled, handle) {
                            used.insert(def_idx.0);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    for (idx, name) in private {
        if !used.contains(&idx) {
            findings.push(StaticAnalysisFinding::new(
                FindingKind::UnusedPrivateFunction,
                module_name.to_string(),
                None,
                format!("Private function `{}` is never used", name),
            ));
        }
    }
    for (idx, name) in friend {
        if !used.contains(&idx) {
            findings.push(StaticAnalysisFinding::new(
                FindingKind::UnusedFriendFunction,
                module_name.to_string(),
                None,
                format!("Friend function `{}` is never used", name),
            ));
        }
    }
}

fn find_function_definition(
    module: &CompiledModule,
    handle_idx: aptos_move_binary_format::file_format::FunctionHandleIndex,
) -> Option<aptos_move_binary_format::file_format::FunctionDefinitionIndex> {
    for (idx, def) in module.function_defs().iter().enumerate() {
        if def.function == handle_idx {
            return Some(aptos_move_binary_format::file_format::FunctionDefinitionIndex(
                idx as u16,
            ));
        }
    }
    None
}

fn analyze_unused_struct(module_name: &str, compiled: &CompiledModule, findings: &mut Vec<StaticAnalysisFinding>) {
    let mut struct_used = vec![false; compiled.struct_defs().len()];
    for func in compiled.function_defs() {
        let handle = compiled.function_handle_at(func.function);
        let params = compiled.signature_at(handle.parameters);
        for token in &params.0 {
            mark_struct_in_signature(token, &mut struct_used);
        }
        if let Some(code) = &func.code {
            for instr in &code.code {
                match instr {
                    aptos_move_binary_format::file_format::Bytecode::Pack(idx) |
                    aptos_move_binary_format::file_format::Bytecode::Unpack(idx) |
                    aptos_move_binary_format::file_format::Bytecode::ImmBorrowGlobal(idx) |
                    aptos_move_binary_format::file_format::Bytecode::MutBorrowGlobal(idx) => {
                        struct_used[idx.into_index()] = true;
                    }
                    _ => {}
                }
            }
        }
    }
    for (idx, used) in struct_used.into_iter().enumerate() {
        if !used {
            let def = compiled.struct_def_at(aptos_move_binary_format::file_format::StructDefinitionIndex(idx as u16));
            let name = compiled.identifier_at(compiled.struct_handle_at(def.struct_handle).name);
            findings.push(StaticAnalysisFinding::new(
                FindingKind::UnusedStruct,
                module_name.to_string(),
                None,
                format!("Struct `{}` is never constructed", name),
            ));
        }
    }
}

fn mark_struct_in_signature(token: &aptos_move_binary_format::file_format::SignatureToken, used: &mut [bool]) {
    use aptos_move_binary_format::file_format::SignatureToken;
    match token {
        SignatureToken::Struct(idx) => {
            let pos = idx.into_index();
            if pos < used.len() {
                used[pos] = true;
            }
        }
        SignatureToken::StructInstantiation(idx, _) => {
            let pos = idx.into_index();
            if pos < used.len() {
                used[pos] = true;
            }
        }
        SignatureToken::Vector(inner) | SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) => {
            mark_struct_in_signature(inner, used)
        }
        SignatureToken::TypeParameter(_) |
        SignatureToken::Bool |
        SignatureToken::U8 |
        SignatureToken::U16 |
        SignatureToken::U32 |
        SignatureToken::U64 |
        SignatureToken::U128 |
        SignatureToken::U256 |
        SignatureToken::Address |
        SignatureToken::Signer |
        SignatureToken::Function(_, _, _) => {}
    }
}

#[cfg(test)]
mod tests {
    use aptos_move_binary_format::file_format::{SignatureToken, StructHandleIndex};

    use super::mark_struct_in_signature;

    #[test]
    fn mark_struct_in_signature_out_of_bounds_safe() {
        let mut used = vec![false; 2];
        let idx = StructHandleIndex::new(17);
        let token = SignatureToken::Struct(idx);
        mark_struct_in_signature(&token, &mut used);
        assert_eq!(used, vec![false; 2]);
    }
}

fn analyze_bool_judgement(
    module_name: &str,
    functions: &BTreeMap<usize, FunctionInfo>,
    findings: &mut Vec<StaticAnalysisFinding>,
) {
    for info in functions.values() {
        for (offset, instr) in info.bytecode.iter().enumerate() {
            match instr {
                Bytecode::Call(_, _, Operation::Eq, srcs, _) | Bytecode::Call(_, _, Operation::Neq, srcs, _) => {
                    if srcs.len() != 2 {
                        continue;
                    }
                    let left = get_def_bytecode(info, srcs[0], offset);
                    let right = get_def_bytecode(info, srcs[1], offset);
                    if (left.map(is_ld_bool).unwrap_or(false) && right.map(|bc| ret_is_bool(info, bc)).unwrap_or(false)) ||
                        (right.map(is_ld_bool).unwrap_or(false) &&
                            left.map(|bc| ret_is_bool(info, bc)).unwrap_or(false))
                    {
                        findings.push(StaticAnalysisFinding::new(
                            FindingKind::BoolJudgement,
                            module_name.to_string(),
                            Some(info.name.clone()),
                            format!("Bool comparison against constant at offset {}", offset),
                        ));
                        break;
                    }
                }
                _ => {}
            }
        }
    }
}

fn is_ld_bool(bytecode: &Bytecode) -> bool {
    matches!(
        bytecode,
        Bytecode::Load(_, _, Constant::Bool(true)) | Bytecode::Load(_, _, Constant::Bool(false))
    )
}

fn ret_is_bool(info: &FunctionInfo, bytecode: &Bytecode) -> bool {
    match bytecode {
        Bytecode::Call(_, dsts, _, _, _) => {
            dsts.get(0).and_then(|idx| info.local_types.get(*idx)) == Some(&Type::Primitive(PrimitiveType::Bool))
        }
        Bytecode::Assign(_, dst, _, _) | Bytecode::Load(_, dst, _) => {
            info.local_types.get(*dst) == Some(&Type::Primitive(PrimitiveType::Bool))
        }
        _ => false,
    }
}

fn analyze_infinite_loop(
    module_name: &str,
    functions: &BTreeMap<usize, FunctionInfo>,
    findings: &mut Vec<StaticAnalysisFinding>,
) {
    use aptos_move_binary_format::file_format::CodeOffset;
    for info in functions.values() {
        let label_offsets = Bytecode::label_offsets(&info.bytecode);
        for (offset, instr) in info.bytecode.iter().enumerate() {
            if let Bytecode::Branch(_, then_label, else_label, cond) = instr {
                if let Some(def) = get_def_bytecode(info, *cond, offset) {
                    if let Bytecode::Load(_, _, Constant::Bool(value)) = def {
                        let then_offset = label_offsets.get(then_label).cloned();
                        let else_offset = label_offsets.get(else_label).cloned();
                        let current = offset as CodeOffset;
                        let backward = if *value {
                            then_offset.map(|v| v <= current)
                        } else {
                            else_offset.map(|v| v <= current)
                        };
                        if backward.unwrap_or(false) {
                            findings.push(StaticAnalysisFinding::new(
                                FindingKind::InfiniteLoop,
                                module_name.to_string(),
                                Some(info.name.clone()),
                                format!("Constant branch at offset {}", offset),
                            ));
                            break;
                        }
                    }
                }
            }
        }
    }
}

fn analyze_precision_loss(
    module_name: &str,
    functions: &BTreeMap<usize, FunctionInfo>,
    symbol_pool: &SymbolPool,
    findings: &mut Vec<StaticAnalysisFinding>,
) {
    for info in functions.values() {
        for (offset, instr) in info.bytecode.iter().enumerate() {
            if let Bytecode::Call(_, _, Operation::Mul, srcs, _) = instr {
                if srcs.len() != 2 {
                    continue;
                }
                let left = get_def_bytecode(info, srcs[0], offset);
                let right = get_def_bytecode(info, srcs[1], offset);
                if matches_div_or_sqrt(info, left, symbol_pool) || matches_div_or_sqrt(info, right, symbol_pool) {
                    findings.push(StaticAnalysisFinding::new(
                        FindingKind::PrecisionLoss,
                        module_name.to_string(),
                        Some(info.name.clone()),
                        format!("Multiplication with prior division at offset {}", offset),
                    ));
                    break;
                }
            }
        }
    }
}

fn matches_div_or_sqrt(info: &FunctionInfo, bytecode: Option<&Bytecode>, symbol_pool: &SymbolPool) -> bool {
    let mut visited_instrs = HashSet::new();
    let mut visited_temps = HashSet::new();
    matches_div_or_sqrt_impl(info, bytecode, symbol_pool, &mut visited_instrs, &mut visited_temps)
}

fn matches_div_or_sqrt_impl(
    info: &FunctionInfo,
    bytecode: Option<&Bytecode>,
    symbol_pool: &SymbolPool,
    visited_instrs: &mut HashSet<usize>,
    visited_temps: &mut HashSet<usize>,
) -> bool {
    let Some(instr) = bytecode else {
        return false;
    };
    let ptr = instr as *const Bytecode as usize;
    if !visited_instrs.insert(ptr) {
        return false;
    }

    let result = match instr {
        Bytecode::Call(_, _, Operation::Div, _, _) => true,
        Bytecode::Call(_, _, Operation::Function(_, fun_id, _), _, _) => {
            symbol_pool.string(fun_id.symbol()).as_str() == "sqrt"
        }
        Bytecode::Assign(_, _, src, _) => {
            if !visited_temps.insert(*src) {
                false
            } else {
                let next = get_def_bytecode(info, *src, usize::MAX);
                let res = matches_div_or_sqrt_impl(info, next, symbol_pool, visited_instrs, visited_temps);
                visited_temps.remove(src);
                res
            }
        }
        _ => false,
    };

    visited_instrs.remove(&ptr);
    result
}

fn analyze_type_conversion(
    module_name: &str,
    functions: &BTreeMap<usize, FunctionInfo>,
    findings: &mut Vec<StaticAnalysisFinding>,
) {
    for info in functions.values() {
        for (offset, instr) in info.bytecode.iter().enumerate() {
            match instr {
                Bytecode::Call(_, _, Operation::CastU8, srcs, _)
                    if is_same_numeric(&info.local_types, srcs, PrimitiveType::U8) => {}
                Bytecode::Call(_, _, Operation::CastU16, srcs, _)
                    if is_same_numeric(&info.local_types, srcs, PrimitiveType::U16) => {}
                Bytecode::Call(_, _, Operation::CastU32, srcs, _)
                    if is_same_numeric(&info.local_types, srcs, PrimitiveType::U32) => {}
                Bytecode::Call(_, _, Operation::CastU64, srcs, _)
                    if is_same_numeric(&info.local_types, srcs, PrimitiveType::U64) => {}
                Bytecode::Call(_, _, Operation::CastU128, srcs, _)
                    if is_same_numeric(&info.local_types, srcs, PrimitiveType::U128) => {}
                Bytecode::Call(_, _, Operation::CastU256, srcs, _)
                    if is_same_numeric(&info.local_types, srcs, PrimitiveType::U256) => {}
                _ => continue,
            }
            findings.push(StaticAnalysisFinding::new(
                FindingKind::TypeConversion,
                module_name.to_string(),
                Some(info.name.clone()),
                format!("Redundant cast at offset {}", offset),
            ));
            break;
        }
    }
}

fn is_same_numeric(local_types: &[Type], srcs: &[usize], primitive: PrimitiveType) -> bool {
    srcs.first().and_then(|idx| local_types.get(*idx)) == Some(&Type::Primitive(primitive))
}

fn analyze_unchecked_return(
    module_name: &str,
    functions: &BTreeMap<usize, FunctionInfo>,
    symbol_pool: &SymbolPool,
    findings: &mut Vec<StaticAnalysisFinding>,
) {
    for info in functions.values() {
        for (offset, instr) in info.bytecode.iter().enumerate() {
            if let Bytecode::Call(_, dests, Operation::Function(_, fun_id, _), _, _) = instr {
                if dests.is_empty() {
                    continue;
                }
                let mut dropped = 0;
                let mut idx = offset + 1;
                while idx < info.bytecode.len() && dropped < dests.len() {
                    match &info.bytecode[idx] {
                        Bytecode::Call(_, _, Operation::Drop, srcs, _)
                            if srcs.len() == 1 && dests.contains(&srcs[0]) =>
                        {
                            dropped += 1;
                        }
                        Bytecode::Assign(_, dst, src, _) => {
                            if dests.contains(dst) || dests.contains(src) {
                                dropped = dests.len();
                                break;
                            }
                        }
                        Bytecode::Branch(_, _, _, cond) if dests.iter().any(|d| d == cond) => {
                            dropped = dests.len();
                            break;
                        }
                        _ => {}
                    }
                    idx += 1;
                }
                if dropped > 0 {
                    findings.push(StaticAnalysisFinding::new(
                        FindingKind::UncheckedReturn,
                        module_name.to_string(),
                        Some(info.name.clone()),
                        format!(
                            "Return from `{}` dropped without checks",
                            symbol_pool.string(fun_id.symbol())
                        ),
                    ));
                }
            }
        }
    }
}

fn analyze_unused_const(module_name: &str, compiled: &CompiledModule, findings: &mut Vec<StaticAnalysisFinding>) {
    if compiled.constant_pool().is_empty() {
        return;
    }
    let mut visited = vec![false; compiled.constant_pool().len()];
    for func in compiled.function_defs() {
        if let Some(code) = &func.code {
            for instr in &code.code {
                if let aptos_move_binary_format::file_format::Bytecode::LdConst(idx) = instr {
                    visited[idx.into_index()] = true;
                }
            }
        }
    }
    for (idx, used) in visited.into_iter().enumerate() {
        if !used {
            findings.push(StaticAnalysisFinding::new(
                FindingKind::UnusedConst,
                module_name.to_string(),
                None,
                format!("Constant pool entry {} is never referenced", idx),
            ));
        }
    }
}
