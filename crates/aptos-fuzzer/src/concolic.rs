use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use aptos_move_binary_format::file_format::Bytecode;
use aptos_move_core_types::language_storage::ModuleId;
use aptos_move_core_types::u256::U256;
use aptos_move_vm_runtime::{MoveTracer, MoveTracerExtraInfo, MoveTracerFrameInfo, MoveTracerInstructionContext};
use aptos_move_vm_types::values::{Container, ContainerRef, Value, ValueImpl};
use log::{trace, warn};
use z3::ast::{Ast, Bool, Dynamic, Int};
use z3::DeclKind;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SymbolValue {
    Value(Int),
    Unknown,
}

#[derive(Clone, Debug)]
pub struct ConcolicState {
    pub stack: Vec<SymbolValue>,
    pub locals: Vec<Vec<SymbolValue>>,
    pub args: Vec<BTreeMap<usize, Int>>,
    pub disable: bool,
    runtime_issues: Vec<RuntimeIssue>,
    branch_counts: HashMap<String, HashMap<u16, BranchCounter>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeIssueKind {
    PrecisionLoss,
    BoolJudgement,
    InfiniteLoop,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeIssue {
    pub kind: RuntimeIssueKind,
    pub module: String,
    pub function: String,
    pub pc: u16,
    pub message: String,
}

impl RuntimeIssue {
    fn new(kind: RuntimeIssueKind, module: String, function: String, pc: u16, message: String) -> Self {
        Self {
            kind,
            module,
            function,
            pc,
            message,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct BranchCounter {
    last_hash: Option<u64>,
    count: usize,
}

const INFINITE_LOOP_THRESHOLD: usize = 1000;

fn extract_primitive_value(v: &ValueImpl) -> ValueImpl {
    match v {
        ValueImpl::IndexedRef(i) => {
            let ContainerRef::Local(local) = &i.container_ref else {
                panic!("Unsupported container ref {:?} for comparison", i);
            };
            match local {
                Container::Locals(inner) | Container::Vec(inner) | Container::Struct(inner) => {
                    let inner = inner.borrow();
                    let val = inner.get(i.idx).unwrap();
                    extract_primitive_value(val)
                }
                Container::VecBool(inner) => {
                    let inner = inner.borrow();
                    let val = inner.get(i.idx).unwrap();
                    ValueImpl::Bool(*val)
                }
                Container::VecU8(inner) => {
                    let inner = inner.borrow();
                    let val = inner.get(i.idx).unwrap();
                    ValueImpl::U8(*val)
                }
                Container::VecU16(inner) => {
                    let inner = inner.borrow();
                    let val = inner.get(i.idx).unwrap();
                    ValueImpl::U16(*val)
                }
                Container::VecU32(inner) => {
                    let inner = inner.borrow();
                    let val = inner.get(i.idx).unwrap();
                    ValueImpl::U32(*val)
                }
                Container::VecU64(inner) => {
                    let inner = inner.borrow();
                    let val = inner.get(i.idx).unwrap();
                    ValueImpl::U64(*val)
                }
                Container::VecU128(inner) => {
                    let inner = inner.borrow();
                    let val = inner.get(i.idx).unwrap();
                    ValueImpl::U128(*val)
                }
                Container::VecU256(inner) => {
                    let inner = inner.borrow();
                    let val = inner.get(i.idx).unwrap();
                    ValueImpl::U256(*val)
                }
                _ => {
                    panic!("Unsupported container type {:?} for comparison", local);
                }
            }
        }
        ValueImpl::Bool(b) => ValueImpl::Bool(*b),
        ValueImpl::U8(u) => ValueImpl::U8(*u),
        ValueImpl::U16(u) => ValueImpl::U16(*u),
        ValueImpl::U32(u) => ValueImpl::U32(*u),
        ValueImpl::U64(u) => ValueImpl::U64(*u),
        ValueImpl::U128(u) => ValueImpl::U128(*u),
        ValueImpl::U256(u) => ValueImpl::U256(*u),
        _ => panic!("Unsupported value type {:?} for comparison", v),
    }
}

fn compare_value_impl(v1: &ValueImpl, v2: &ValueImpl) -> Ordering {
    let v1_value = extract_primitive_value(v1);
    let v2_value = extract_primitive_value(v2);
    match (v1_value, v2_value) {
        (ValueImpl::Bool(b1), ValueImpl::Bool(b2)) => b1.cmp(&b2),
        (ValueImpl::U8(u1), ValueImpl::U8(u2)) => u1.cmp(&u2),
        (ValueImpl::U16(u1), ValueImpl::U16(u2)) => u1.cmp(&u2),
        (ValueImpl::U32(u1), ValueImpl::U32(u2)) => u1.cmp(&u2),
        (ValueImpl::U64(u1), ValueImpl::U64(u2)) => u1.cmp(&u2),
        (ValueImpl::U128(u1), ValueImpl::U128(u2)) => u1.cmp(&u2),
        (ValueImpl::U256(u1), ValueImpl::U256(u2)) => u1.cmp(&u2),
        _ => panic!("Unsupported value type {:?} and {:?} for comparison", v1, v2),
    }
}

pub fn compare_value(v1: &Value, v2: &Value) -> Ordering {
    compare_value_impl(&v1.0, &v2.0)
}

pub fn value_to_u256(v: &Value) -> U256 {
    let value = extract_primitive_value(&v.0);
    match &value {
        ValueImpl::Bool(b) => {
            if *b {
                U256::one()
            } else {
                U256::zero()
            }
        }
        ValueImpl::U8(u) => U256::from(*u),
        ValueImpl::U16(u) => U256::from(*u),
        ValueImpl::U32(u) => U256::from(*u),
        ValueImpl::U64(u) => U256::from(*u),
        ValueImpl::U128(u) => U256::from(*u),
        ValueImpl::U256(u) => *u,
        _ => panic!("Unsupported value type for conversion to U256"),
    }
}

pub fn value_bitwidth(v: &Value) -> u32 {
    let value = extract_primitive_value(&v.0);
    match &value {
        ValueImpl::Bool(_) => 1,
        ValueImpl::U8(_) => 8,
        ValueImpl::U16(_) => 16,
        ValueImpl::U32(_) => 32,
        ValueImpl::U64(_) => 64,
        ValueImpl::U128(_) => 128,
        ValueImpl::U256(_) => 256,
        _ => panic!("Unsupported value type for bitwidth"),
    }
}

fn int_two_pow(bits: u32) -> Int {
    let v = U256::one() << bits;
    Int::from_str(&v.to_string()).unwrap()
}

fn int_mod_2n(x: &Int, bits: u32) -> Int {
    x.modulo(int_two_pow(bits))
}

/// Convert U256 to Int numeral.
fn int_from_u256(u: U256) -> Int {
    Int::from_str(&u.to_string()).unwrap()
}

/// Integer-only AND with a constant bitmask:
/// Returns (x & mask) under w-bit semantics, using only Int + div/mod by powers
/// of two. Implementation uses "run decomposition": split mask's 1-bits into
/// contiguous runs [a..=b], and for each run extract that window from x, then
/// place it back.
pub fn int_bvand_const(x: &Int, mask: U256, bits: u32) -> Int {
    // Normalize x to w-bit domain (BitVec semantics).
    let x0 = int_mod_2n(x, bits);

    // Quick exits.
    if mask == U256::zero() {
        return Int::from_u64(0);
    }
    // Restrict mask to w bits (BV mask)
    let mask_w = mask & ((U256::one() << bits) - U256::one());

    // Iterate over runs of 1s in mask_w.
    let mut m = mask_w;
    let mut i: u32 = 0;
    let mut terms: Vec<Int> = Vec::new();

    while m != U256::zero() {
        // skip zeros
        while m != U256::zero() && (m & U256::one()) == U256::zero() {
            m = m.checked_shr(1).unwrap();
            i += 1;
        }
        if m == U256::zero() {
            break;
        }
        // start of a run
        let a = i;
        // consume ones
        while (m & U256::one()) == U256::one() {
            m = m.checked_shr(1).unwrap();
            i += 1;
        }
        let b = i - 1; // inclusive end
        let L = b - a + 1;

        // term(a,b) = (((x0 mod 2^(b+1)) div 2^a) mod 2^L) * 2^a
        let term = (x0.clone() % int_two_pow(b + 1) / int_two_pow(a)) % int_two_pow(L) * int_two_pow(a);
        terms.push(term);
    }

    // Sum all terms (if no runs, it's zero which we handled above).
    let mut acc = Int::from_u64(0);
    for t in terms {
        acc += t;
    }
    acc
}

/// Integer-only OR with a constant bitmask:
/// Returns (x | mask) under w-bit semantics, using only Int ops.
/// Uses identity: x | M = (x & ~M_w) + M_w, where ~M_w is bitwise-not of M
/// within w bits. We reuse int_bvand_const for the "clear then add" pattern.
pub fn int_bvor_const(x: &Int, mask: U256, bits: u32) -> Int {
    // mask limited to w bits
    let full = (U256::one() << bits) - U256::one();
    let mask_w = mask & full;
    let not_mask_w = full ^ mask_w;

    // Keep x's bits where mask is 0, then force-on mask bits by addition.
    let kept = int_bvand_const(x, not_mask_w, bits);
    kept + int_from_u256(mask_w)
}

/// Integer-only NOT under w-bit semantics:
/// r = ~x  (within w bits)  ==  (2^w - 1) - (x mod 2^w)
pub fn int_bvnot(x: &Int, bits: u32) -> Int {
    let x0 = int_mod_2n(x, bits);
    let full = int_two_pow(bits) - 1;
    full - x0
}

/// Integer-only XOR with a constant mask under w-bit semantics:
/// r = x ^ mask = (x & ~mask_w) + (~x & mask_w)
pub fn int_bvxor_const(x: &Int, mask: U256, bits: u32) -> Int {
    let full = (U256::one() << bits) - U256::one();
    let mask_w = mask & full;
    let not_mask_w = full ^ mask_w;

    let part_keep = int_bvand_const(x, not_mask_w, bits);
    let x_not = int_bvnot(x, bits);
    let part_flip = int_bvand_const(&x_not, mask_w, bits);

    // Disjoint bit regions; sum is exact. Normalize just in case.
    let sum = part_keep + part_flip;
    int_mod_2n(&sum, bits)
}

impl Default for ConcolicState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConcolicState {
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            locals: Vec::new(),
            args: Vec::new(),
            disable: false,
            runtime_issues: Vec::new(),
            branch_counts: HashMap::new(),
        }
    }

    pub fn open_frame(&mut self, frame: &MoveTracerFrameInfo<'_>) {
        trace!(
            "Open frame: {}::{}",
            frame.function.module_or_script_id(),
            frame.function.name()
        );
        let func_key = format!(
            "{}::{}",
            format_module_name(frame.function.module_or_script_id()),
            frame.function.name()
        );
        self.branch_counts.remove(&func_key);
        if self.locals.is_empty() {
            let locals = frame
                .param_tys
                .iter()
                .enumerate()
                .map(|(i, ty)| Self::resolve_arg(self.args.len(), i, ty))
                .collect::<Vec<_>>();
            self.args.push(
                locals
                    .iter()
                    .enumerate()
                    .filter_map(|(i, v)| match v {
                        SymbolValue::Value(bv) => Some((i, bv.clone())),
                        SymbolValue::Unknown => None,
                    })
                    .collect(),
            );
            self.locals.push(locals);
            trace!("args: {:?}", self.args);
        } else {
            if frame.param_tys.len() > self.stack.len() {
                self.stack.clear();
                self.locals.clear();
                self.disable = true;
                warn!("Symbolic stack underflow when opening frame");
                return;
            }
            let skip_idx = self.stack.len() - frame.param_tys.len();
            self.locals.push(self.stack.drain(skip_idx..).collect());
            self.stack.truncate(skip_idx);
            if frame.is_native {
                for _ in 0..frame.return_tys.len() {
                    self.stack.push(SymbolValue::Unknown);
                }
            }
        }
    }

    pub fn close_frame(&mut self) {
        trace!("Close frame");
        self.locals.pop();
    }

    pub fn before_instruction(&mut self, ctx: &MoveTracerInstructionContext<'_>) -> Option<Bool> {
        // if self.disable {
        //     return None;
        // }
        let s = &ctx.operand_stack;
        let extra = ctx.extra;
        let instruction = ctx.instruction;
        let pc = ctx.pc;
        let module_name = format_module_name(ctx.frame.function.module_or_script_id());
        let function_name = ctx.frame.function.name().to_string();
        let function_key = format!("{}::{}", module_name, function_name);

        if self.stack.len() != s.values.len() && s.values.is_empty() {
            self.stack.clear();
        }
        assert_eq!(
            self.stack.len(),
            s.values.len(),
            "stack: {:?}, stack from trace: {:?}",
            self.stack,
            s.values,
        );

        match instruction {
            Bytecode::Eq | Bytecode::Neq | Bytecode::Lt | Bytecode::Le | Bytecode::Gt | Bytecode::Ge => {
                self.check_bool_judgement(instruction, &module_name, &function_name, pc, s.values());
            }
            Bytecode::BrTrue(_) | Bytecode::BrFalse(_) => {
                self.check_infinite_loop(&function_key, pc, &module_name, &function_name);
            }
            _ => {}
        }

        let mut process_binary_op = || {
            let (rhs, lhs) = (self.stack.pop().unwrap(), self.stack.pop().unwrap());
            let stack_iter = s.last_n(2).unwrap();
            let true_lhs = stack_iter.get(0).unwrap();
            let true_rhs = stack_iter.get(1).unwrap();
            let (new_l, new_r) = match (lhs, rhs) {
                (SymbolValue::Value(l), SymbolValue::Value(r)) => (l, r),
                (SymbolValue::Value(l), SymbolValue::Unknown) => {
                    let new_r = Self::resolve_value(true_rhs);
                    (l, new_r)
                }
                (SymbolValue::Unknown, SymbolValue::Value(r)) => {
                    let new_l = Self::resolve_value(true_lhs);
                    (new_l, r)
                }
                (SymbolValue::Unknown, SymbolValue::Unknown) => {
                    return None;
                }
            };
            Some((new_l, new_r))
        };

        match instruction {
            Bytecode::Pop |
            Bytecode::BrTrue(_) |
            Bytecode::BrFalse(_) |
            Bytecode::Abort |
            Bytecode::VecImmBorrow(_) |
            Bytecode::VecMutBorrow(_) => {
                self.stack.pop();
            }
            Bytecode::LdU8(_) |
            Bytecode::LdU16(_) |
            Bytecode::LdU32(_) |
            Bytecode::LdU64(_) |
            Bytecode::LdU128(_) |
            Bytecode::LdU256(_) |
            Bytecode::LdConst(_) => {
                self.stack.push(SymbolValue::Unknown);
            }
            Bytecode::LdFalse => {
                self.stack.push(SymbolValue::Value(Int::from_u64(0)));
            }
            Bytecode::LdTrue => {
                self.stack.push(SymbolValue::Value(Int::from_u64(1)));
            }
            Bytecode::CastU8 => {
                if let Some(v) = self.stack.last() {
                    if let SymbolValue::Value(int) = v {
                        return Some(int.le(Self::max_u_bits(8)));
                    }
                } else {
                    warn!("Stack underflow at pc {}", pc);
                }
            }
            Bytecode::CastU16 => {
                if let Some(v) = self.stack.last() {
                    if let SymbolValue::Value(int) = v {
                        return Some(int.le(Self::max_u_bits(16)));
                    }
                } else {
                    warn!("Stack underflow at pc {}", pc);
                }
            }
            Bytecode::CastU32 => {
                if let Some(v) = self.stack.last() {
                    if let SymbolValue::Value(int) = v {
                        return Some(int.le(Self::max_u_bits(32)));
                    }
                } else {
                    warn!("Stack underflow at pc {}", pc);
                }
            }
            Bytecode::CastU64 => {
                if let Some(v) = self.stack.last() {
                    if let SymbolValue::Value(int) = v {
                        return Some(int.le(Self::max_u_bits(64)));
                    }
                } else {
                    warn!("Stack underflow at pc {}", pc);
                }
            }
            Bytecode::CastU128 => {
                if let Some(v) = self.stack.last() {
                    if let SymbolValue::Value(int) = v {
                        return Some(int.le(Self::max_u_bits(128)));
                    }
                } else {
                    warn!("Stack underflow at pc {}", pc);
                }
            }
            Bytecode::Add => {
                if let Some((l, r)) = process_binary_op() {
                    // overflow check not implemented yet
                    let sum = l + r;
                    self.stack.push(SymbolValue::Value(sum));
                } else {
                    self.stack.push(SymbolValue::Unknown);
                }
            }
            Bytecode::Sub => {
                if let Some((l, r)) = process_binary_op() {
                    // overflow check not implemented yet
                    let diff = l - r;
                    self.stack.push(SymbolValue::Value(diff));
                } else {
                    self.stack.push(SymbolValue::Unknown);
                }
            }
            Bytecode::Mul => {
                if let Some((l, r)) = process_binary_op() {
                    self.check_precision_loss(&module_name, &function_name, pc, &l, &r);
                    let prod = l * r;
                    self.stack.push(SymbolValue::Value(prod));
                } else {
                    self.stack.push(SymbolValue::Unknown);
                }
            }
            Bytecode::Div => {
                if let Some((l, r)) = process_binary_op() {
                    // overflow check not implemented yet
                    let quot = l / r;
                    self.stack.push(SymbolValue::Value(quot));
                } else {
                    self.stack.push(SymbolValue::Unknown);
                }
            }
            Bytecode::Mod => {
                if let Some((l, r)) = process_binary_op() {
                    // overflow check not implemented yet
                    let rem = l % r;
                    self.stack.push(SymbolValue::Value(rem));
                } else {
                    self.stack.push(SymbolValue::Unknown);
                }
            }
            Bytecode::And | Bytecode::BitAnd => {
                let (rhs, lhs) = (self.stack.pop().unwrap(), self.stack.pop().unwrap());
                let stack_iter = s.last_n(2).unwrap();
                let true_lhs = stack_iter.get(0).unwrap();
                let true_rhs = stack_iter.get(1).unwrap();

                let bit_width = value_bitwidth(true_lhs);
                let (true_l, true_r) = (value_to_u256(true_lhs), value_to_u256(true_rhs));
                match (lhs, rhs) {
                    (SymbolValue::Value(l), SymbolValue::Value(r)) => {
                        self.stack.push(SymbolValue::Unknown);
                    }
                    (SymbolValue::Value(l), SymbolValue::Unknown) => {
                        let and = int_bvand_const(&l, true_r, bit_width);
                        self.stack.push(SymbolValue::Value(and));
                    }
                    (SymbolValue::Unknown, SymbolValue::Value(r)) => {
                        let and = int_bvand_const(&r, true_l, bit_width);
                        self.stack.push(SymbolValue::Value(and));
                    }
                    (SymbolValue::Unknown, SymbolValue::Unknown) => {
                        self.stack.push(SymbolValue::Unknown);
                    }
                }
            }
            Bytecode::Or | Bytecode::BitOr => {
                let (rhs, lhs) = (self.stack.pop().unwrap(), self.stack.pop().unwrap());
                let stack_iter = s.last_n(2).unwrap();
                let true_lhs = stack_iter.get(0).unwrap();
                let true_rhs = stack_iter.get(1).unwrap();

                let bit_width = value_bitwidth(true_lhs);
                let (true_l, true_r) = (value_to_u256(true_lhs), value_to_u256(true_rhs));
                match (lhs, rhs) {
                    (SymbolValue::Value(l), SymbolValue::Value(r)) => {
                        self.stack.push(SymbolValue::Unknown);
                    }
                    (SymbolValue::Value(l), SymbolValue::Unknown) => {
                        let or = int_bvor_const(&l, true_r, bit_width);
                        self.stack.push(SymbolValue::Value(or));
                    }
                    (SymbolValue::Unknown, SymbolValue::Value(r)) => {
                        let or = int_bvor_const(&r, true_l, bit_width);
                        self.stack.push(SymbolValue::Value(or));
                    }
                    (SymbolValue::Unknown, SymbolValue::Unknown) => {
                        self.stack.push(SymbolValue::Unknown);
                    }
                }
            }
            Bytecode::Xor => {
                let (rhs, lhs) = (self.stack.pop().unwrap(), self.stack.pop().unwrap());
                let stack_iter = s.last_n(2).unwrap();
                let true_lhs = stack_iter.get(0).unwrap();
                let true_rhs = stack_iter.get(1).unwrap();

                let bit_width = value_bitwidth(true_lhs);
                let (true_l, true_r) = (value_to_u256(true_lhs), value_to_u256(true_rhs));
                match (lhs, rhs) {
                    (SymbolValue::Value(l), SymbolValue::Value(r)) => {
                        self.stack.push(SymbolValue::Unknown);
                    }
                    (SymbolValue::Value(l), SymbolValue::Unknown) => {
                        let xor = int_bvxor_const(&l, true_r, bit_width);
                        self.stack.push(SymbolValue::Value(xor));
                    }
                    (SymbolValue::Unknown, SymbolValue::Value(r)) => {
                        let xor = int_bvxor_const(&r, true_l, bit_width);
                        self.stack.push(SymbolValue::Value(xor));
                    }
                    (SymbolValue::Unknown, SymbolValue::Unknown) => {
                        self.stack.push(SymbolValue::Unknown);
                    }
                }
            }
            Bytecode::Shl => {
                let (rhs, lhs) = (self.stack.pop().unwrap(), self.stack.pop().unwrap());
                let stack_iter = s.last_n(2).unwrap();
                let true_lhs = stack_iter.get(0).unwrap();
                let true_rhs = stack_iter.get(1).unwrap();
                let bit_width = value_bitwidth(true_lhs);
                let true_r = value_to_u256(true_rhs).unchecked_as_u32();
                let threshold = Self::max_u_bits(bit_width);
                match (lhs, rhs) {
                    (SymbolValue::Value(l), SymbolValue::Value(r)) => {
                        self.stack.push(SymbolValue::Unknown);
                    }
                    (SymbolValue::Value(l), SymbolValue::Unknown) => {
                        let shl = l * int_two_pow(true_r);
                        let shl_mod = shl.modulo(int_two_pow(bit_width));
                        self.stack.push(SymbolValue::Value(shl_mod));
                        return Some(shl.gt(&threshold)); // cause overflow
                    }
                    (SymbolValue::Unknown, SymbolValue::Value(r)) => {
                        self.stack.push(SymbolValue::Unknown);
                    }
                    (SymbolValue::Unknown, SymbolValue::Unknown) => {
                        self.stack.push(SymbolValue::Unknown);
                    }
                }
            }
            Bytecode::Shr => {
                let (rhs, lhs) = (self.stack.pop().unwrap(), self.stack.pop().unwrap());
                let stack_iter = s.last_n(2).unwrap();
                let true_lhs = stack_iter.get(0).unwrap();
                let true_rhs = stack_iter.get(1).unwrap();

                let true_r = value_to_u256(true_rhs).unchecked_as_u32();
                match (lhs, rhs) {
                    (SymbolValue::Value(l), SymbolValue::Value(r)) => {
                        self.stack.push(SymbolValue::Unknown);
                    }
                    (SymbolValue::Value(l), SymbolValue::Unknown) => {
                        let shr = l / int_two_pow(true_r);
                        self.stack.push(SymbolValue::Value(shr));
                    }
                    (SymbolValue::Unknown, SymbolValue::Value(r)) => {
                        self.stack.push(SymbolValue::Unknown);
                    }
                    (SymbolValue::Unknown, SymbolValue::Unknown) => {
                        self.stack.push(SymbolValue::Unknown);
                    }
                }
            }
            Bytecode::Not => {
                if let Some(v) = self.stack.pop() {
                    match v {
                        SymbolValue::Value(n) => {
                            let bit_width = value_bitwidth(s.last_n(1).unwrap().get(0).unwrap());
                            let not_n = int_bvnot(&n, bit_width);
                            self.stack.push(SymbolValue::Value(not_n));
                        }
                        SymbolValue::Unknown => {
                            self.stack.push(SymbolValue::Unknown);
                        }
                    }
                } else {
                    warn!("Stack underflow at pc {}", pc);
                }
            }
            Bytecode::CopyLoc(idx) | Bytecode::MutBorrowLoc(idx) | Bytecode::ImmBorrowLoc(idx) => {
                if let Some(locals) = self.locals.last() {
                    if let Some(v) = locals.get(*idx as usize) {
                        self.stack.push(v.clone());
                    } else {
                        warn!("Local index out of bounds at pc {}", pc);
                        self.stack.push(SymbolValue::Unknown);
                    }
                } else {
                    warn!("No locals available at pc {}", pc);
                    self.stack.push(SymbolValue::Unknown);
                }
            }
            Bytecode::MoveLoc(idx) => {
                if let Some(locals) = self.locals.last_mut() {
                    if let Some(v) = locals.get(*idx as usize) {
                        self.stack.push(v.clone());
                        locals[*idx as usize] = SymbolValue::Unknown; // moved-from
                    } else {
                        warn!("Local index out of bounds at pc {}", pc);
                        self.stack.push(SymbolValue::Unknown);
                    }
                } else {
                    warn!("No locals available at pc {}", pc);
                    self.stack.push(SymbolValue::Unknown);
                }
            }
            Bytecode::StLoc(idx) => {
                if let Some(v) = self.stack.pop() {
                    if let Some(locals) = self.locals.last_mut() {
                        if let Some(slot) = locals.get_mut(*idx as usize) {
                            *slot = v;
                        } else {
                            for _ in locals.len()..=*idx as usize {
                                locals.push(SymbolValue::Unknown);
                            }
                            locals[*idx as usize] = v;
                        }
                    } else {
                        warn!("No locals available at pc {}", pc);
                    }
                } else {
                    warn!("Stack underflow at pc {}", pc);
                }
            }
            Bytecode::WriteRef | Bytecode::VecPushBack(_) => {
                self.stack.pop();
                self.stack.pop();
            }
            Bytecode::Eq => {
                let (rhs, lhs) = (self.stack.pop().unwrap(), self.stack.pop().unwrap());
                let stack_iter = s.last_n(2).unwrap();
                let true_lhs = stack_iter.get(0).unwrap();
                let true_rhs = stack_iter.get(1).unwrap();
                let (new_l, new_r) = match (lhs, rhs) {
                    (SymbolValue::Value(l), SymbolValue::Value(r)) => (l, r),
                    (SymbolValue::Value(l), SymbolValue::Unknown) => {
                        let new_r = Self::resolve_value(true_rhs);
                        (l, new_r)
                    }
                    (SymbolValue::Unknown, SymbolValue::Value(r)) => {
                        let new_l = Self::resolve_value(true_lhs);
                        (new_l, r)
                    }
                    (SymbolValue::Unknown, SymbolValue::Unknown) => {
                        self.stack.push(SymbolValue::Unknown);
                        return None;
                    }
                };
                if matches!(compare_value(true_lhs, true_rhs), Ordering::Equal) {
                    let eq = new_l._eq(&new_r);
                    let int = eq.ite(&Int::from_u64(1), &Int::from_u64(0));
                    self.stack.push(SymbolValue::Value(int));
                    return Some(eq);
                } else {
                    // different values are not equal
                    let neq = new_l._eq(&new_r).not();
                    let int = neq.ite(&Int::from_u64(1), &Int::from_u64(0));
                    self.stack.push(SymbolValue::Value(int));
                    return Some(neq);
                }
            }
            Bytecode::Neq => {
                let (rhs, lhs) = (self.stack.pop().unwrap(), self.stack.pop().unwrap());
                let stack_iter = s.last_n(2).unwrap();
                let true_lhs = stack_iter.get(0).unwrap();
                let true_rhs = stack_iter.get(1).unwrap();
                let (new_l, new_r) = match (lhs, rhs) {
                    (SymbolValue::Value(l), SymbolValue::Value(r)) => (l, r),
                    (SymbolValue::Value(l), SymbolValue::Unknown) => {
                        let new_r = Self::resolve_value(true_rhs);
                        (l, new_r)
                    }
                    (SymbolValue::Unknown, SymbolValue::Value(r)) => {
                        let new_l = Self::resolve_value(true_lhs);
                        (new_l, r)
                    }
                    (SymbolValue::Unknown, SymbolValue::Unknown) => {
                        self.stack.push(SymbolValue::Unknown);
                        return None;
                    }
                };
                if !matches!(compare_value(true_lhs, true_rhs), Ordering::Equal) {
                    let neq = new_l._eq(&new_r).not();
                    let bv = neq.ite(&Int::from_u64(1), &Int::from_u64(0));
                    self.stack.push(SymbolValue::Value(bv));
                    return Some(neq);
                } else {
                    // same values are equal
                    let eq = new_l._eq(&new_r);
                    let bv = eq.ite(&Int::from_u64(1), &Int::from_u64(0));
                    self.stack.push(SymbolValue::Value(bv));
                    return Some(eq.not());
                }
            }
            Bytecode::Lt => {
                let (rhs, lhs) = (self.stack.pop().unwrap(), self.stack.pop().unwrap());
                let stack_iter = s.last_n(2).unwrap();
                let true_lhs = stack_iter.get(0).unwrap();
                let true_rhs = stack_iter.get(1).unwrap();
                let (new_l, new_r) = match (lhs, rhs) {
                    (SymbolValue::Value(l), SymbolValue::Value(r)) => (l, r),
                    (SymbolValue::Value(l), SymbolValue::Unknown) => {
                        let new_r = Self::resolve_value(true_rhs);
                        (l, new_r)
                    }
                    (SymbolValue::Unknown, SymbolValue::Value(r)) => {
                        let new_l = Self::resolve_value(true_lhs);
                        (new_l, r)
                    }
                    (SymbolValue::Unknown, SymbolValue::Unknown) => {
                        self.stack.push(SymbolValue::Unknown);
                        return None;
                    }
                };
                if matches!(compare_value(true_lhs, true_rhs), Ordering::Less) {
                    let lt = new_l.lt(&new_r);
                    let int = lt.ite(&Int::from_u64(1), &Int::from_u64(0));
                    self.stack.push(SymbolValue::Value(int));
                    return Some(lt);
                } else {
                    // not less than
                    let nlt = new_l.lt(&new_r).not();
                    let int = nlt.ite(&Int::from_u64(1), &Int::from_u64(0));
                    self.stack.push(SymbolValue::Value(int));
                    return Some(nlt);
                }
            }
            Bytecode::Le => {
                let (rhs, lhs) = (self.stack.pop().unwrap(), self.stack.pop().unwrap());
                let stack_iter = s.last_n(2).unwrap();
                let true_lhs = stack_iter.get(0).unwrap();
                let true_rhs = stack_iter.get(1).unwrap();
                let (new_l, new_r) = match (lhs, rhs) {
                    (SymbolValue::Value(l), SymbolValue::Value(r)) => (l, r),
                    (SymbolValue::Value(l), SymbolValue::Unknown) => {
                        let new_r = Self::resolve_value(true_rhs);
                        (l, new_r)
                    }
                    (SymbolValue::Unknown, SymbolValue::Value(r)) => {
                        let new_l = Self::resolve_value(true_lhs);
                        (new_l, r)
                    }
                    (SymbolValue::Unknown, SymbolValue::Unknown) => {
                        self.stack.push(SymbolValue::Unknown);
                        return None;
                    }
                };
                if !matches!(compare_value(true_lhs, true_rhs), Ordering::Greater) {
                    let lt = new_l.le(&new_r);
                    let int = lt.ite(&Int::from_u64(1), &Int::from_u64(0));
                    self.stack.push(SymbolValue::Value(int));
                    return Some(lt);
                } else {
                    // not less than
                    let nlt = new_l.le(&new_r).not();
                    let int = nlt.ite(&Int::from_u64(1), &Int::from_u64(0));
                    self.stack.push(SymbolValue::Value(int));
                    return Some(nlt);
                }
            }
            Bytecode::Gt => {
                let (rhs, lhs) = (self.stack.pop().unwrap(), self.stack.pop().unwrap());
                let stack_iter = s.last_n(2).unwrap();
                let true_lhs = stack_iter.get(0).unwrap();
                let true_rhs = stack_iter.get(1).unwrap();
                let (new_l, new_r) = match (lhs, rhs) {
                    (SymbolValue::Value(l), SymbolValue::Value(r)) => (l, r),
                    (SymbolValue::Value(l), SymbolValue::Unknown) => {
                        let new_r = Self::resolve_value(true_rhs);
                        (l, new_r)
                    }
                    (SymbolValue::Unknown, SymbolValue::Value(r)) => {
                        let new_l = Self::resolve_value(true_lhs);
                        (new_l, r)
                    }
                    (SymbolValue::Unknown, SymbolValue::Unknown) => {
                        self.stack.push(SymbolValue::Unknown);
                        return None;
                    }
                };
                if matches!(compare_value(true_lhs, true_rhs), Ordering::Greater) {
                    let lt = new_l.gt(&new_r);
                    let int = lt.ite(&Int::from_u64(1), &Int::from_u64(0));
                    self.stack.push(SymbolValue::Value(int));
                    return Some(lt);
                } else {
                    // not less than
                    let nlt = new_l.gt(&new_r).not();
                    let int = nlt.ite(&Int::from_u64(1), &Int::from_u64(0));
                    self.stack.push(SymbolValue::Value(int));
                    return Some(nlt);
                }
            }
            Bytecode::Ge => {
                let (rhs, lhs) = (self.stack.pop().unwrap(), self.stack.pop().unwrap());
                let stack_iter = s.last_n(2).unwrap();
                let true_lhs = stack_iter.get(0).unwrap();
                let true_rhs = stack_iter.get(1).unwrap();
                let (new_l, new_r) = match (lhs, rhs) {
                    (SymbolValue::Value(l), SymbolValue::Value(r)) => (l, r),
                    (SymbolValue::Value(l), SymbolValue::Unknown) => {
                        let new_r = Self::resolve_value(true_rhs);
                        (l, new_r)
                    }
                    (SymbolValue::Unknown, SymbolValue::Value(r)) => {
                        let new_l = Self::resolve_value(true_lhs);
                        (new_l, r)
                    }
                    (SymbolValue::Unknown, SymbolValue::Unknown) => {
                        self.stack.push(SymbolValue::Unknown);
                        return None;
                    }
                };
                if !matches!(compare_value(true_lhs, true_rhs), Ordering::Less) {
                    let lt = new_l.ge(&new_r);
                    let int = lt.ite(&Int::from_u64(1), &Int::from_u64(0));
                    self.stack.push(SymbolValue::Value(int));
                    return Some(lt);
                } else {
                    // not less than
                    let nlt = new_l.ge(&new_r).not();
                    let int = nlt.ite(&Int::from_u64(1), &Int::from_u64(0));
                    self.stack.push(SymbolValue::Value(int));
                    return Some(nlt);
                }
            }
            Bytecode::VecPack(_, len) => {
                for _ in 0..*len {
                    self.stack.pop();
                }
                self.stack.push(SymbolValue::Unknown); // represent the vector
                                                       // as unknown
            }
            Bytecode::VecUnpack(_, len) => {
                self.stack.pop();
                for _ in 0..*len {
                    self.stack.push(SymbolValue::Unknown); // represent each
                                                           // element as unknown
                }
            }
            Bytecode::VecSwap(_) => {
                self.stack.pop();
                self.stack.pop();
                self.stack.pop();
            }
            Bytecode::Pack(_) | Bytecode::PackGeneric(_) => {
                if let Some(extra_info) = extra {
                    match extra_info {
                        MoveTracerExtraInfo::Pack(count) | MoveTracerExtraInfo::PackGeneric(count) => {
                            for _ in 0..count {
                                self.stack.pop();
                            }
                            self.stack.push(SymbolValue::Unknown); // represent the struct as unknown
                        }
                        _ => {}
                    }
                } else {
                    warn!("Missing extra info for pack at pc {}", pc);
                    self.disable = true;
                    return None;
                }
            }
            Bytecode::Unpack(_) | Bytecode::UnpackGeneric(_) => {
                self.stack.pop();
                if let Some(extra_info) = extra {
                    match extra_info {
                        MoveTracerExtraInfo::Unpack(count) | MoveTracerExtraInfo::UnpackGeneric(count) => {
                            for _ in 0..count {
                                self.stack.push(SymbolValue::Unknown); // represent each field as unknown
                            }
                        }
                        _ => {}
                    }
                } else {
                    warn!("Missing extra info for unpack at pc {}", pc);
                    self.disable = true;
                    return None;
                }
            }
            Bytecode::PackVariant(_) | Bytecode::PackVariantGeneric(_) => {
                if let Some(extra_info) = extra {
                    match extra_info {
                        MoveTracerExtraInfo::PackVariant(count) | MoveTracerExtraInfo::PackVariantGeneric(count) => {
                            for _ in 0..count {
                                self.stack.pop();
                            }
                            self.stack.push(SymbolValue::Unknown); // represent the enum as unknown
                        }
                        _ => {}
                    }
                } else {
                    warn!("Missing extra info for pack variant at pc {}", pc);
                    self.disable = true;
                    return None;
                }
            }
            Bytecode::UnpackVariant(_) | Bytecode::UnpackVariantGeneric(_) => {
                self.stack.pop();
                if let Some(extra_info) = extra {
                    match extra_info {
                        MoveTracerExtraInfo::UnpackVariant(count) |
                        MoveTracerExtraInfo::UnpackVariantGeneric(count) => {
                            for _ in 0..count {
                                self.stack.push(SymbolValue::Unknown); // represent each field as unknown
                            }
                        }
                        _ => {}
                    }
                } else {
                    warn!("Missing extra info for unpack variant at pc {}", pc);
                    self.disable = true;
                    return None;
                }
            }
            _ => {}
        }
        None
    }

    fn resolve_arg(
        cmd_index: usize,
        param_index: usize,
        ty: &aptos_move_vm_types::loaded_data::runtime_types::Type,
    ) -> SymbolValue {
        use aptos_move_vm_types::loaded_data::runtime_types::Type;
        match ty {
            Type::Bool | Type::U8 | Type::U16 | Type::U32 | Type::U64 | Type::U128 | Type::U256 => {
                let name = format!("{}.{}", cmd_index, param_index);
                let int = Int::new_const(name);
                SymbolValue::Value(int)
            }
            _ => SymbolValue::Unknown,
        }
    }

    fn resolve_value(value: &Value) -> Int {
        Self::resolve_value_impl(&value.0)
    }

    fn resolve_value_impl(value_impl: &ValueImpl) -> Int {
        let primitive_value = extract_primitive_value(value_impl);
        match primitive_value {
            ValueImpl::Bool(b) => {
                let int_val = if b { 1 } else { 0 };
                Int::from_u64(int_val)
            }
            ValueImpl::U8(u) => Int::from_u64(u as u64),
            ValueImpl::U16(u) => Int::from_u64(u as u64),
            ValueImpl::U32(u) => Int::from_u64(u as u64),
            ValueImpl::U64(u) => Int::from_u64(u),
            ValueImpl::U128(u) => Int::from_str(&u.to_string()).unwrap(),
            ValueImpl::U256(u) => Int::from_str(&u.to_string()).unwrap(),
            _ => panic!("Unsupported value type {:?} for symbolic execution", value_impl),
        }
    }

    #[inline]
    fn max_u_bits(n: u32) -> Int {
        if n <= 63 {
            Int::from_u64((1u64 << n) - 1)
        } else {
            let two_pow_n_minus_1 = match n {
                64 => "18446744073709551615",
                128 => "340282366920938463463374607431768211455",
                256 => "115792089237316195423570985008687907853269984665640564039457584007913129639935",
                _ => unreachable!("add more cases or compute big ints as needed"),
            };
            Int::from_str(two_pow_n_minus_1).unwrap()
        }
    }
}

impl ConcolicState {
    fn record_issue(&mut self, issue: RuntimeIssue) {
        self.runtime_issues.push(issue);
    }

    fn check_precision_loss(&mut self, module: &str, function: &str, pc: u16, lhs: &Int, rhs: &Int) {
        if contains_division(lhs) || contains_division(rhs) {
            let message = format!("Precision loss detected at {}::{} (pc {})", module, function, pc);
            self.record_issue(RuntimeIssue::new(
                RuntimeIssueKind::PrecisionLoss,
                module.to_string(),
                function.to_string(),
                pc,
                message,
            ));
        }
    }

    fn check_bool_judgement(
        &mut self,
        instruction: &Bytecode,
        module: &str,
        function: &str,
        pc: u16,
        operand_stack: &[Value],
    ) {
        if self.stack.len() < 2 {
            return;
        }
        let lhs = &self.stack[self.stack.len() - 2];
        let rhs = &self.stack[self.stack.len() - 1];
        let mut loss = matches!(
            (lhs, rhs),
            (SymbolValue::Value(l), SymbolValue::Value(r))
                if int_has_variable(l) == Some(false) && int_has_variable(r) == Some(false)
        );

        if matches!(instruction, Bytecode::Eq | Bytecode::Neq) {
            let bool_const = operand_stack.last().and_then(value_is_bool);
            if bool_const.is_some() &&
                (matches!(lhs, SymbolValue::Value(l) if int_has_variable(l) == Some(false)) ||
                    matches!(rhs, SymbolValue::Value(r) if int_has_variable(r) == Some(false)))
            {
                loss = true;
            }
        }

        if loss {
            let message = format!("Unnecessary bool judgement at {}::{} (pc {})", module, function, pc);
            self.record_issue(RuntimeIssue::new(
                RuntimeIssueKind::BoolJudgement,
                module.to_string(),
                function.to_string(),
                pc,
                message,
            ));
        }
    }

    fn check_infinite_loop(&mut self, function_key: &str, pc: u16, module: &str, function: &str) {
        if let Some(SymbolValue::Value(cond)) = self.stack.last() {
            let cond_hash = hash_string(&cond.to_string());
            let entry = self
                .branch_counts
                .entry(function_key.to_string())
                .or_default()
                .entry(pc)
                .or_default();
            if entry.last_hash != Some(cond_hash) {
                entry.last_hash = Some(cond_hash);
                entry.count = 1;
            } else {
                entry.count += 1;
                if entry.count >= INFINITE_LOOP_THRESHOLD {
                    entry.count = 0;
                    let message = format!("Potential infinite loop at {}::{} (pc {})", module, function, pc);
                    self.record_issue(RuntimeIssue::new(
                        RuntimeIssueKind::InfiniteLoop,
                        module.to_string(),
                        function.to_string(),
                        pc,
                        message,
                    ));
                }
            }
        }
    }

    pub fn take_issues(&mut self) -> Vec<RuntimeIssue> {
        std::mem::take(&mut self.runtime_issues)
    }
}

pub struct SymbolicMoveTracer {
    state: ConcolicState,
}

impl SymbolicMoveTracer {
    pub fn new() -> Self {
        Self {
            state: ConcolicState::new(),
        }
    }

    pub fn state(&self) -> &ConcolicState {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut ConcolicState {
        &mut self.state
    }

    pub fn reset(&mut self) {
        self.state = ConcolicState::new();
    }

    pub fn take_issues(&mut self) -> Vec<RuntimeIssue> {
        self.state.take_issues()
    }
}

impl Default for SymbolicMoveTracer {
    fn default() -> Self {
        Self::new()
    }
}

impl MoveTracer for SymbolicMoveTracer {
    fn open_frame(&mut self, frame: &MoveTracerFrameInfo<'_>) {
        self.state.open_frame(frame);
    }

    fn close_frame(&mut self, _frame: &MoveTracerFrameInfo<'_>) {
        self.state.close_frame();
    }

    fn before_instruction(&mut self, instruction: &MoveTracerInstructionContext<'_>) {
        self.state.before_instruction(instruction);
    }
}

fn format_module_name(module_id: &ModuleId) -> String {
    format!("{}::{}", module_id.address().to_hex_literal(), module_id.name())
}

fn value_is_bool(value: &Value) -> Option<bool> {
    if let ValueImpl::Bool(b) = &value.0 {
        Some(*b)
    } else {
        None
    }
}

fn hash_string(value: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn contains_division(expr: &Int) -> bool {
    let mut stack = vec![Dynamic::from(expr.clone())];
    let mut count = 0;
    while let Some(node) = stack.pop() {
        count += 1;
        if count > 10_000 {
            break;
        }
        if let Ok(decl) = node.safe_decl() {
            match decl.kind() {
                DeclKind::DIV | DeclKind::IDIV => return true,
                _ => {}
            }
        }
        stack.extend(node.children());
    }
    false
}

fn int_has_variable(expr: &Int) -> Option<bool> {
    let mut stack = vec![Dynamic::from(expr.clone())];
    let mut count = 0;
    while let Some(node) = stack.pop() {
        count += 1;
        if count > 10_000 {
            return None;
        }
        if node.is_const() {
            if let Ok(decl) = node.safe_decl() {
                if decl.kind() == DeclKind::UNINTERPRETED {
                    return Some(true);
                }
            }
        }
        stack.extend(node.children());
    }
    Some(false)
}
