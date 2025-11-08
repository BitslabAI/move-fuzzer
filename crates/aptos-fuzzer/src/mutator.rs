use std::borrow::Cow;
use std::cmp;

use aptos_move_core_types::language_storage::TypeTag;
use aptos_types::transaction::{EntryFunction, Script, TransactionArgument, TransactionPayload};
use libafl::mutators::{MutationResult, Mutator};
use libafl::state::HasRand;
use libafl_bolts::rands::Rand;
use libafl_bolts::Named;

use crate::input::AptosFuzzerInput;
use crate::script_sequence::{compile_sequence, ScriptSequence, SequenceArgument, SequenceCall};
use crate::state::{AptosFuzzerState, FunctionParameter, PublicFunctionTarget};

#[derive(Default)]
pub struct AptosFuzzerMutator {}

impl AptosFuzzerMutator {
    fn mutate_entry_function_args(entry_func: &mut EntryFunction, state: &mut AptosFuzzerState) -> bool {
        let args = entry_func.args();
        if args.is_empty() {
            return false;
        }

        // Create new mutated arguments
        let mut new_args = Vec::new();
        let mut mutated = false;

        for arg_bytes in args.iter() {
            let mut mutated_arg = arg_bytes.clone();
            if Self::mutate_byte_vector(&mut mutated_arg, state) {
                mutated = true;
            }
            new_args.push(mutated_arg);
        }

        if mutated {
            // Reconstruct EntryFunction with mutated args
            let (module, function, ty_args, _) = entry_func.clone().into_inner();
            *entry_func = EntryFunction::new(module, function, ty_args, new_args);
        }

        mutated
    }

    /// Mutate Script arguments using state's random source (pure random)
    fn mutate_script_args(script: &mut Script, state: &mut AptosFuzzerState) -> bool {
        let args = script.args();
        if args.is_empty() {
            return false;
        }

        // Create new mutated arguments
        let mut new_args = Vec::new();
        let mut mutated = false;

        for arg in args.iter() {
            let mut mutated_arg = arg.clone();
            if Self::mutate_transaction_argument(&mut mutated_arg, state) {
                mutated = true;
            }
            new_args.push(mutated_arg);
        }

        if mutated {
            // Reconstruct Script with mutated args
            let (code, ty_args, _) = script.clone().into_inner();
            *script = Script::new(code, ty_args, new_args);
        }

        mutated
    }

    /// Mutate a byte vector using state's random source (pure random bytes)
    fn mutate_byte_vector(bytes: &mut Vec<u8>, state: &mut AptosFuzzerState) -> bool {
        let len = if bytes.is_empty() {
            // choose a small random length
            (1 + (state.rand_mut().next() % 16)) as usize
        } else {
            // keep current length
            bytes.len()
        };
        bytes.resize(len, 0);
        for b in bytes.iter_mut() {
            *b = (state.rand_mut().next() & 0xFF) as u8;
        }
        true
    }

    /// Mutate a TransactionArgument using state's random source (pure random)
    fn mutate_transaction_argument(arg: &mut TransactionArgument, state: &mut AptosFuzzerState) -> bool {
        match arg {
            TransactionArgument::U8(val) => {
                *val = (state.rand_mut().next() & 0xFF) as u8;
                true
            }
            TransactionArgument::U16(val) => {
                *val = (state.rand_mut().next() % 65536) as u16;
                true
            }
            TransactionArgument::U32(val) => {
                *val = (state.rand_mut().next() & 0xFFFF_FFFF) as u32;
                true
            }
            TransactionArgument::U64(val) => {
                *val = state.rand_mut().next();
                true
            }
            TransactionArgument::U128(val) => {
                let hi = state.rand_mut().next() as u128;
                let lo = state.rand_mut().next() as u128;
                *val = (hi << 64) | lo;
                true
            }
            TransactionArgument::U256(val) => {
                let high_part = {
                    let hi = state.rand_mut().next() as u128;
                    let lo = state.rand_mut().next() as u128;
                    (hi << 64) | lo
                };
                let low_part = {
                    let hi = state.rand_mut().next() as u128;
                    let lo = state.rand_mut().next() as u128;
                    (hi << 64) | lo
                };
                let mut bytes = [0u8; 32];
                bytes[0..16].copy_from_slice(&low_part.to_le_bytes());
                bytes[16..32].copy_from_slice(&high_part.to_le_bytes());
                *val = aptos_move_core_types::u256::U256::from_le_bytes(&bytes);
                true
            }
            TransactionArgument::Bool(val) => {
                *val = (state.rand_mut().next() & 1) == 0;
                true
            }
            TransactionArgument::Address(_addr) => {
                let mut addr_bytes = [0u8; 32];
                for byte in addr_bytes.iter_mut() {
                    *byte = (state.rand_mut().next() % 256) as u8;
                }
                *_addr = aptos_move_core_types::account_address::AccountAddress::try_from(addr_bytes.to_vec())
                    .unwrap_or(*_addr);
                true
            }
            TransactionArgument::U8Vector(vec) => {
                let len = (state.rand_mut().next() % 64) as usize;
                vec.clear();
                for _ in 0..len {
                    vec.push((state.rand_mut().next() & 0xFF) as u8);
                }
                true
            }
            TransactionArgument::Serialized(bytes) => {
                let len = (state.rand_mut().next() % 64) as usize;
                bytes.clear();
                bytes.resize(len, 0);
                for b in bytes.iter_mut() {
                    *b = (state.rand_mut().next() & 0xFF) as u8;
                }
                true
            }
        }
    }

    fn mutate_sequence(state: &mut AptosFuzzerState, input: &mut AptosFuzzerInput) -> bool {
        let base_sequence = input.script_sequence().cloned().unwrap_or_else(ScriptSequence::new);
        let available_values = Self::collect_available_values(&base_sequence, state);
        let function_count = state.public_functions().len();
        if function_count == 0 {
            return false;
        }

        let attempts = cmp::min(8, function_count);
        for _ in 0..attempts {
            let idx = (state.rand_mut().next() as usize) % function_count;
            let function = state.public_functions()[idx].clone();
            let Some(call) = Self::build_sequence_call(&function, &available_values, state) else {
                continue;
            };
            let mut new_sequence = base_sequence.clone();
            new_sequence.push_call(call);
            if let Some(mut script) = compile_sequence(&new_sequence, state.aptos_state().module_bytes()) {
                Self::mutate_script_args(&mut script, state);
                *input.payload_mut() = TransactionPayload::Script(script);
                input.set_script_sequence(Some(new_sequence));
                return true;
            }
        }

        false
    }

    fn collect_available_values(sequence: &ScriptSequence, state: &AptosFuzzerState) -> Vec<AvailableValue> {
        let mut values = Vec::new();
        for (call_idx, call) in sequence.calls().iter().enumerate() {
            if let Some(function) = state.public_function(call.module(), call.function()) {
                for (return_idx, ty) in function.return_types().iter().enumerate() {
                    values.push(AvailableValue {
                        call_idx: call_idx as u16,
                        return_idx: return_idx as u16,
                        ty: ty.clone(),
                    });
                }
            }
        }
        values
    }

    fn build_sequence_call(
        function: &PublicFunctionTarget,
        available_values: &[AvailableValue],
        state: &mut AptosFuzzerState,
    ) -> Option<SequenceCall> {
        let mut args = Vec::new();
        for param in function.parameters() {
            match param {
                FunctionParameter::Signer => {
                    return None;
                }
                FunctionParameter::Value(tag) => {
                    let matches: Vec<&AvailableValue> =
                        available_values.iter().filter(|value| value.ty == *tag).collect();
                    let use_previous = !matches.is_empty() && (state.rand_mut().next() & 1) == 0;
                    if use_previous {
                        let index = (state.rand_mut().next() as usize) % matches.len();
                        let value = matches[index];
                        args.push(SequenceArgument::PreviousResult {
                            call_idx: value.call_idx,
                            return_idx: value.return_idx,
                        });
                    } else {
                        let bytes = AptosFuzzerState::default_arg_bytes(tag)?;
                        args.push(SequenceArgument::Raw { bytes, ty: tag.clone() });
                    }
                }
            }
        }

        Some(SequenceCall::new(
            function.module_id().clone(),
            function.name().clone(),
            Vec::new(),
            args,
        ))
    }
}

impl Mutator<AptosFuzzerInput, AptosFuzzerState> for AptosFuzzerMutator {
    fn mutate(
        &mut self,
        state: &mut AptosFuzzerState,
        input: &mut AptosFuzzerInput,
    ) -> Result<MutationResult, libafl::Error> {
        let mutated = match input.payload() {
            TransactionPayload::Script(_) => Self::mutate_sequence(state, input),
            _ => match input.payload_mut() {
                TransactionPayload::EntryFunction(entry_func) => Self::mutate_entry_function_args(entry_func, state),
                _ => false,
            },
        };

        if mutated {
            Ok(MutationResult::Mutated)
        } else {
            Ok(MutationResult::Skipped)
        }
    }

    fn post_exec(
        &mut self,
        _state: &mut AptosFuzzerState,
        _new_corpus_id: Option<libafl::corpus::CorpusId>,
    ) -> Result<(), libafl::Error> {
        Ok(())
    }
}

impl Named for AptosFuzzerMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("AptosFuzzerMutator");
        &NAME
    }
}

#[derive(Clone)]
struct AvailableValue {
    call_idx: u16,
    return_idx: u16,
    ty: TypeTag,
}
