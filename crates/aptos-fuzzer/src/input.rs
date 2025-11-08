use aptos_types::transaction::TransactionPayload;
use libafl::inputs::Input;
use serde::{Deserialize, Serialize};

use crate::script_sequence::ScriptSequence;

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize, Serialize)]
pub struct AptosFuzzerInput {
    payload: TransactionPayload,
    script_sequence: Option<ScriptSequence>,
}

impl Input for AptosFuzzerInput {}

// Currently we only support TransactionPayload::EntryFunction
// TODO: add script
impl AptosFuzzerInput {
    pub fn new(payload: TransactionPayload) -> Self {
        Self {
            payload,
            script_sequence: None,
        }
    }

    pub fn with_script(payload: TransactionPayload, sequence: ScriptSequence) -> Self {
        Self {
            payload,
            script_sequence: Some(sequence),
        }
    }

    pub fn payload(&self) -> &TransactionPayload {
        &self.payload
    }

    pub fn payload_mut(&mut self) -> &mut TransactionPayload {
        &mut self.payload
    }

    pub fn script_sequence(&self) -> Option<&ScriptSequence> {
        self.script_sequence.as_ref()
    }

    pub fn script_sequence_mut(&mut self) -> Option<&mut ScriptSequence> {
        self.script_sequence.as_mut()
    }

    pub fn set_script_sequence(&mut self, sequence: Option<ScriptSequence>) {
        self.script_sequence = sequence;
    }
}
