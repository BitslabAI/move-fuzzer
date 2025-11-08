use std::cell::{Ref, RefMut};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use aptos_move_binary_format::access::ModuleAccess;
use aptos_move_binary_format::file_format::{SignatureToken, StructHandleIndex, Visibility};
use aptos_move_binary_format::CompiledModule;
use aptos_move_core_types::account_address::AccountAddress;
use aptos_move_core_types::identifier::Identifier;
use aptos_move_core_types::language_storage::{ModuleId, StructTag, TypeTag};
use aptos_move_core_types::u256::U256;
use aptos_types::transaction::{EntryFunction as AptosEntryFunction, TransactionPayload};
use libafl::corpus::{Corpus, CorpusId, HasCurrentCorpusId, HasTestcase, InMemoryCorpus, Testcase};
use libafl::stages::StageId;
use libafl::state::{
    HasCorpus, HasCurrentStageId, HasExecutions, HasImported, HasLastFoundTime, HasLastReportTime, HasRand,
    HasSolutions, HasStartTime, StageStack, Stoppable,
};
use libafl::{HasMetadata, HasNamedMetadata};
use libafl_bolts::rands::StdRand;
use libafl_bolts::serdeany::{NamedSerdeAnyMap, SerdeAnyMap};

use crate::concolic::RuntimeIssue;
use crate::executor::aptos_custom_state::AptosCustomState;
use crate::input::AptosFuzzerInput;
use crate::script_sequence::{compile_sequence, ScriptSequence};
use crate::static_analysis::StaticAnalysisFinding;

// AFL-style map size constant
pub const MAP_SIZE: usize = 1 << 16;

// Similar to libafl::state::StdState
pub struct AptosFuzzerState {
    // RNG instance
    rand: StdRand,
    /// How many times the executor ran the harness/target
    executions: u64,
    /// At what time the fuzzing started
    start_time: Duration,
    /// the number of new paths that imported from other fuzzers
    imported: usize,
    /// The corpus
    corpus: InMemoryCorpus<AptosFuzzerInput>,
    /// Solution corpus
    solutions: InMemoryCorpus<AptosFuzzerInput>,
    /// Execution path captured during the most recent run
    current_execution_path: Option<Vec<u32>>,
    current_execution_path_id: Option<u64>,
    /// Execution paths recorded for interesting inputs
    execution_paths_by_input: HashMap<AptosFuzzerInput, ExecutionPathRecord>,
    /// Execution path IDs observed so far to deduplicate interesting inputs
    seen_execution_paths: HashSet<u64>,
    /// Metadata stored for this state by one of the components
    metadata: SerdeAnyMap,
    /// Metadata stored with names
    named_metadata: NamedSerdeAnyMap,
    /// The last time something was added to the corpus
    last_found_time: Duration,
    /// The last time we reported progress (if available/used).
    /// This information is used by fuzzer `maybe_report_progress`.
    last_report_time: Option<Duration>,
    /// The current index of the corpus; used to record for resumable fuzzing.
    corpus_id: Option<CorpusId>,
    /// Request the fuzzer to stop at the start of the next stage
    /// or at the beginning of the next fuzzing iteration
    stop_requested: bool,
    stage_stack: StageStack,

    /// Aptos specific fields
    aptos_state: AptosCustomState,
    /// Cumulative coverage map for statistics (Observer map resets each
    /// execution)
    cumulative_coverage: Vec<u8>,
    /// Execution path IDs that triggered abort-code objectives
    pub abort_code_paths: HashSet<u64>,
    /// Execution path IDs that triggered shift overflow objectives
    pub shift_overflow_paths: HashSet<u64>,
    /// Modules explicitly loaded for fuzzing
    target_modules: Vec<ModuleId>,
    /// Static analysis findings discovered before fuzzing
    static_findings: Vec<StaticAnalysisFinding>,
    last_runtime_issues: Vec<RuntimeIssue>,
    /// Public functions discovered from loaded modules
    public_functions: Vec<PublicFunctionTarget>,
    /// Lookup table for module::function -> public function index
    function_lookup: HashMap<String, usize>,
}

#[derive(Clone)]
struct ExecutionPathRecord {
    id: u64,
    path: Vec<u32>,
}

#[derive(Clone, Debug)]
pub struct PublicFunctionTarget {
    module_id: ModuleId,
    name: Identifier,
    parameters: Vec<FunctionParameter>,
    return_types: Vec<TypeTag>,
    is_entry: bool,
}

impl PublicFunctionTarget {
    pub fn module_id(&self) -> &ModuleId {
        &self.module_id
    }

    pub fn name(&self) -> &Identifier {
        &self.name
    }

    pub fn parameters(&self) -> &[FunctionParameter] {
        &self.parameters
    }

    pub fn return_types(&self) -> &[TypeTag] {
        &self.return_types
    }

    pub fn is_entry(&self) -> bool {
        self.is_entry
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FunctionParameter {
    Signer,
    Value(TypeTag),
}

struct LoadedModule {
    module_id: ModuleId,
    module: CompiledModule,
    bytes: Vec<u8>,
}

impl AptosFuzzerState {
    pub fn new(modules_dir: PathBuf) -> Self {
        let loaded_modules = Self::load_modules_from_path(&modules_dir);
        let mut state = Self {
            // TODO: replace me with actual aptos state
            aptos_state: AptosCustomState::new_default(),
            rand: StdRand::new(),
            executions: 0,
            start_time: Duration::from_secs(0),
            imported: 0,
            corpus: InMemoryCorpus::new(),
            solutions: InMemoryCorpus::new(),
            current_execution_path: None,
            current_execution_path_id: None,
            execution_paths_by_input: HashMap::new(),
            seen_execution_paths: HashSet::new(),
            abort_code_paths: HashSet::new(),
            shift_overflow_paths: HashSet::new(),
            metadata: SerdeAnyMap::new(),
            named_metadata: NamedSerdeAnyMap::new(),
            last_found_time: Duration::from_secs(0),
            last_report_time: None,
            corpus_id: None,
            stop_requested: false,
            stage_stack: StageStack::default(),
            cumulative_coverage: vec![0u8; MAP_SIZE],
            target_modules: Vec::new(),
            static_findings: Vec::new(),
            last_runtime_issues: Vec::new(),
            public_functions: Vec::new(),
            function_lookup: HashMap::new(),
        };

        let mut entry_payloads = Vec::new();
        for loaded in loaded_modules {
            state
                .aptos_state
                .deploy_module_bytes(loaded.module_id.clone(), loaded.bytes);
            state.target_modules.push(loaded.module_id.clone());

            for function in Self::extract_public_functions(&loaded.module_id, &loaded.module) {
                if function.is_entry() {
                    if let Some(payload) = Self::entry_payload_from_function(&function) {
                        entry_payloads.push(payload);
                    }
                }
                let key = Self::function_key(function.module_id(), function.name());
                state.function_lookup.insert(key, state.public_functions.len());
                state.public_functions.push(function);
            }
        }

        for payload in entry_payloads {
            let input = AptosFuzzerInput::new(payload);
            let _ = state.corpus.add(Testcase::new(input));
        }

        if let Some(script_input) = Self::make_empty_script_seed(state.aptos_state()) {
            let _ = state.corpus.add(Testcase::new(script_input));
        }
        state
    }

    /// Drain current corpus entries into a vector of inputs and clear the
    /// corpus. Useful to re-insert seeds via fuzzer.add_input so
    /// events/feedback are fired.
    pub fn take_initial_inputs(&mut self) -> Vec<AptosFuzzerInput> {
        let ids: Vec<_> = self.corpus().ids().collect();
        let mut inputs = Vec::with_capacity(ids.len());
        for id in ids {
            if let Ok(input) = self.corpus().cloned_input_for_id(id) {
                inputs.push(input);
            }
        }
        // Clear existing entries
        while let Some(id) = self.corpus().ids().next() {
            let _ = self.corpus_mut().remove(id);
        }
        inputs
    }

    pub fn aptos_state(&self) -> &AptosCustomState {
        &self.aptos_state
    }

    pub fn aptos_state_mut(&mut self) -> &mut AptosCustomState {
        &mut self.aptos_state
    }

    pub fn cumulative_coverage(&self) -> &[u8] {
        &self.cumulative_coverage
    }

    pub fn cumulative_coverage_mut(&mut self) -> &mut [u8] {
        &mut self.cumulative_coverage
    }

    pub fn take_solutions(&self) -> Vec<AptosFuzzerInput> {
        let solutions = self.solutions();
        let mut seen_ids = HashSet::new();
        let mut inputs = Vec::new();
        for id in solutions.ids() {
            if let Ok(input) = solutions.cloned_input_for_id(id) {
                if let Some(record) = self.execution_paths_by_input.get(&input) {
                    if seen_ids.insert(record.id) {
                        inputs.push(input);
                    }
                }
            }
        }
        inputs
    }

    pub fn clear_current_execution_path(&mut self) {
        self.current_execution_path = None;
        self.current_execution_path_id = None;
    }

    pub fn set_current_execution_path(&mut self, execution_path: Vec<u32>) {
        let id = Self::compute_execution_path_id(&execution_path);
        self.current_execution_path = Some(execution_path);
        self.current_execution_path_id = Some(id);
    }

    pub fn current_execution_path_id(&self) -> Option<u64> {
        self.current_execution_path_id
    }

    pub fn set_last_runtime_issues(&mut self, issues: Vec<RuntimeIssue>) {
        self.last_runtime_issues = issues;
    }

    pub fn last_runtime_issues(&self) -> &[RuntimeIssue] {
        &self.last_runtime_issues
    }

    pub fn record_current_execution_path_for(&mut self, input: &AptosFuzzerInput) -> Option<u64> {
        match (self.current_execution_path_id, self.current_execution_path.as_ref()) {
            (Some(id), Some(path)) => {
                self.execution_paths_by_input
                    .entry(input.clone())
                    .or_insert_with(|| ExecutionPathRecord { id, path: path.clone() });
                Some(id)
            }
            _ => None,
        }
    }

    pub fn mark_execution_path_seen(&mut self, path_id: u64) -> bool {
        self.seen_execution_paths.insert(path_id)
    }

    pub fn has_seen_execution_path(&self, path_id: u64) -> bool {
        self.seen_execution_paths.contains(&path_id)
    }

    pub fn get_solution_execution_path(&self, input: &AptosFuzzerInput) -> Option<Vec<u32>> {
        self.execution_paths_by_input
            .get(input)
            .map(|record| record.path.clone())
    }

    pub fn get_solution_execution_path_id(&self, input: &AptosFuzzerInput) -> Option<u64> {
        self.execution_paths_by_input.get(input).map(|record| record.id)
    }

    pub fn compute_execution_path_id(execution_path: &[u32]) -> u64 {
        const FNV_OFFSET: u64 = 0xcbf29ce484222325;
        const FNV_PRIME: u64 = 0x100000001b3;
        execution_path.iter().fold(FNV_OFFSET, |hash, value| {
            let hash = hash ^ (*value as u64);
            hash.wrapping_mul(FNV_PRIME)
        })
    }

    pub fn target_modules(&self) -> &[ModuleId] {
        &self.target_modules
    }

    pub fn public_functions(&self) -> &[PublicFunctionTarget] {
        &self.public_functions
    }

    pub fn public_function(&self, module_id: &ModuleId, name: &Identifier) -> Option<&PublicFunctionTarget> {
        let key = Self::function_key(module_id, name);
        self.function_lookup
            .get(&key)
            .and_then(|idx| self.public_functions.get(*idx))
    }

    pub fn set_static_findings(&mut self, findings: Vec<StaticAnalysisFinding>) {
        self.static_findings = findings;
    }

    pub fn static_findings(&self) -> &[StaticAnalysisFinding] {
        &self.static_findings
    }
}

// initial inputs
impl HasCorpus<AptosFuzzerInput> for AptosFuzzerState {
    type Corpus = InMemoryCorpus<AptosFuzzerInput>;

    fn corpus(&self) -> &InMemoryCorpus<AptosFuzzerInput> {
        &self.corpus
    }

    fn corpus_mut(&mut self) -> &mut InMemoryCorpus<AptosFuzzerInput> {
        &mut self.corpus
    }
}

impl HasRand for AptosFuzzerState {
    type Rand = StdRand;

    fn rand(&self) -> &StdRand {
        &self.rand
    }

    fn rand_mut(&mut self) -> &mut StdRand {
        &mut self.rand
    }
}

impl HasCurrentCorpusId for AptosFuzzerState {
    fn set_corpus_id(&mut self, id: CorpusId) -> Result<(), libafl::Error> {
        self.corpus_id = Some(id);
        Ok(())
    }

    fn clear_corpus_id(&mut self) -> Result<(), libafl::Error> {
        self.corpus_id = None;
        Ok(())
    }

    fn current_corpus_id(&self) -> Result<Option<CorpusId>, libafl::Error> {
        Ok(self.corpus_id)
    }
}

impl Stoppable for AptosFuzzerState {
    fn stop_requested(&self) -> bool {
        self.stop_requested
    }

    fn request_stop(&mut self) {
        self.stop_requested = true;
    }

    fn discard_stop_request(&mut self) {
        self.stop_requested = false;
    }
}

impl HasMetadata for AptosFuzzerState {
    fn metadata_map(&self) -> &SerdeAnyMap {
        &self.metadata
    }

    fn metadata_map_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

impl HasNamedMetadata for AptosFuzzerState {
    fn named_metadata_map(&self) -> &NamedSerdeAnyMap {
        &self.named_metadata
    }

    fn named_metadata_map_mut(&mut self) -> &mut NamedSerdeAnyMap {
        &mut self.named_metadata
    }
}

impl HasExecutions for AptosFuzzerState {
    fn executions(&self) -> &u64 {
        &self.executions
    }

    fn executions_mut(&mut self) -> &mut u64 {
        &mut self.executions
    }
}

impl HasLastFoundTime for AptosFuzzerState {
    fn last_found_time(&self) -> &Duration {
        &self.last_found_time
    }

    fn last_found_time_mut(&mut self) -> &mut Duration {
        &mut self.last_found_time
    }
}

// inputs that can trigger a bug
impl HasSolutions<AptosFuzzerInput> for AptosFuzzerState {
    type Solutions = InMemoryCorpus<AptosFuzzerInput>;
    fn solutions(&self) -> &InMemoryCorpus<AptosFuzzerInput> {
        &self.solutions
    }

    fn solutions_mut(&mut self) -> &mut InMemoryCorpus<AptosFuzzerInput> {
        &mut self.solutions
    }
}

impl HasTestcase<AptosFuzzerInput> for AptosFuzzerState {
    fn testcase(&self, id: CorpusId) -> Result<Ref<'_, Testcase<AptosFuzzerInput>>, libafl::Error> {
        Ok(self.corpus().get(id)?.borrow())
    }

    fn testcase_mut(&self, id: CorpusId) -> Result<RefMut<'_, Testcase<AptosFuzzerInput>>, libafl::Error> {
        Ok(self.corpus().get(id)?.borrow_mut())
    }
}

impl HasImported for AptosFuzzerState {
    fn imported(&self) -> &usize {
        &self.imported
    }

    fn imported_mut(&mut self) -> &mut usize {
        &mut self.imported
    }
}

impl HasLastReportTime for AptosFuzzerState {
    fn last_report_time(&self) -> &Option<Duration> {
        &self.last_report_time
    }

    fn last_report_time_mut(&mut self) -> &mut Option<Duration> {
        &mut self.last_report_time
    }
}

impl HasCurrentStageId for AptosFuzzerState {
    fn set_current_stage_id(&mut self, id: StageId) -> Result<(), libafl::Error> {
        self.stage_stack.set_current_stage_id(id)
    }

    fn clear_stage_id(&mut self) -> Result<(), libafl::Error> {
        self.stage_stack.clear_stage_id()
    }

    fn current_stage_id(&self) -> Result<Option<StageId>, libafl::Error> {
        self.stage_stack.current_stage_id()
    }
}

impl HasStartTime for AptosFuzzerState {
    fn start_time(&self) -> &Duration {
        &self.start_time
    }

    fn start_time_mut(&mut self) -> &mut Duration {
        &mut self.start_time
    }
}

impl AptosFuzzerState {
    fn make_empty_script_seed(state: &AptosCustomState) -> Option<AptosFuzzerInput> {
        let sequence = ScriptSequence::new();
        compile_sequence(&sequence, state.module_bytes())
            .map(|script| AptosFuzzerInput::with_script(TransactionPayload::Script(script), sequence))
    }

    fn load_modules_from_path(path: &Path) -> Vec<LoadedModule> {
        let mut files = Vec::new();
        Self::collect_module_files(path, &mut files);
        files.sort();

        let mut loaded = Vec::new();
        let mut seen = HashSet::new();
        for file in files {
            let bytes = match fs::read(&file) {
                Ok(bytes) => bytes,
                Err(err) => {
                    eprintln!("[aptos-fuzzer] failed to read module {}: {err}", file.display());
                    continue;
                }
            };
            let module = match CompiledModule::deserialize(bytes.as_slice()) {
                Ok(module) => module,
                Err(err) => {
                    eprintln!("[aptos-fuzzer] failed to deserialize module {}: {err}", file.display());
                    continue;
                }
            };
            let module_id = module.self_id();
            if seen.insert(module_id.clone()) {
                loaded.push(LoadedModule {
                    module_id,
                    module,
                    bytes,
                });
            }
        }
        loaded
    }

    fn collect_module_files(path: &Path, files: &mut Vec<PathBuf>) {
        if Self::is_dependency_path(path) {
            return;
        }
        if path.is_dir() {
            let entries = match fs::read_dir(path) {
                Ok(entries) => entries,
                Err(err) => {
                    eprintln!("[aptos-fuzzer] failed to list directory {}: {err}", path.display());
                    return;
                }
            };
            for entry in entries {
                if let Ok(dir_entry) = entry {
                    Self::collect_module_files(&dir_entry.path(), files);
                }
            }
            return;
        }

        if path.extension().map(|ext| ext == "mv").unwrap_or(false) {
            files.push(path.to_path_buf());
        }
    }

    fn is_dependency_path(path: &Path) -> bool {
        path.components()
            .any(|component| matches!(component, Component::Normal(name) if name.to_str() == Some("dependencies")))
    }

    fn extract_public_functions(module_id: &ModuleId, module: &CompiledModule) -> Vec<PublicFunctionTarget> {
        let mut functions = Vec::new();
        for func_def in &module.function_defs {
            if func_def.visibility != Visibility::Public {
                continue;
            }
            let handle = module.function_handle_at(func_def.function);
            if !handle.type_parameters.is_empty() {
                continue;
            }

            let params_sig = module.signature_at(handle.parameters);
            let parameters = match Self::parameters_from_signature(module, &params_sig.0) {
                Some(params) => params,
                None => continue,
            };

            let returns_sig = module.signature_at(handle.return_);
            let return_types = match Self::signature_tokens_to_typetags(module, &returns_sig.0) {
                Some(types) => types,
                None => continue,
            };

            let name = module.identifier_at(handle.name).to_owned();
            functions.push(PublicFunctionTarget {
                module_id: module_id.clone(),
                name,
                parameters,
                return_types,
                is_entry: func_def.is_entry,
            });
        }
        functions
    }

    fn parameters_from_signature(module: &CompiledModule, tokens: &[SignatureToken]) -> Option<Vec<FunctionParameter>> {
        let mut params = Vec::new();
        for token in tokens {
            match token {
                SignatureToken::Signer => params.push(FunctionParameter::Signer),
                SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) => {
                    if matches!(inner.as_ref(), SignatureToken::Signer) {
                        params.push(FunctionParameter::Signer);
                    } else {
                        return None;
                    }
                }
                _ => {
                    let ty = Self::signature_token_to_type_tag(module, token)?;
                    params.push(FunctionParameter::Value(ty));
                }
            }
        }
        Some(params)
    }

    fn signature_tokens_to_typetags(module: &CompiledModule, tokens: &[SignatureToken]) -> Option<Vec<TypeTag>> {
        tokens
            .iter()
            .map(|token| Self::signature_token_to_type_tag(module, token))
            .collect()
    }

    fn signature_token_to_type_tag(module: &CompiledModule, token: &SignatureToken) -> Option<TypeTag> {
        Some(match token {
            SignatureToken::Bool => TypeTag::Bool,
            SignatureToken::U8 => TypeTag::U8,
            SignatureToken::U16 => TypeTag::U16,
            SignatureToken::U32 => TypeTag::U32,
            SignatureToken::U64 => TypeTag::U64,
            SignatureToken::U128 => TypeTag::U128,
            SignatureToken::U256 => TypeTag::U256,
            SignatureToken::Address => TypeTag::Address,
            SignatureToken::Signer => TypeTag::Signer,
            SignatureToken::Vector(inner) => {
                TypeTag::Vector(Box::new(Self::signature_token_to_type_tag(module, inner)?))
            }
            SignatureToken::Struct(handle_idx) => {
                TypeTag::Struct(Box::new(Self::struct_tag_from_handle(module, *handle_idx, &[])?))
            }
            SignatureToken::StructInstantiation(handle_idx, tys) => {
                let type_args = tys
                    .iter()
                    .map(|inner| Self::signature_token_to_type_tag(module, inner))
                    .collect::<Option<Vec<_>>>()?;
                TypeTag::Struct(Box::new(Self::struct_tag_from_handle(module, *handle_idx, &type_args)?))
            }
            _ => return None,
        })
    }

    fn struct_tag_from_handle(
        module: &CompiledModule,
        handle_idx: StructHandleIndex,
        type_args: &[TypeTag],
    ) -> Option<StructTag> {
        let handle = module.struct_handle_at(handle_idx);
        if !handle.type_parameters.is_empty() && handle.type_parameters.len() != type_args.len() {
            return None;
        }
        let module_handle = module.module_handle_at(handle.module);
        let address = *module.address_identifier_at(module_handle.address);
        let module_name = module.identifier_at(module_handle.name).to_owned();
        let struct_name = module.identifier_at(handle.name).to_owned();
        Some(StructTag {
            address,
            module: module_name,
            name: struct_name,
            type_args: type_args.to_vec(),
        })
    }

    fn entry_payload_from_function(function: &PublicFunctionTarget) -> Option<TransactionPayload> {
        let mut args = Vec::new();
        for param in function.parameters() {
            if let FunctionParameter::Value(tag) = param {
                let bytes = Self::default_arg_bytes(tag)?;
                args.push(bytes);
            }
        }

        let entry = AptosEntryFunction::new(function.module_id().clone(), function.name().clone(), Vec::new(), args);
        Some(TransactionPayload::EntryFunction(entry))
    }

    fn function_key(module_id: &ModuleId, name: &Identifier) -> String {
        format!("{}::{}", module_id, name)
    }

    pub(crate) fn default_arg_bytes(type_tag: &TypeTag) -> Option<Vec<u8>> {
        match type_tag {
            TypeTag::Bool => bcs::to_bytes(&false).ok(),
            TypeTag::U8 => bcs::to_bytes(&0u8).ok(),
            TypeTag::U16 => bcs::to_bytes(&0u16).ok(),
            TypeTag::U32 => bcs::to_bytes(&0u32).ok(),
            TypeTag::U64 => bcs::to_bytes(&0u64).ok(),
            TypeTag::U128 => bcs::to_bytes(&0u128).ok(),
            TypeTag::U256 => bcs::to_bytes(&U256::from(0u8)).ok(),
            TypeTag::Address => bcs::to_bytes(&AccountAddress::ZERO).ok(),
            TypeTag::Vector(inner) => match &**inner {
                TypeTag::Bool => bcs::to_bytes::<Vec<bool>>(&Vec::new()).ok(),
                TypeTag::U8 => bcs::to_bytes::<Vec<u8>>(&Vec::new()).ok(),
                TypeTag::U16 => bcs::to_bytes::<Vec<u16>>(&Vec::new()).ok(),
                TypeTag::U32 => bcs::to_bytes::<Vec<u32>>(&Vec::new()).ok(),
                TypeTag::U64 => bcs::to_bytes::<Vec<u64>>(&Vec::new()).ok(),
                TypeTag::U128 => bcs::to_bytes::<Vec<u128>>(&Vec::new()).ok(),
                TypeTag::U256 => bcs::to_bytes::<Vec<U256>>(&Vec::new()).ok(),
                TypeTag::Address => bcs::to_bytes::<Vec<AccountAddress>>(&Vec::new()).ok(),
                _ => None,
            },
            _ => None,
        }
    }
}
