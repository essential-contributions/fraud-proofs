#![no_main]
sp1_zkvm::entrypoint!(main);

use std::collections::{HashMap, HashSet};

use alloy_primitives::FixedBytes;
use alloy_sol_types::SolType;
use essential_constraint_vm::{exec_bytecode, Access, BytecodeMapped, SolutionAccess, StateSlots};
use essential_types::{solution::SolutionData, ContentAddress, PredicateAddress};
use fraud_proof_lib::PublicValuesStruct;

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let n = sp1_zkvm::io::read::<u32>();

    // execute bytecode
    println!("cycle-tracker-start: constraint-vm");
    println!("cycle-tracker-start: map-bytecode");
    let bytes = BytecodeMapped::try_from_bytes(CONSTRAINT_BYTECODE.to_vec()).unwrap();
    println!("cycle-tracker-end: map-bytecode");
    let solution_data = [SolutionData {
        predicate_to_solve: PredicateAddress {
            contract: ContentAddress([0; 32]),
            predicate: ContentAddress([0; 32]),
        },
        decision_variables: vec![],
        state_mutations: vec![],
        transient_data: vec![],
    }];
    let mutable_keys = HashSet::new();
    let transient_data = HashMap::new();
    let access = Access {
        solution: SolutionAccess {
            data: &solution_data,
            index: 0,
            mutable_keys: &mutable_keys,
            transient_data: &transient_data,
        },
        state_slots: StateSlots::EMPTY,
    };
    let result = exec_bytecode(&bytes, access);
    println!("cycle-tracker-end: constraint-vm");

    // Encode the public values of the program.
    println!("cycle-tracker-start: alloy-abi-encode");
    let (a, b, t) = match result {
        Ok(mut stack) => {
            let word = stack.pop().unwrap().to_be_bytes();
            (0, 0, word[7])
        }
        Err(_) => (0, 0, 13),
    };
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct {
        block_hash: FixedBytes::<32>::from([0u8; 32]),
        solution: a,
        constraint: b,
        fraud_type: t,
    });
    println!("cycle-tracker-end: alloy-abi-encode");

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    println!("cycle-tracker-start: commit-bytes");
    sp1_zkvm::io::commit_slice(&bytes);
    println!("cycle-tracker-end: commit-bytes");
}

// Test code that executes heavy cryptographic operations (no storage access)
#[rustfmt::skip]
static CONSTRAINT_BYTECODE: &[u8] = &[
    PUSH, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Push 0 onto the stack
    PUSH, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Push 0 onto the stack
    PUSH, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Push 0 onto the stack
    PUSH, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Push 0 onto the stack
    PUSH, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, // Push 4 onto the stack
    SHA256, // Hash the top 4 words on the stack
    PUSH, 0x66, 0x68, 0x7a, 0xad, 0xf8, 0x62, 0xbd, 0x77, // Push 0x66687aadf862bd77 onto the stack (expected hash)
    PUSH, 0x6c, 0x8f, 0xc1, 0x8b, 0x8e, 0x9f, 0x8e, 0x20, // Push 0x6c8fc18b8e9f8e20 onto the stack (expected hash)
    PUSH, 0x08, 0x97, 0x14, 0x85, 0x6e, 0xe2, 0x33, 0xb3, // Push 0x089714856ee233b3 onto the stack (expected hash)
    PUSH, 0x90, 0x2a, 0x59, 0x1d, 0x0d, 0x5f, 0x29, 0x25, // Push 0x902a591d0d5f2925 onto the stack (expected hash)
    PUSH, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, // Push 4 onto the stack
    EQN, // Check if the hash and top 4 words on the stack are equal
    PUSH, 0x66, 0x68, 0x7a, 0xad, 0xf8, 0x62, 0xbd, 0x77, // Push 0x66687aadf862bd77 onto the stack (prehash)
    PUSH, 0x6c, 0x8f, 0xc1, 0x8b, 0x8e, 0x9f, 0x8e, 0x20, // Push 0x6c8fc18b8e9f8e20 onto the stack (prehash)
    PUSH, 0x08, 0x97, 0x14, 0x85, 0x6e, 0xe2, 0x33, 0xb3, // Push 0x089714856ee233b3 onto the stack (prehash)
    PUSH, 0x90, 0x2a, 0x59, 0x1d, 0x0d, 0x5f, 0x29, 0x25, // Push 0x902a591d0d5f2925 onto the stack (prehash)
    PUSH, 0x65, 0x57, 0xe2, 0x55, 0x68, 0xf5, 0x70, 0x9d, // Push 0x6557e25568f5709d onto the stack (signature)
    PUSH, 0x8e, 0xf0, 0xe2, 0xed, 0x51, 0x4e, 0x05, 0x59, // Push 0x8ef0e2ed514e0559 onto the stack (signature)
    PUSH, 0x43, 0x70, 0x31, 0x0d, 0x2e, 0xb9, 0x15, 0x6a, // Push 0x4370310d2eb9156a onto the stack (signature)
    PUSH, 0xcf, 0xae, 0x57, 0xca, 0x9c, 0x7c, 0xda, 0x1e, // Push 0xcfae57ca9c7cda1e onto the stack (signature)
    PUSH, 0x32, 0x5f, 0x34, 0x33, 0x3b, 0xb5, 0xab, 0xd8, // Push 0x325f34333bb5abd8 onto the stack (signature)
    PUSH, 0xdf, 0x47, 0x0d, 0x8e, 0x21, 0xef, 0x15, 0x23, // Push 0xdf470d8e21ef1523 onto the stack (signature)
    PUSH, 0x73, 0xf1, 0xe2, 0xfc, 0x59, 0xfc, 0xbf, 0x5c, // Push 0x73f1e2fc59fcbf5c onto the stack (signature)
    PUSH, 0x4c, 0x54, 0x86, 0xbf, 0x3a, 0xd0, 0x3f, 0xc3, // Push 0x4c5486bf3ad03fc3 onto the stack (signature)
    PUSH, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Push 1 onto the stack (signature recovery id)
    RECOVER_SECP256K1, // Recover the public key from the secp256k1 signature
    PUSH, 0x03, 0x41, 0x1d, 0xbd, 0x69, 0xcf, 0x3a, 0x61, // Push 0x03411dbd69cf3a61 onto the stack (expected public key)
    PUSH, 0x13, 0x78, 0x7b, 0x4a, 0x2f, 0x9c, 0xa4, 0x91, // Push 0x13787b4a2f9ca491 onto the stack (expected public key)
    PUSH, 0x37, 0x07, 0xc2, 0xf9, 0x06, 0xba, 0x52, 0x58, // Push 0x3707c2f906ba5258 onto the stack (expected public key)
    PUSH, 0x93, 0x1a, 0x3f, 0xde, 0x8d, 0xc8, 0xe6, 0x29, // Push 0x931a3fde8dc8e629 onto the stack (expected public key)
    PUSH, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, // Push 0x0000000000000078 onto the stack (expected public key)
    PUSH, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // Push 5 onto the stack
    EQN, // Check if the expected public key and top 5 words on the stack are equal
    AND,
];

// Stack manipulation opcodes
pub const PUSH: u8 = 0x01; // Push one word onto the stack
pub const POP: u8 = 0x02; // Pop one word from the stack
pub const DUP: u8 = 0x03; // Duplicate the top word on the stack
pub const DUPI: u8 = 0x04; // Duplicate the word at the given stack depth index
pub const SWAP: u8 = 0x05; // Swap top two words on stack
pub const SWAPI: u8 = 0x06; // Swap the top word on the stack with the word at the given stack depth index
pub const SEL: u8 = 0x07; // Conditionally keep one of the top two elements on the stack
pub const SELN: u8 = 0x08; // Conditionally keep one of the top two ranges on the stack

// Predicate opcodes (todo: all of this should be considered as part of the "ALU")
pub const EQ: u8 = 0x10; // Check equality of two words
pub const EQN: u8 = 0x11; // Check equality of two ranges on the stack
pub const EQS: u8 = 0x19; // Pop two sets off the stack and check if they are equal (todo: update numbers to match new ordering)
pub const GT: u8 = 0x12; // Check if left-hand side is greater than right-hand side
pub const LT: u8 = 0x13; // Check if left-hand side is less than right-hand side
pub const GTE: u8 = 0x14; // Check if left-hand side is greater than or equal to right-hand side
pub const LTE: u8 = 0x15; // Check if left-hand side is less than or equal to right-hand side
pub const AND: u8 = 0x16; // Logical AND of two words
pub const OR: u8 = 0x17; // Logical OR of two words
pub const NOT: u8 = 0x18; // Logical NOT of a word

// Arithmetic and logic unit (ALU) opcodes
pub const ADD: u8 = 0x20; // Add two words
pub const SUB: u8 = 0x21; // Subtract two words
pub const MUL: u8 = 0x22; // Multiply two words
pub const DIV: u8 = 0x23; // Integer division
pub const MOD: u8 = 0x24; // Modulus of lhs by rhs

// Access opcodes
pub const CONTRACT: u8 = 0x31; // Get the content hash of the contract this predicate belongs to(todo: this was renamed from THIS_CONTRACT_ADDRESS) (todo: renumber)
pub const PREDICATE: u8 = 0x30; // Get the content hash of this predicate (todo: this was renamed from THIS_ADDRESS) (todo: renumber)
pub const SOLUTION: u8 = 0x32; // Get the pathway of this predicate (todo: this was renamed from THIS_PATHWAY)

pub const PREDICATE_AT: u8 = 0x33; // Get the predicate at solution data pathway
pub const MUT_KEYS: u8 = 0x34; // Push the keys of the proposed state mutations onto the stack
pub const PUB_VAR_KEYS: u8 = 0x35; // Push the keys of the pub vars at `pathway_id` onto the stack
pub const REPEAT_COUNTER: u8 = 0x36; // Access the top repeat counters current value
pub const DECISION_VAR: u8 = 0x37; // Access a range of `len` words starting from `value_ix` within the decision variable located at `slot_ix`
pub const DECISION_VAR_LEN: u8 = 0x38; // Get the length of the decision variable value located at `slot_ix`
pub const STATE: u8 = 0x39; // Access a range of words from the state value located in the slot at `slot_ix`
pub const STATE_LEN: u8 = 0x3A; // Get the length of a state value at a specified `slot_ix`
pub const PUB_VAR: u8 = 0x3B; // Access a range of public decision variable words at `pathway_ix` and key `key_0, ...key_N`
pub const PUB_VAR_LEN: u8 = 0x3C; // Get the length of the value indexed by `pathway_ix` and key `key_0, ...key_N`
pub const NUM_SLOTS: u8 = 0x3D; // Get the number of decision var or state slots

// Cryptographic opcodes
pub const SHA256: u8 = 0x50; // Produce a SHA 256 hash from the specified data
pub const VERIFY_ED25519: u8 = 0x51; // Validate an Ed25519 signature against a public key
pub const RECOVER_SECP256K1: u8 = 0x52; // Recover the public key from a secp256k1 signature

// Control flow opcodes
pub const HALT: u8 = 0x60; // End the execution of the program
pub const HALTI: u8 = 0x61; // Halt the program if the value is true
pub const JMPI: u8 = 0x63; // Jump forward the given number of instructions if the value is true
pub const PANICI: u8 = 0x64; // Panic if the `condition` is true
pub const REP: u8 = 0x09; // Repeat a section of code the number of times (todo: renumber)
pub const REND: u8 = 0x0A; // Increment or decrements the top counter on the repeat stack (todo: renumber)

// Temporary memory opcodes
pub const MGROW: u8 = 0x70; // Allocate new memory to the end of the temporary memory (todo: renamed from ALLOC)
pub const MLOAD: u8 = 0x71; // Load the value at the index of temporary memory onto the stack (todo: renamed from LOAD)
pub const MSTORE: u8 = 0x72; // Store the value at the index of temporary memory (todo: renamed from STORE)

// State slots opcodes
pub const ALLOC_SLOTS: u8 = 0x80; // Allocate new slots to the end of the memory
pub const LOAD_SLOT: u8 = 0x81; // Load the value at the index of a slot onto the stack
pub const STORE_SLOT: u8 = 0x82; // Store the value at the index of state slots
pub const LOAD_SLOT_WORD: u8 = 0x83; // Load the word at the index of the value at the slot onto the stack
pub const STORE_SLOT_WORD: u8 = 0x84; // Store the word at the index of the value at the slot
pub const CLEAR_SLOT: u8 = 0x85; // Clear the value at the index
pub const CLEAR_SLOTS: u8 = 0x86; // Clear a range of values
pub const SLOTS_LEN: u8 = 0x87; // Get the current length of the memory
pub const SLOTS_VALUE_LEN: u8 = 0x88; // Get the current length of a given value at the index

// Key range opcodes
pub const SLOAD: u8 = 0x90; // Read a range of values at each key from state starting at the key into state slots starting at the slot index
pub const KEY_RANGE_EXTERN: u8 = 0x91; // Read a range of values at each key from external state starting at the key into state slots starting at the slot index
