use alloy_sol_types::sol;

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        bytes32 block_hash;
        uint32 solution;
        uint32 constraint;
        uint8 fraud_type;
    }
}
