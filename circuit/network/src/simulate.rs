// Copyright (c) 2019-2026 Provable Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::Aleo;
use snarkvm_circuit_algorithms::{
    BHP256,
    BHP512,
    BHP768,
    BHP1024,
    Commit,
    CommitUncompressed,
    Hash,
    HashMany,
    HashToGroup,
    HashToScalar,
    HashUncompressed,
    Keccak256,
    Keccak384,
    Keccak512,
    Pedersen64,
    Pedersen128,
    Poseidon2,
    Poseidon4,
    Poseidon8,
    Sha3_256,
    Sha3_384,
    Sha3_512,
};
use snarkvm_circuit_collections::merkle_tree::MerklePath;
use snarkvm_circuit_types::{
    Boolean,
    Field,
    Group,
    Scalar,
    environment::{Assignment, R1CS, SimulateCircuit, prelude::*},
};

use core::fmt;

type E = SimulateCircuit;

thread_local! {
    static GENERATOR_G: Vec<Group<AleoSimulate>> = Vec::constant(<console::TestnetV0 as console::Network>::g_powers().to_vec());

    static COMMITMENT_DOMAIN: Field<AleoSimulate> = Field::constant(<console::TestnetV0 as console::Network>::commitment_domain());
    static ENCRYPTION_DOMAIN: Field<AleoSimulate> = Field::constant(<console::TestnetV0 as console::Network>::encryption_domain());
    static GRAPH_KEY_DOMAIN: Field<AleoSimulate> = Field::constant(<console::TestnetV0 as console::Network>::graph_key_domain());
    static SERIAL_NUMBER_DOMAIN: Field<AleoSimulate> = Field::constant(<console::TestnetV0 as console::Network>::serial_number_domain());

    static BHP_256: BHP256<AleoSimulate> = BHP256::<AleoSimulate>::constant(console::TESTNET_BHP_256.clone());
    static BHP_512: BHP512<AleoSimulate> = BHP512::<AleoSimulate>::constant(console::TESTNET_BHP_512.clone());
    static BHP_768: BHP768<AleoSimulate> = BHP768::<AleoSimulate>::constant(console::TESTNET_BHP_768.clone());
    static BHP_1024: BHP1024<AleoSimulate> = BHP1024::<AleoSimulate>::constant(console::TESTNET_BHP_1024.clone());

    static KECCAK_256: Keccak256<AleoSimulate> = Keccak256::<AleoSimulate>::new();
    static KECCAK_384: Keccak384<AleoSimulate> = Keccak384::<AleoSimulate>::new();
    static KECCAK_512: Keccak512<AleoSimulate> = Keccak512::<AleoSimulate>::new();

    static PEDERSEN_64: Pedersen64<AleoSimulate> = Pedersen64::<AleoSimulate>::constant(console::TESTNET_PEDERSEN_64.clone());
    static PEDERSEN_128: Pedersen128<AleoSimulate> = Pedersen128::<AleoSimulate>::constant(console::TESTNET_PEDERSEN_128.clone());

    static POSEIDON_2: Poseidon2<AleoSimulate> = Poseidon2::<AleoSimulate>::constant(console::TESTNET_POSEIDON_2.clone());
    static POSEIDON_4: Poseidon4<AleoSimulate> = Poseidon4::<AleoSimulate>::constant(console::TESTNET_POSEIDON_4.clone());
    static POSEIDON_8: Poseidon8<AleoSimulate> = Poseidon8::<AleoSimulate>::constant(console::TESTNET_POSEIDON_8.clone());

    static SHA3_256: Sha3_256<AleoSimulate> = Sha3_256::<AleoSimulate>::new();
    static SHA3_384: Sha3_384<AleoSimulate> = Sha3_384::<AleoSimulate>::new();
    static SHA3_512: Sha3_512<AleoSimulate> = Sha3_512::<AleoSimulate>::new();
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct AleoSimulate;

impl Aleo for AleoSimulate {
    fn initialize_global_constants() {
        GENERATOR_G.with(|_| ());
        COMMITMENT_DOMAIN.with(|_| ());
        ENCRYPTION_DOMAIN.with(|_| ());
        GRAPH_KEY_DOMAIN.with(|_| ());
        SERIAL_NUMBER_DOMAIN.with(|_| ());
        BHP_256.with(|_| ());
        BHP_512.with(|_| ());
        BHP_768.with(|_| ());
        BHP_1024.with(|_| ());
        KECCAK_256.with(|_| ());
        KECCAK_384.with(|_| ());
        KECCAK_512.with(|_| ());
        PEDERSEN_64.with(|_| ());
        PEDERSEN_128.with(|_| ());
        POSEIDON_2.with(|_| ());
        POSEIDON_4.with(|_| ());
        POSEIDON_8.with(|_| ());
        SHA3_256.with(|_| ());
        SHA3_384.with(|_| ());
        SHA3_512.with(|_| ());
    }

    fn commitment_domain() -> Field<Self> {
        COMMITMENT_DOMAIN.with(|domain| domain.clone())
    }

    fn encryption_domain() -> Field<Self> {
        ENCRYPTION_DOMAIN.with(|domain| domain.clone())
    }

    fn graph_key_domain() -> Field<Self> {
        GRAPH_KEY_DOMAIN.with(|domain| domain.clone())
    }

    fn serial_number_domain() -> Field<Self> {
        SERIAL_NUMBER_DOMAIN.with(|domain| domain.clone())
    }

    fn g_powers() -> Vec<Group<Self>> {
        GENERATOR_G.with(|g| g.clone())
    }

    #[inline]
    fn g_scalar_multiply(scalar: &Scalar<Self>) -> Group<Self> {
        GENERATOR_G.with(|bases| {
            bases
                .iter()
                .zip_eq(&scalar.to_bits_le())
                .fold(Group::zero(), |output, (base, bit)| Group::ternary(bit, &(&output + base), &output))
        })
    }

    fn commit_bhp256(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Field<Self> {
        BHP_256.with(|bhp| bhp.commit(input, randomizer))
    }

    fn commit_bhp512(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Field<Self> {
        BHP_512.with(|bhp| bhp.commit(input, randomizer))
    }

    fn commit_bhp768(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Field<Self> {
        BHP_768.with(|bhp| bhp.commit(input, randomizer))
    }

    fn commit_bhp1024(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Field<Self> {
        BHP_1024.with(|bhp| bhp.commit(input, randomizer))
    }

    fn commit_ped64(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Field<Self> {
        PEDERSEN_64.with(|pedersen| pedersen.commit(input, randomizer))
    }

    fn commit_ped128(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Field<Self> {
        PEDERSEN_128.with(|pedersen| pedersen.commit(input, randomizer))
    }

    fn commit_to_group_bhp256(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Group<Self> {
        BHP_256.with(|bhp| bhp.commit_uncompressed(input, randomizer))
    }

    fn commit_to_group_bhp512(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Group<Self> {
        BHP_512.with(|bhp| bhp.commit_uncompressed(input, randomizer))
    }

    fn commit_to_group_bhp768(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Group<Self> {
        BHP_768.with(|bhp| bhp.commit_uncompressed(input, randomizer))
    }

    fn commit_to_group_bhp1024(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Group<Self> {
        BHP_1024.with(|bhp| bhp.commit_uncompressed(input, randomizer))
    }

    fn commit_to_group_ped64(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Group<Self> {
        PEDERSEN_64.with(|pedersen| pedersen.commit_uncompressed(input, randomizer))
    }

    fn commit_to_group_ped128(input: &[Boolean<Self>], randomizer: &Scalar<Self>) -> Group<Self> {
        PEDERSEN_128.with(|pedersen| pedersen.commit_uncompressed(input, randomizer))
    }

    fn hash_bhp256(input: &[Boolean<Self>]) -> Field<Self> {
        BHP_256.with(|bhp| bhp.hash(input))
    }

    fn hash_bhp512(input: &[Boolean<Self>]) -> Field<Self> {
        BHP_512.with(|bhp| bhp.hash(input))
    }

    fn hash_bhp768(input: &[Boolean<Self>]) -> Field<Self> {
        BHP_768.with(|bhp| bhp.hash(input))
    }

    fn hash_bhp1024(input: &[Boolean<Self>]) -> Field<Self> {
        BHP_1024.with(|bhp| bhp.hash(input))
    }

    fn hash_keccak256(input: &[Boolean<Self>]) -> Vec<Boolean<Self>> {
        KECCAK_256.with(|keccak| keccak.hash(input))
    }

    fn hash_keccak384(input: &[Boolean<Self>]) -> Vec<Boolean<Self>> {
        KECCAK_384.with(|keccak| keccak.hash(input))
    }

    fn hash_keccak512(input: &[Boolean<Self>]) -> Vec<Boolean<Self>> {
        KECCAK_512.with(|keccak| keccak.hash(input))
    }

    fn hash_ped64(input: &[Boolean<Self>]) -> Field<Self> {
        PEDERSEN_64.with(|pedersen| pedersen.hash(input))
    }

    fn hash_ped128(input: &[Boolean<Self>]) -> Field<Self> {
        PEDERSEN_128.with(|pedersen| pedersen.hash(input))
    }

    fn hash_psd2(input: &[Field<Self>]) -> Field<Self> {
        POSEIDON_2.with(|poseidon| poseidon.hash(input))
    }

    fn hash_psd4(input: &[Field<Self>]) -> Field<Self> {
        POSEIDON_4.with(|poseidon| poseidon.hash(input))
    }

    fn hash_psd8(input: &[Field<Self>]) -> Field<Self> {
        POSEIDON_8.with(|poseidon| poseidon.hash(input))
    }

    fn hash_sha3_256(input: &[Boolean<Self>]) -> Vec<Boolean<Self>> {
        SHA3_256.with(|sha3| sha3.hash(input))
    }

    fn hash_sha3_384(input: &[Boolean<Self>]) -> Vec<Boolean<Self>> {
        SHA3_384.with(|sha3| sha3.hash(input))
    }

    fn hash_sha3_512(input: &[Boolean<Self>]) -> Vec<Boolean<Self>> {
        SHA3_512.with(|sha3| sha3.hash(input))
    }

    fn hash_many_psd2(input: &[Field<Self>], num_outputs: u16) -> Vec<Field<Self>> {
        POSEIDON_2.with(|poseidon| poseidon.hash_many(input, num_outputs))
    }

    fn hash_many_psd4(input: &[Field<Self>], num_outputs: u16) -> Vec<Field<Self>> {
        POSEIDON_4.with(|poseidon| poseidon.hash_many(input, num_outputs))
    }

    fn hash_many_psd8(input: &[Field<Self>], num_outputs: u16) -> Vec<Field<Self>> {
        POSEIDON_8.with(|poseidon| poseidon.hash_many(input, num_outputs))
    }

    fn hash_to_group_bhp256(input: &[Boolean<Self>]) -> Group<Self> {
        BHP_256.with(|bhp| bhp.hash_uncompressed(input))
    }

    fn hash_to_group_bhp512(input: &[Boolean<Self>]) -> Group<Self> {
        BHP_512.with(|bhp| bhp.hash_uncompressed(input))
    }

    fn hash_to_group_bhp768(input: &[Boolean<Self>]) -> Group<Self> {
        BHP_768.with(|bhp| bhp.hash_uncompressed(input))
    }

    fn hash_to_group_bhp1024(input: &[Boolean<Self>]) -> Group<Self> {
        BHP_1024.with(|bhp| bhp.hash_uncompressed(input))
    }

    fn hash_to_group_ped64(input: &[Boolean<Self>]) -> Group<Self> {
        PEDERSEN_64.with(|pedersen| pedersen.hash_uncompressed(input))
    }

    fn hash_to_group_ped128(input: &[Boolean<Self>]) -> Group<Self> {
        PEDERSEN_128.with(|pedersen| pedersen.hash_uncompressed(input))
    }

    fn hash_to_group_psd2(input: &[Field<Self>]) -> Group<Self> {
        POSEIDON_2.with(|poseidon| poseidon.hash_to_group(input))
    }

    fn hash_to_group_psd4(input: &[Field<Self>]) -> Group<Self> {
        POSEIDON_4.with(|poseidon| poseidon.hash_to_group(input))
    }

    fn hash_to_group_psd8(input: &[Field<Self>]) -> Group<Self> {
        POSEIDON_8.with(|poseidon| poseidon.hash_to_group(input))
    }

    fn hash_to_scalar_psd2(input: &[Field<Self>]) -> Scalar<Self> {
        POSEIDON_2.with(|poseidon| poseidon.hash_to_scalar(input))
    }

    fn hash_to_scalar_psd4(input: &[Field<Self>]) -> Scalar<Self> {
        POSEIDON_4.with(|poseidon| poseidon.hash_to_scalar(input))
    }

    fn hash_to_scalar_psd8(input: &[Field<Self>]) -> Scalar<Self> {
        POSEIDON_8.with(|poseidon| poseidon.hash_to_scalar(input))
    }

    fn verify_merkle_path_bhp<const DEPTH: u8>(
        path: &MerklePath<Self, DEPTH>,
        root: &Field<Self>,
        leaf: &Vec<Boolean<Self>>,
    ) -> Boolean<Self> {
        BHP_1024.with(|bhp1024| BHP_512.with(|bhp512| path.verify(bhp1024, bhp512, root, leaf)))
    }

    fn verify_merkle_path_psd<const DEPTH: u8>(
        path: &MerklePath<Self, DEPTH>,
        root: &Field<Self>,
        leaf: &Vec<Field<Self>>,
    ) -> Boolean<Self> {
        POSEIDON_4.with(|psd4| POSEIDON_2.with(|psd2| path.verify(psd4, psd2, root, leaf)))
    }
}

impl Environment for AleoSimulate {
    type Affine = <E as Environment>::Affine;
    type BaseField = <E as Environment>::BaseField;
    type Network = <E as Environment>::Network;
    type ScalarField = <E as Environment>::ScalarField;

    fn zero() -> LinearCombination<Self::BaseField> {
        E::zero()
    }

    fn one() -> LinearCombination<Self::BaseField> {
        E::one()
    }

    fn new_variable(mode: Mode, value: Self::BaseField) -> Variable<Self::BaseField> {
        E::new_variable(mode, value)
    }

    fn new_witness<Fn: FnOnce() -> Output::Primitive, Output: Inject>(mode: Mode, logic: Fn) -> Output {
        E::new_witness(mode, logic)
    }

    fn scope<S: Into<String>, Fn, Output>(name: S, logic: Fn) -> Output
    where
        Fn: FnOnce() -> Output,
    {
        E::scope(name, logic)
    }

    fn enforce<Fn, A, B, C>(constraint: Fn) -> Result<(), ConstraintUnsatisfied>
    where
        Fn: FnOnce() -> (A, B, C),
        A: Into<LinearCombination<Self::BaseField>>,
        B: Into<LinearCombination<Self::BaseField>>,
        C: Into<LinearCombination<Self::BaseField>>,
    {
        E::enforce(constraint)
    }

    fn is_satisfied() -> bool {
        E::is_satisfied()
    }

    fn is_satisfied_in_scope() -> bool {
        E::is_satisfied_in_scope()
    }

    fn num_constants() -> u64 {
        E::num_constants()
    }

    fn num_public() -> u64 {
        E::num_public()
    }

    fn num_private() -> u64 {
        E::num_private()
    }

    fn num_variables() -> u64 {
        E::num_variables()
    }

    fn num_constraints() -> u64 {
        E::num_constraints()
    }

    fn num_nonzeros() -> (u64, u64, u64) {
        E::num_nonzeros()
    }

    fn num_constants_in_scope() -> u64 {
        E::num_constants_in_scope()
    }

    fn num_public_in_scope() -> u64 {
        E::num_public_in_scope()
    }

    fn num_private_in_scope() -> u64 {
        E::num_private_in_scope()
    }

    fn num_constraints_in_scope() -> u64 {
        E::num_constraints_in_scope()
    }

    fn num_nonzeros_in_scope() -> (u64, u64, u64) {
        E::num_nonzeros_in_scope()
    }

    fn get_variable_limit() -> Option<u64> {
        E::get_variable_limit()
    }

    fn set_variable_limit(limit: Option<u64>) {
        E::set_variable_limit(limit)
    }

    fn get_constraint_limit() -> Option<u64> {
        E::get_constraint_limit()
    }

    fn set_constraint_limit(limit: Option<u64>) {
        E::set_constraint_limit(limit)
    }

    fn halt<S: Into<String>, T>(message: S) -> T {
        E::halt(message)
    }

    fn inject_r1cs(r1cs: R1CS<Self::BaseField>) {
        E::inject_r1cs(r1cs)
    }

    fn eject_r1cs_and_reset() -> R1CS<Self::BaseField> {
        E::eject_r1cs_and_reset()
    }

    fn eject_assignment_and_reset() -> Assignment<<Self::Network as console::Environment>::Field> {
        E::eject_assignment_and_reset()
    }

    fn reset() {
        E::reset()
    }

    fn is_in_simulate_mode() -> bool {
        E::is_in_simulate_mode()
    }
}

impl fmt::Display for AleoSimulate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AleoSimulate")
    }
}
