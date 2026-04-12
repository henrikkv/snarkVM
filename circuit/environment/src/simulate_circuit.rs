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

use crate::{ConstraintUnsatisfied, Mode, *};

use core::fmt;
use std::sync::Arc;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct SimulateCircuit;

impl Environment for SimulateCircuit {
    type Affine = <console::TestnetV0 as console::Environment>::Affine;
    type BaseField = <console::TestnetV0 as console::Environment>::Field;
    type Network = console::TestnetV0;
    type ScalarField = <console::TestnetV0 as console::Environment>::Scalar;

    fn zero() -> LinearCombination<Self::BaseField> {
        LinearCombination::zero()
    }

    fn one() -> LinearCombination<Self::BaseField> {
        LinearCombination::one()
    }

    fn new_variable(_mode: Mode, value: Self::BaseField) -> Variable<Self::BaseField> {
        Variable::Constant(Arc::new(value))
    }

    fn new_witness<Fn: FnOnce() -> Output::Primitive, Output: Inject>(_mode: Mode, logic: Fn) -> Output {
        Inject::new(Mode::Constant, logic())
    }

    fn scope<S: Into<String>, Fn, Output>(_name: S, logic: Fn) -> Output
    where
        Fn: FnOnce() -> Output,
    {
        logic()
    }

    fn enforce<Fn, A, B, C>(constraint: Fn) -> Result<(), ConstraintUnsatisfied>
    where
        Fn: FnOnce() -> (A, B, C),
        A: Into<LinearCombination<Self::BaseField>>,
        B: Into<LinearCombination<Self::BaseField>>,
        C: Into<LinearCombination<Self::BaseField>>,
    {
        let (a, b, c) = constraint();
        let (a, b, c) = (a.into(), b.into(), c.into());
        if a.value() * b.value() != c.value() {
            return Err(ConstraintUnsatisfied { a: a.to_string(), b: b.to_string(), c: c.to_string() });
        }
        Ok(())
    }

    fn is_satisfied() -> bool {
        true
    }

    fn is_satisfied_in_scope() -> bool {
        true
    }

    fn num_constants() -> u64 {
        0
    }

    fn num_public() -> u64 {
        0
    }

    fn num_private() -> u64 {
        0
    }

    fn num_variables() -> u64 {
        0
    }

    fn num_constraints() -> u64 {
        0
    }

    fn num_nonzeros() -> (u64, u64, u64) {
        (0, 0, 0)
    }

    fn num_constants_in_scope() -> u64 {
        0
    }

    fn num_public_in_scope() -> u64 {
        0
    }

    fn num_private_in_scope() -> u64 {
        0
    }

    fn num_constraints_in_scope() -> u64 {
        0
    }

    fn num_nonzeros_in_scope() -> (u64, u64, u64) {
        (0, 0, 0)
    }

    fn get_variable_limit() -> Option<u64> {
        None
    }

    fn set_variable_limit(_limit: Option<u64>) {}

    fn get_constraint_limit() -> Option<u64> {
        None
    }

    fn set_constraint_limit(_limit: Option<u64>) {}

    fn halt<S: Into<String>, T>(message: S) -> T {
        panic!("{}", message.into())
    }

    fn inject_r1cs(_r1cs: R1CS<Self::BaseField>) {}

    fn eject_r1cs_and_reset() -> R1CS<Self::BaseField> {
        R1CS::new()
    }

    fn eject_assignment_and_reset() -> Assignment<<Self::Network as console::Environment>::Field> {
        Assignment::from(R1CS::new())
    }

    fn reset() {}

    fn is_in_simulate_mode() -> bool {
        true
    }
}

impl fmt::Display for SimulateCircuit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SimulateCircuit")
    }
}
