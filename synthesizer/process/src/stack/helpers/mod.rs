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

use super::*;

mod check_upgrade;
mod initialize;
mod sample;
mod stack_trait;
mod synthesize;

pub(super) fn synthesize_proving_key_for_simulate<N: Network, R: Rng + CryptoRng>(
    stack: &Stack<N>,
    function_name: &Identifier<N>,
    rng: &mut R,
) -> Result<()> {
    ensure!(
        N::ID == TestnetV0::ID,
        "Simulate-mode key synthesis is only supported on TestnetV0. Network ID: {}",
        N::ID
    );
    let stack = (stack as &dyn std::any::Any)
        .downcast_ref::<Stack<TestnetV0>>()
        .ok_or_else(|| anyhow!("Simulate key synthesis: stack downcast failed"))?;
    let function_name = (function_name as &dyn std::any::Any)
        .downcast_ref::<Identifier<TestnetV0>>()
        .ok_or_else(|| anyhow!("Simulate key synthesis: identifier downcast failed"))?;
    stack.synthesize_key::<circuit::network::AleoTestnetV0, R>(function_name, rng)
}
