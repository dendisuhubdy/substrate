// This file is part of Substrate.

// Copyright (C) 2019-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! High-level helpers for interaction with SGX enclaves

use sp_std::str;
use sp_std::prelude::Vec;
#[cfg(not(feature = "std"))]
use sp_std::prelude::vec;
use sp_core::RuntimeDebug;
use sp_core::offchain::{
	Timestamp,
	HttpRequestId as RequestId,
	HttpRequestStatus as RequestStatus,
	HttpError,
};

pub struct Enclave;

pub struct Sgx;

impl Sgx {
	pub fn remote_attest(url: Vec<u8>) -> Result<Enclave, ()> {
		sp_io::offchain::tee_remote_attest(url);
		todo!()
	}

	pub fn call(url: Vec<u8>) -> Result<Enclave, ()> {
		todo!()
	}
}
