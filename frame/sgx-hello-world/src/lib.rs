// Copyright 2020 Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.

//! # Intel SGX Enclave Hello World

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use frame_support::{
	debug, decl_module, decl_storage, decl_event, decl_error,
	dispatch::DispatchResult,
	weights::Pays
};
use frame_system::{self as system, offchain, ensure_signed};
use frame_system::offchain::{SendSignedTransaction, Signer};
use sp_core::crypto::KeyTypeId;
use sp_runtime::{
	RuntimeDebug,
	offchain::{http, tee},
	transaction_validity::{TransactionValidity, TransactionSource}
};
use sp_std::vec::Vec;
use sp_std::*;

#[cfg(test)]
mod tests;

/// Defines application identifier for crypto keys of this module.
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"sgx!");

pub mod crypto {
	use crate::KEY_TYPE;
	use sp_core::sr25519::Signature as Sr25519Signature;
	use sp_runtime::{
		app_crypto::{app_crypto, sr25519},
		traits::Verify,
		MultiSignature, MultiSigner,
	};

	app_crypto!(sr25519, KEY_TYPE);

	pub struct TestAuthId;
	// implemented for ocw-runtime
	impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}

	// implemented for mock runtime in test
	impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
		for TestAuthId
	{
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}
}

#[derive(Encode, Decode, Default, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct Enclave;

type EnclaveAddress = Vec<u8>;

/// This pallet's configuration trait
pub trait Trait: frame_system::Trait + offchain::CreateSignedTransaction<Call<Self>>  {
	/// The identifier type for an authority.
	type AuthorityId: offchain::AppCrypto<Self::Public, Self::Signature>;
    /// The overarching dispatch call type.
    type Call: From<Call<Self>>;
    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_error! {
    pub enum Error for Module<T: Trait> {
		/// The enclave is already registrered
        EnclaveAlreadyRegistered,
		/// The enclave is not registrered
		EnclaveNotFound
    }
}

decl_storage! {
	trait Store for Module<T: Trait> as SgxHelloWorld {
		/// Enclaves that are verified (i.e, verified via remote attestation)
		VerifiedEnclaves get(fn verified_enclaves): map hasher(twox_64_concat) T::AccountId => Enclave;
		/// Enclaves that are waiting to be verified
		UnverifiedEnclaves get(fn unverified_enclaves): Vec<(T::AccountId, EnclaveAddress)>;
	}
}

decl_event!(
	pub enum Event<T> where AccountId = <T as frame_system::Trait>::AccountId {
		EnclaveAdded(AccountId),
		EnclaveRemoved(AccountId),
	}
);

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		type Error = Error<T>;

		#[weight = (100, Pays::No)]
		fn register_verified_enclave(origin, enclave: T::AccountId) -> DispatchResult {
			let _who = ensure_signed(origin)?;
			<VerifiedEnclaves<T>>::insert(enclave.clone(), Enclave);
			Self::deposit_event(RawEvent::EnclaveRemoved(enclave));
			Ok(())
		}

		#[weight = (100, Pays::No)]
		pub fn register_enclave(origin, url: Vec<u8>) -> DispatchResult {
			let sender = ensure_signed(origin)?;

			let mut unverified_enclaves = UnverifiedEnclaves::<T>::get();
			if <VerifiedEnclaves<T>>::contains_key(&sender) {
				Err(Error::<T>::EnclaveAlreadyRegistered.into())
			} else {
				match unverified_enclaves.binary_search_by(|(s, _)| s.cmp(&sender)) {
					Ok(_) => Err(Error::<T>::EnclaveAlreadyRegistered.into()),
					Err(idx) => {
						unverified_enclaves.insert(idx, (sender.clone(), url));
						UnverifiedEnclaves::<T>::put(unverified_enclaves);
						Ok(())
					}
				}
			}
		}

		#[weight = (100, Pays::No)]
		pub fn deregister_enclave(origin) -> DispatchResult {
			let enclave = ensure_signed(origin)?;
			if <VerifiedEnclaves<T>>::contains_key(&enclave) {
				<VerifiedEnclaves<T>>::remove(enclave.clone());
				Self::deposit_event(RawEvent::EnclaveRemoved(enclave));
				Ok(())
			} else {
				Err(Error::<T>::EnclaveNotFound.into())
			}
		}

		#[weight = (100, Pays::No)]
		pub fn prune_unverified_enclaves(origin) -> DispatchResult {
			let _who = ensure_signed(origin)?;
			<UnverifiedEnclaves<T>>::kill();
			Ok(())
		}

		#[weight = 1000]
		pub fn call_enclave(
			origin,
			from: T::AccountId,
			enclave: T::AccountId,
			xt: Vec<u8>
		) -> DispatchResult {
			todo!("call_enclave");
		}

		fn deposit_event() = default;

		/// Offchain Worker entry point.
		//
		// TODO: use the offchain worker to re-verify the "trusted enclaves"
		// every x block or maybe could be done in `on_initialize` or `on_finalize`
		fn offchain_worker(block_number: T::BlockNumber) {
			let waiting_enclaves = <UnverifiedEnclaves<T>>::get();
			if !waiting_enclaves.is_empty() {
				Self::remote_attest_unverified_enclaves(waiting_enclaves).unwrap();
			}

			// Re-verify "verified enclaves" at least once every hour
			// An enclave might get revoked or vulnerabilities might get detected
			//
			// Assuming the block production time is 1-20 seconds
			if block_number % 2000.into() == 0.into() {
				Self::check_verified_enclaves();
			}
		}
	}
}

impl<T: Trait> Module<T> {
	fn remote_attest_unverified_enclaves(uv: Vec<(T::AccountId, EnclaveAddress)>) -> Result<(), &'static str> {
		let signer = Signer::<T, T::AuthorityId>::all_accounts();
		if !signer.can_sign() {
			return Err(
				"No local accounts available. Consider adding one via `author_insertKey` RPC with keytype \"sgx!\""
			)?
		}

		let _ = signer.send_signed_transaction(
			|_account| {
				Call::prune_unverified_enclaves()
			}
		);

		for (enclave_sign, enclave_addr) in uv {
			let qe = match Self::send_ra_request(&enclave_sign, &enclave_addr) {
				Ok(qe) => qe,
				Err(e) => {
					debug::warn!("[enclave]; request failed: {}. Enclave might be down; ignoring", e);
					continue
				}
			};
			debug::info!("[rx] quoting_report: {:?}", qe);
			let vr = match Self::get_ias_verification_report(&qe) {
				Ok(vr) => vr,
				Err(e) => {
					debug::warn!("[IAS]; request failed with error: {}", e);
					continue
				}
			};
			debug::info!("[rx] ias_verification_report: {:?}", vr);
			let _ = signer.send_signed_transaction(
				|_account| {
					Call::register_verified_enclave(enclave_sign.clone())
				}
			);
		}
		Ok(())
	}

	fn send_ra_request(signer: &T::AccountId, enclave_addr: &[u8]) -> Result<Vec<u8>, &'static str> {
		let enclave_addr = sp_std::str::from_utf8(&enclave_addr).map_err(|_e| "enclave address must be valid utf8")?;
		let body = vec![b"remote_attest\r\n"];
		debug::info!("sending request to: {:?}::{:?}", signer, enclave_addr);
		let pending = http::Request::post(&enclave_addr, body)
			.add_header("substrate_sgx", "1.0")
			.send()
			.unwrap();
		let response = pending.wait().expect("http IO error");
		Ok(response.body().collect())
	}

	// https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf
	fn get_ias_verification_report(quote: &[u8]) -> Result<Vec<u8>, &'static str> {
		const IAS_REPORT_URL: &str = "https://api.trustedservices.intel.com/sgx/dev/attestation/v4/report";
		const API_KEY: &str = "e9589de0dfe5482588600a73d08b70f6";

		// { "isvEnclaveQuote": "<base64 encoded quote>" }
		let encoded_quote = base64::encode(&quote);
		let mut body = Vec::new();
		body.push("{\"isvEnclaveQuote\":");
		body.push("\"");
		body.push(&encoded_quote);
		body.push("\"}");

		let pending = http::Request::post(IAS_REPORT_URL, body)
			.add_header("Content-Type", "application/json")
			.add_header("Ocp-Apim-Subscription-Key", API_KEY)
			.send()
			.unwrap();

		let response = pending.wait().expect("http IO error");
		if response.code == 200 {
			Ok(response.body().collect())
		} else {
			Err("Intel IAS error")
		}
	}

	// TODO
	fn check_verified_enclaves() {}
}

#[allow(deprecated)] // ValidateUnsigned
impl<T: Trait> frame_support::unsigned::ValidateUnsigned for Module<T> {
	type Call = Call<T>;

	fn validate_unsigned(
		_source: TransactionSource,
		_call: &Self::Call,
	) -> TransactionValidity {
		todo!("implement when sgx_hello_world is using unsigned transactions");
	}
}
