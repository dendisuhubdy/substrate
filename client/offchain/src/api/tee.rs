
pub struct Sgx;

impl Sgx {
	pub fn remote_attest(&self, url: Vec<u8>) -> Result<(), ()> {
		todo!()
	}

	pub fn call(&self, url: Vec<u8>, http: &crate::api::http::HttpApi) -> Result<(), ()> {
		todo!()
	}
}
