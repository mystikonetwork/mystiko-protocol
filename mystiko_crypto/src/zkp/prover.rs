use anyhow::Result;
use typed_builder::TypedBuilder;

#[derive(Debug, Clone, TypedBuilder)]
pub struct ZKProveOptions<'a> {
    pub program: &'a [u8],
    pub abi_spec: &'a [u8],
    pub proving_key: &'a [u8],
    pub json_args_str: &'a str,
}

#[derive(Debug, Clone, TypedBuilder)]
pub struct ZKVerifyOptions<'a, Proof> {
    pub proof: &'a Proof,
    pub verification_key: &'a [u8],
}

pub trait ZKProver<P>: Send + Sync {
    type Error;

    fn prove(&self, options: ZKProveOptions) -> Result<P, Self::Error>;
    fn verify(&self, options: ZKVerifyOptions<P>) -> Result<bool, Self::Error>;
}
