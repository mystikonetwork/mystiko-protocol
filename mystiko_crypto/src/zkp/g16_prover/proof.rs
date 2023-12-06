use crate::error::ZkpError;
use anyhow::Result;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use typed_builder::TypedBuilder;
use zokrates_bellman::Bellman;
use zokrates_field::{Bn128Field, Field};
use zokrates_proof_systems::groth16::ProofPoints;
use zokrates_proof_systems::{Backend, G1Affine, G2Affine, G2AffineFq2, Scheme, G16};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, TypedBuilder)]
pub struct G16Proof {
    proof: Proof,
    inputs: Vec<String>,
}

impl G16Proof {
    pub fn verify(&self, vk: serde_json::Value) -> Result<bool, ZkpError> {
        let vk_curve = vk
            .get("curve")
            .ok_or_else(|| ZkpError::VKError("Field `curve` not found in verification key".to_string()))?
            .as_str()
            .ok_or_else(|| ZkpError::VKError("`curve` should be a string".to_string()))?;
        let vk_scheme = vk
            .get("scheme")
            .ok_or_else(|| ZkpError::VKError("Field `scheme` not found in verification key".to_string()))?
            .as_str()
            .ok_or_else(|| ZkpError::VKError("`scheme` should be a string".to_string()))?;

        if vk_curve != "bn128" {
            return Err(ZkpError::MismatchError(
                "curve of the proof and the verification mismatch".to_string(),
            ));
        }

        if vk_scheme != "g16" {
            return Err(ZkpError::MismatchError(
                "scheme of the proof and the verification mismatch".to_string(),
            ));
        }

        call_verify::<Bn128Field, G16, Bellman>(vk, (*self).clone().into())
    }

    pub fn to_json_string(&self) -> Result<String, ZkpError> {
        serde_json::to_string_pretty(self).map_err(|why| ZkpError::ProofError(why.to_string()))
    }

    pub fn from_json_string(proof: &str) -> Result<Self, ZkpError> {
        let proof_json: serde_json::Value = serde_json::from_str(proof)?;

        let proof: G16Proof =
            serde_json::from_value(proof_json).map_err(|why| ZkpError::ProofError(why.to_string()))?;
        Ok(proof)
    }

    pub fn convert_to<T: DeserializeOwned>(&self) -> Result<T> {
        let serialized = serde_json::to_string(&self.proof)?;
        Ok(serde_json::from_str(&serialized)?)
    }
}

type ZokratesG16Proof = zokrates_proof_systems::Proof<Bn128Field, G16>;

impl TryFrom<ZokratesG16Proof> for G16Proof {
    type Error = ZkpError;

    fn try_from(zk_proof: ZokratesG16Proof) -> Result<Self, Self::Error> {
        let proof = Proof {
            a: G1Point::from_affine(zk_proof.proof.a),
            b: G2Point::from_affine(zk_proof.proof.b)?,
            c: G1Point::from_affine(zk_proof.proof.c),
        };

        Ok(G16Proof::builder().proof(proof).inputs(zk_proof.inputs).build())
    }
}

impl From<G16Proof> for ZokratesG16Proof {
    fn from(proof: G16Proof) -> Self {
        let point = ProofPoints {
            a: proof.proof.a.to_affine(),
            b: proof.proof.b.to_affine(),
            c: proof.proof.c.to_affine(),
        };
        ZokratesG16Proof::new(point, proof.inputs)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct G1Point {
    pub x: String,
    pub y: String,
}

impl G1Point {
    fn to_affine(&self) -> G1Affine {
        G1Affine(self.x.clone(), self.y.clone())
    }

    fn from_affine(point: G1Affine) -> Self {
        G1Point { x: point.0, y: point.1 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct G2Point {
    pub x: [String; 2],
    pub y: [String; 2],
}

impl G2Point {
    fn to_affine(&self) -> G2Affine {
        G2Affine::Fq2(G2AffineFq2(
            (self.x[0].clone(), self.x[1].clone()),
            (self.y[0].clone(), self.y[1].clone()),
        ))
    }

    fn from_affine(point: G2Affine) -> Result<Self, ZkpError> {
        match point {
            G2Affine::Fq2(a) => Ok(G2Point {
                x: [a.0 .0, a.0 .1],
                y: [a.1 .0, a.1 .1],
            }),
            _ => Err(ZkpError::ProofError("Unexpected G2Affine type".to_string())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct Proof {
    pub a: G1Point,
    pub b: G2Point,
    pub c: G1Point,
}

fn call_verify<T: Field, S: Scheme<T>, B: Backend<T, S>>(
    vk: serde_json::Value,
    proof: zokrates_proof_systems::Proof<T, S>,
) -> Result<bool, ZkpError> {
    let vk = serde_json::from_value(vk).map_err(|why| ZkpError::VKError(why.to_string()))?;
    Ok(B::verify(vk, proof))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mystiko_fs::read_file_bytes;
    use zokrates_proof_systems::G2AffineFq;

    #[test]
    fn test_g2_point_from_affine() {
        let point = G2Affine::Fq2(G2AffineFq2(
            ("1".to_string(), "2".to_string()),
            ("3".to_string(), "4".to_string()),
        ));
        let _ = G2Point::from_affine(point);
        let point = G2Affine::Fq(G2AffineFq("0".to_string(), "1".to_string()));
        let result = G2Point::from_affine(point);
        assert!(matches!(result.err().unwrap(), ZkpError::ProofError(_)));
    }

    #[tokio::test]
    async fn test_proof() {
        let proof = read_file_bytes("./tests/files/zkp/proof.json").await.unwrap();
        let proof: serde_json::Value = serde_json::from_reader(proof.as_slice()).unwrap();
        let proof = G16Proof::from_json_string(&proof.to_string()).unwrap();

        let proof_str = proof.to_json_string().unwrap();
        let proof2 = G16Proof::from_json_string(&proof_str).unwrap();
        let zk_proof: ZokratesG16Proof = proof2.clone().into();
        let proof3: G16Proof = zk_proof.try_into().unwrap();
        assert_eq!(proof, proof2);
        assert_eq!(proof, proof3);
    }
}
