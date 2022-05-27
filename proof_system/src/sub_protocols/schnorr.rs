use ark_ec::{AffineCurve, PairingEngine};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::RngCore;
use ark_std::UniformRand;
use ark_std::{collections::BTreeMap, io::Write, vec::Vec};
use schnorr_pok::{SchnorrChallengeContributor, SchnorrCommitment};
use zeroize::Zeroize;

use crate::error::ProofSystemError;
use crate::statement_proof::{PedersenCommitmentProof, StatementProof};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchnorrProtocol<'a, G: AffineCurve> {
    pub id: usize,
    pub commitment_key: &'a [G],
    pub commitment: G,
    pub commitment_to_randomness: Option<SchnorrCommitment<G>>,
    pub witnesses: Option<Vec<G::ScalarField>>,
}

impl<'a, G: AffineCurve> SchnorrProtocol<'a, G> {
    pub fn new(id: usize, commitment_key: &'a [G], commitment: G) -> Self {
        Self {
            id,
            commitment_key,
            commitment,
            commitment_to_randomness: None,
            witnesses: None,
        }
    }

    /// `blindings` specifies the randomness to use. If some index is not present, new randomness is generated for it.
    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        mut blindings: BTreeMap<usize, G::ScalarField>,
        witnesses: Vec<G::ScalarField>,
    ) -> Result<(), ProofSystemError> {
        if self.commitment_to_randomness.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let blindings = (0..witnesses.len())
            .map(|i| {
                blindings
                    .remove(&i)
                    .unwrap_or_else(|| G::ScalarField::rand(rng))
            })
            .collect::<Vec<_>>();
        self.commitment_to_randomness =
            Some(SchnorrCommitment::new(&self.commitment_key, blindings));
        self.witnesses = Some(witnesses);
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), ProofSystemError> {
        if self.commitment_to_randomness.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                self.id,
            ));
        }
        self.commitment_key.serialize_unchecked(&mut writer)?;
        self.commitment.serialize_unchecked(&mut writer)?;
        self.commitment_to_randomness
            .as_ref()
            .unwrap()
            .challenge_contribution(writer)?;
        Ok(())
    }

    pub fn gen_proof_contribution<E: PairingEngine>(
        &mut self,
        challenge: &G::ScalarField,
    ) -> Result<StatementProof<E, G>, ProofSystemError> {
        Ok(StatementProof::PedersenCommitment(
            self.gen_proof_contribution_as_struct(challenge)?,
        ))
    }

    pub fn gen_proof_contribution_as_struct(
        &mut self,
        challenge: &G::ScalarField,
    ) -> Result<PedersenCommitmentProof<G>, ProofSystemError> {
        if self.commitment_to_randomness.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                self.id,
            ));
        }
        let commitment = self.commitment_to_randomness.take().unwrap();
        let responses = commitment.response(self.witnesses.as_ref().unwrap(), challenge)?;
        Ok(PedersenCommitmentProof::new(commitment.t, responses))
    }

    pub fn verify_proof_contribution<E: PairingEngine>(
        &self,
        challenge: &G::ScalarField,
        proof: &StatementProof<E, G>,
    ) -> Result<(), ProofSystemError> {
        match proof {
            StatementProof::PedersenCommitment(p) => {
                self.verify_proof_contribution_as_struct(challenge, p)
            }
            _ => Err(ProofSystemError::ProofIncompatibleWithSchnorrProtocol),
        }
    }

    pub fn verify_proof_contribution_as_struct(
        &self,
        challenge: &G::ScalarField,
        proof: &PedersenCommitmentProof<G>,
    ) -> Result<(), ProofSystemError> {
        proof
            .response
            .is_valid(self.commitment_key, &self.commitment, &proof.t, challenge)
            .map_err(|e| e.into())
    }

    pub fn compute_challenge_contribution<W: Write>(
        bases: &[G],
        y: &G,
        t: &G,
        mut writer: W,
    ) -> Result<(), ProofSystemError> {
        bases.serialize_unchecked(&mut writer)?;
        y.serialize_unchecked(&mut writer)?;
        t.serialize_unchecked(writer)?;
        Ok(())
    }
}

impl<'a, G: AffineCurve> Zeroize for SchnorrProtocol<'a, G> {
    fn zeroize(&mut self) {
        self.commitment_to_randomness.as_mut().map(|c| c.zeroize());
        self.witnesses
            .as_mut()
            .map(|w| w.iter_mut().for_each(|v| v.zeroize()));
    }
}

impl<'a, G: AffineCurve> Drop for SchnorrProtocol<'a, G> {
    fn drop(&mut self) {
        self.zeroize();
    }
}
