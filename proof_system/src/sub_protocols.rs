use crate::error::ProofSystemError;
use crate::proof::StatementProof;
use crate::statement::{AccumulatorMembership, AccumulatorNonMembership, PoKBBSSignatureG1};
use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::borrow::Borrow;
use ark_std::collections::{BTreeMap, BTreeSet};
use ark_std::{
    fmt::Debug,
    format,
    io::{Read, Write},
    rand::RngCore,
    vec::Vec,
};

use bbs_plus::proof::PoKOfSignatureG1Protocol;
use vb_accumulator::proofs::{MembershipProofProtocol, NonMembershipProofProtocol};

/// Various sub-protocols that are executed to create a `StatementProof` which are then combined to
/// form a `Proof`
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubProtocol<E: PairingEngine> {
    PoKBBSSignatureG1(PoKBBSSigG1SubProtocol<E>),
    AccumulatorMembership(AccumulatorMembershipSubProtocol<E>),
    AccumulatorNonMembership(AccumulatorNonMembershipSubProtocol<E>),
}

pub trait ProofSubProtocol<E: PairingEngine> {
    fn challenge_contribution(&self, target: &mut [u8]) -> Result<(), ProofSystemError>;
    fn gen_proof_contribution(
        &mut self,
        challenge: &E::Fr,
    ) -> Result<StatementProof<E>, ProofSystemError>;
    fn verify_proof_contribution(
        &self,
        challenge: &E::Fr,
        proof: &StatementProof<E>,
    ) -> Result<(), ProofSystemError>;
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoKBBSSigG1SubProtocol<E: PairingEngine> {
    pub id: usize,
    pub statement: PoKBBSSignatureG1<E>,
    pub protocol: Option<PoKOfSignatureG1Protocol<E>>,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct AccumulatorMembershipSubProtocol<E: PairingEngine> {
    pub id: usize,
    pub statement: AccumulatorMembership<E>,
    pub protocol: Option<MembershipProofProtocol<E>>,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct AccumulatorNonMembershipSubProtocol<E: PairingEngine> {
    pub id: usize,
    pub statement: AccumulatorNonMembership<E>,
    pub protocol: Option<NonMembershipProofProtocol<E>>,
}

impl<E: PairingEngine> PoKBBSSigG1SubProtocol<E> {
    pub fn new(id: usize, statement: PoKBBSSignatureG1<E>) -> Self {
        Self {
            id,
            statement,
            protocol: None,
        }
    }

    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        blindings: BTreeMap<usize, E::Fr>,
        mut witness: crate::witness::PoKBBSSignatureG1<E>,
    ) -> Result<(), ProofSystemError> {
        // Create messages from revealed messages in statement and unrevealed in witness
        let mut messages = Vec::with_capacity(self.statement.params.max_message_count());
        let mut revealed_indices = BTreeSet::new();
        for i in 0..self.statement.params.max_message_count() {
            if witness.unrevealed_messages.contains_key(&i) {
                messages.push(witness.unrevealed_messages.remove(&i).unwrap());
            } else if self.statement.revealed_messages.contains_key(&i) {
                revealed_indices.insert(i);
                messages.push(self.statement.revealed_messages.get(&i).unwrap().clone());
            } else {
                return Err(ProofSystemError::BBSPlusProtocolMessageAbsent(self.id, i));
            }
        }
        let protocol = PoKOfSignatureG1Protocol::init(
            rng,
            &witness.signature,
            &self.statement.params,
            &messages,
            blindings,
            revealed_indices,
        )?;
        self.protocol = Some(protocol);
        Ok(())
    }

    fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                self.id,
            ));
        }
        self.protocol
            .borrow()
            .as_ref()
            .unwrap()
            .challenge_contribution(
                &self.statement.revealed_messages,
                &self.statement.params,
                writer,
            )?;
        Ok(())
    }

    fn gen_proof_contribution(
        &mut self,
        challenge: &E::Fr,
    ) -> Result<StatementProof<E>, ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                format!("{:?}", self.statement),
            ));
        }
        let protocol = self.protocol.take().unwrap();
        let proof = protocol.gen_proof(&challenge)?;
        Ok(StatementProof::PoKBBSSignatureG1(proof))
    }

    pub fn verify_proof_contribution(
        &self,
        challenge: &E::Fr,
        proof: &StatementProof<E>,
    ) -> Result<(), ProofSystemError> {
        match proof {
            StatementProof::PoKBBSSignatureG1(p) => {
                let r = p.verify(
                    &self.statement.revealed_messages,
                    challenge,
                    &self.statement.public_key,
                    &self.statement.params,
                )?;
                Ok(r)
            }
            _ => Err(ProofSystemError::ProofIncompatibleWithProtocol(format!(
                "{:?}",
                self.statement
            ))),
        }
    }
}

impl<E: PairingEngine> AccumulatorMembershipSubProtocol<E> {
    pub fn new(id: usize, statement: AccumulatorMembership<E>) -> Self {
        Self {
            id,
            statement,
            protocol: None,
        }
    }

    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        blinding: Option<E::Fr>,
        witness: crate::witness::Membership<E>,
    ) -> Result<(), ProofSystemError> {
        if self.protocol.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let protocol = MembershipProofProtocol::init(
            rng,
            &witness.element,
            blinding,
            &witness.witness,
            &self.statement.public_key,
            &self.statement.params,
            &self.statement.proving_key,
        );
        self.protocol = Some(protocol);
        Ok(())
    }

    fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                self.id,
            ));
        }
        self.protocol
            .borrow()
            .as_ref()
            .unwrap()
            .challenge_contribution(
                &self.statement.accumulator_value,
                &self.statement.public_key,
                &self.statement.params,
                &self.statement.proving_key,
                writer,
            )?;
        Ok(())
    }

    fn gen_proof_contribution(
        &mut self,
        challenge: &E::Fr,
    ) -> Result<StatementProof<E>, ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                format!("{:?}", self.statement),
            ));
        }
        let protocol = self.protocol.take().unwrap();
        let proof = protocol.gen_proof(&challenge);
        Ok(StatementProof::AccumulatorMembership(proof))
    }

    pub fn verify_proof_contribution(
        &self,
        challenge: &E::Fr,
        proof: &StatementProof<E>,
    ) -> Result<(), ProofSystemError> {
        match proof {
            StatementProof::AccumulatorMembership(p) => {
                let r = p.verify(
                    &self.statement.accumulator_value,
                    challenge,
                    &self.statement.public_key,
                    &self.statement.params,
                    &self.statement.proving_key,
                )?;
                Ok(r)
            }
            _ => Err(ProofSystemError::ProofIncompatibleWithProtocol(format!(
                "{:?}",
                self.statement
            ))),
        }
    }
}

impl<E: PairingEngine> AccumulatorNonMembershipSubProtocol<E> {
    pub fn new(id: usize, statement: AccumulatorNonMembership<E>) -> Self {
        Self {
            id,
            statement,
            protocol: None,
        }
    }

    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        blinding: Option<E::Fr>,
        witness: crate::witness::NonMembership<E>,
    ) -> Result<(), ProofSystemError> {
        if self.protocol.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let protocol = NonMembershipProofProtocol::init(
            rng,
            &witness.element,
            blinding,
            &witness.witness,
            &self.statement.public_key,
            &self.statement.params,
            &self.statement.proving_key,
        );
        self.protocol = Some(protocol);
        Ok(())
    }

    fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                self.id,
            ));
        }
        self.protocol
            .borrow()
            .as_ref()
            .unwrap()
            .challenge_contribution(
                &self.statement.accumulator_value,
                &self.statement.public_key,
                &self.statement.params,
                &self.statement.proving_key,
                writer,
            )?;
        Ok(())
    }

    fn gen_proof_contribution(
        &mut self,
        challenge: &E::Fr,
    ) -> Result<StatementProof<E>, ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                format!("{:?}", self.statement),
            ));
        }
        let protocol = self.protocol.take().unwrap();
        let proof = protocol.gen_proof(&challenge);
        Ok(StatementProof::AccumulatorNonMembership(proof))
    }

    pub fn verify_proof_contribution(
        &self,
        challenge: &E::Fr,
        proof: &StatementProof<E>,
    ) -> Result<(), ProofSystemError> {
        match proof {
            StatementProof::AccumulatorNonMembership(p) => {
                let r = p.verify(
                    &self.statement.accumulator_value,
                    challenge,
                    &self.statement.public_key,
                    &self.statement.params,
                    &self.statement.proving_key,
                )?;
                Ok(r)
            }
            _ => Err(ProofSystemError::ProofIncompatibleWithProtocol(format!(
                "{:?}",
                self.statement
            ))),
        }
    }
}

impl<E: PairingEngine> SubProtocol<E> {
    pub fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), ProofSystemError> {
        match self {
            SubProtocol::PoKBBSSignatureG1(s) => s.challenge_contribution(writer),
            SubProtocol::AccumulatorMembership(s) => s.challenge_contribution(writer),
            SubProtocol::AccumulatorNonMembership(s) => s.challenge_contribution(writer),
        }
    }

    pub fn gen_proof_contribution(
        &mut self,
        challenge: &E::Fr,
    ) -> Result<StatementProof<E>, ProofSystemError> {
        match self {
            SubProtocol::PoKBBSSignatureG1(s) => s.gen_proof_contribution(challenge),
            SubProtocol::AccumulatorMembership(s) => s.gen_proof_contribution(challenge),
            SubProtocol::AccumulatorNonMembership(s) => s.gen_proof_contribution(challenge),
        }
    }

    pub fn verify_proof_contribution(
        &self,
        challenge: &E::Fr,
        proof: &StatementProof<E>,
    ) -> Result<(), ProofSystemError> {
        match self {
            SubProtocol::PoKBBSSignatureG1(s) => s.verify_proof_contribution(challenge, proof),
            SubProtocol::AccumulatorMembership(s) => s.verify_proof_contribution(challenge, proof),
            SubProtocol::AccumulatorNonMembership(s) => {
                s.verify_proof_contribution(challenge, proof)
            }
        }
    }
}
