use ark_bls12_381::{Bls12_381, G1Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{prelude::StdRng, SeedableRng};
use bbs_plus::prelude::{KeypairG2, SignatureG1, SignatureParamsG1};
use blake2::Blake2b512;
use std::collections::{BTreeMap, BTreeSet};

use proof_system::prelude::{
    BoundCheckSmcWithKVInnerProof, EqualWitnesses, MetaStatements, ProofSpec, StatementProof,
    Statements, Witness, WitnessRef, Witnesses,
};
use test_utils::{test_serialization, Fr, ProofG1};

use proof_system::{
    prelude::{
        bound_check_smc::SmcParamsAndCommitmentKey,
        bound_check_smc_with_kv::SmcParamsAndCommitmentKeyAndSecretKey,
    },
    statement::{
        bbs_plus::PoKBBSSignatureG1 as PoKSignatureBBSG1Stmt,
        bound_check_smc_with_kv::{
            BoundCheckSmcWithKVProver as BoundCheckProverStmt,
            BoundCheckSmcWithKVVerifier as BoundCheckVerifierStmt,
        },
    },
    sub_protocols::{bound_check_smc::BoundCheckSmcProtocol, should_use_cls},
    witness::PoKBBSSignatureG1 as PoKSignatureBBSG1Wit,
};

#[test]
fn pok_of_bbs_plus_sig_and_bounded_message_using_set_membership_check_range_proof_with_keyed_verification(
) {
    // Prove knowledge of BBS+ signature and a specific message satisfies some bounds i.e. min <= message < max.
    // Here message set as min and them max
    let mut rng = StdRng::seed_from_u64(0u64);
    let msg_count = 5;

    let sig_params = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut rng, msg_count);
    let sig_keypair = KeypairG2::<Bls12_381>::generate_using_rng(&mut rng, &sig_params);

    let (smc_setup_params, sk) =
        SmcParamsAndCommitmentKey::new::<_, Blake2b512>(&mut rng, b"test", 2);
    smc_setup_params.verify().unwrap();
    let smc_setup_params_with_sk = SmcParamsAndCommitmentKeyAndSecretKey {
        params_and_comm_key: smc_setup_params.clone(),
        sk,
    };

    fn check(
        rng: &mut StdRng,
        min: u64,
        max: u64,
        msg_idx: usize,
        msg: Fr,
        msgs: Vec<Fr>,
        sig_params: SignatureParamsG1<Bls12_381>,
        sig_keypair: KeypairG2<Bls12_381>,
        sig: SignatureG1<Bls12_381>,
        smc_setup_params: SmcParamsAndCommitmentKey<Bls12_381>,
        smc_setup_params_with_sk: SmcParamsAndCommitmentKeyAndSecretKey<Bls12_381>,
        valid_proof: bool,
        is_cls: bool,
    ) {
        let mut prover_statements = Statements::new();
        prover_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
            sig_params.clone(),
            sig_keypair.public_key.clone(),
            BTreeMap::new(),
        ));
        prover_statements.add(
            BoundCheckProverStmt::new_statement_from_params(min, max, smc_setup_params.clone())
                .unwrap(),
        );

        let mut meta_statements = MetaStatements::new();
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![(0, msg_idx), (1, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        ));

        if valid_proof {
            test_serialization!(Statements<Bls12_381, G1Affine>, prover_statements);
            test_serialization!(MetaStatements, meta_statements);
        }

        let proof_spec_prover = ProofSpec::new(
            prover_statements.clone(),
            meta_statements.clone(),
            vec![],
            None,
        );
        proof_spec_prover.validate().unwrap();

        if valid_proof {
            test_serialization!(ProofSpec<Bls12_381, G1Affine>, proof_spec_prover);
        }

        let mut witnesses = Witnesses::new();
        witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
            sig.clone(),
            msgs.clone().into_iter().enumerate().collect(),
        ));
        witnesses.add(Witness::BoundCheckSmcWithKV(msg));

        if valid_proof {
            test_serialization!(Witnesses<Bls12_381>, witnesses);
        }

        let proof = ProofG1::new::<StdRng, Blake2b512>(
            rng,
            proof_spec_prover,
            witnesses.clone(),
            None,
            Default::default(),
        )
        .unwrap()
        .0;

        if valid_proof {
            test_serialization!(ProofG1, proof);
        }

        if is_cls {
            match &proof.statement_proofs[1] {
                StatementProof::BoundCheckSmcWithKV(p) => match &p.proof {
                    BoundCheckSmcWithKVInnerProof::CCS(_) => {
                        assert!(false, "expected CLS proof but found CCS")
                    }
                    BoundCheckSmcWithKVInnerProof::CLS(_) => assert!(true),
                },
                _ => assert!(
                    false,
                    "this shouldn't happen as this test is checking set membership based proof"
                ),
            }
        } else {
            match &proof.statement_proofs[1] {
                StatementProof::BoundCheckSmcWithKV(p) => match &p.proof {
                    BoundCheckSmcWithKVInnerProof::CLS(_) => {
                        assert!(false, "expected CCS proof but found CLS")
                    }
                    BoundCheckSmcWithKVInnerProof::CCS(_) => assert!(true),
                },
                _ => assert!(
                    false,
                    "this shouldn't happen as this test is checking set membership based proof"
                ),
            }
        }

        let mut verifier_statements = Statements::new();
        verifier_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
            sig_params.clone(),
            sig_keypair.public_key.clone(),
            BTreeMap::new(),
        ));
        verifier_statements.add(
            BoundCheckVerifierStmt::new_statement_from_params(
                min,
                max,
                smc_setup_params_with_sk.clone(),
            )
            .unwrap(),
        );

        let proof_spec_verifier = ProofSpec::new(
            verifier_statements.clone(),
            meta_statements.clone(),
            vec![],
            None,
        );
        proof_spec_verifier.validate().unwrap();

        let res =
            proof.verify::<StdRng, Blake2b512>(rng, proof_spec_verifier, None, Default::default());
        assert_eq!(res.is_ok(), valid_proof);
    }

    let min = 100;
    let max = 200;
    let msgs = (0..msg_count)
        .map(|i| Fr::from(min + 1 + i as u64))
        .collect::<Vec<_>>();

    let sig = SignatureG1::<Bls12_381>::new(&mut rng, &msgs, &sig_keypair.secret_key, &sig_params)
        .unwrap();
    sig.verify(&msgs, sig_keypair.public_key.clone(), sig_params.clone())
        .unwrap();

    let is_cls = should_use_cls(min, max);
    assert!(is_cls);

    // Check for message that is signed and satisfies the bounds
    check(
        &mut rng,
        min,
        max,
        1,
        msgs[1],
        msgs.clone(),
        sig_params.clone(),
        sig_keypair.clone(),
        sig.clone(),
        smc_setup_params.clone(),
        smc_setup_params_with_sk.clone(),
        true,
        is_cls,
    );

    // Check for message that satisfies the bounds but is not signed
    check(
        &mut rng,
        min,
        max,
        0,
        Fr::from(min + 10),
        msgs,
        sig_params.clone(),
        sig_keypair.clone(),
        sig,
        smc_setup_params.clone(),
        smc_setup_params_with_sk.clone(),
        false,
        is_cls,
    );

    let min = 100;
    let max = min + 2_u64.pow(21);
    let msgs = (0..msg_count)
        .map(|i| Fr::from(min + 1 + i as u64))
        .collect::<Vec<_>>();

    let sig = SignatureG1::<Bls12_381>::new(&mut rng, &msgs, &sig_keypair.secret_key, &sig_params)
        .unwrap();
    sig.verify(&msgs, sig_keypair.public_key.clone(), sig_params.clone())
        .unwrap();

    let is_cls = should_use_cls(min, max);
    assert!(!is_cls);

    // Check for message that is signed and satisfies the bounds
    check(
        &mut rng,
        min,
        max,
        1,
        msgs[1],
        msgs.clone(),
        sig_params.clone(),
        sig_keypair.clone(),
        sig.clone(),
        smc_setup_params.clone(),
        smc_setup_params_with_sk.clone(),
        true,
        is_cls,
    );

    // Check for message that satisfies the bounds but is not signed
    check(
        &mut rng,
        min,
        max,
        0,
        Fr::from(min + 10),
        msgs,
        sig_params,
        sig_keypair,
        sig,
        smc_setup_params,
        smc_setup_params_with_sk.clone(),
        false,
        is_cls,
    );
}
