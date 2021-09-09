use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;
use ark_std::collections::{BTreeMap, BTreeSet};
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use bbs_plus::proof::PoKOfSignatureG1Protocol;
use bbs_plus::setup::{KeypairG2, SignatureParamsG1};
use bbs_plus::signature::SignatureG1;
use benches::setup_bbs_plus;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

type Fr = <Bls12_381 as PairingEngine>::Fr;

fn pok_sig_benchmark(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0u64);
    setup_bbs_plus!(
        SignatureParamsG1,
        KeypairG2,
        rng,
        message_count_range,
        messages_range,
        params_range,
        keypair_range
    );

    let sigs_range = (0..message_count_range.len())
        .map(|i| {
            SignatureG1::<Bls12_381>::new(
                &mut rng,
                &messages_range[i],
                &keypair_range[i].secret_key,
                &params_range[i],
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    let mut revealed_indices_range = vec![];
    let mut revealed_msgs_range = vec![];

    for (i, count) in message_count_range.iter().enumerate() {
        let messages = &messages_range[i];

        let mut k = BTreeSet::new();
        k.insert(0);
        if *count > 1 {
            k.insert(1);
        }
        if *count > *count / 4 {
            k.insert(*count / 4);
        }
        if *count > *count / 2 {
            k.insert(*count / 2);
        }
        if *count > *count - 1 {
            k.insert(*count - 1);
        }

        let mut revealed_indices = vec![];
        let mut revealed_messages = vec![];

        for j in k.iter() {
            let mut ids = BTreeSet::new();
            let mut msgs = BTreeMap::new();
            for l in 0..=*j {
                ids.insert(l);
                msgs.insert(l, messages[l]);
            }
            revealed_indices.push(ids);
            revealed_messages.push(msgs);
        }

        let params = &params_range[i];
        let sig = &sigs_range[i];

        let mut prove_group = c.benchmark_group(format!("Creating proof for Proof-of-knowledge of signature and corresponding multi-message of size {}", count));
        for (j, r_count) in k.iter().enumerate() {
            prove_group.bench_with_input(
                BenchmarkId::from_parameter(format!("Revealing {} messages", r_count)),
                &r_count,
                |b, &_i| {
                    b.iter(|| {
                        let pok = PoKOfSignatureG1Protocol::init(
                            &mut rng,
                            black_box(&sig),
                            black_box(&params),
                            black_box(messages),
                            black_box(BTreeMap::new()),
                            black_box(revealed_indices[j].clone()),
                        )
                        .unwrap();
                        let challenge = Fr::rand(&mut rng);
                        pok.gen_proof(&challenge).unwrap();
                    });
                },
            );
        }
        prove_group.finish();

        revealed_indices_range.push(revealed_indices);
        revealed_msgs_range.push(revealed_messages);
    }

    let mut challenges_range = vec![];
    let mut proofs_range = vec![];

    for i in 0..message_count_range.len() {
        let messages = &messages_range[i];
        let params = &params_range[i];
        let sig = &sigs_range[i];

        let mut challenges = vec![];
        let mut proofs = vec![];

        for j in 0..revealed_indices_range[i].len() {
            let pok = PoKOfSignatureG1Protocol::init(
                &mut rng,
                &sig,
                &params,
                messages,
                BTreeMap::new(),
                revealed_indices_range[i][j].clone(),
            )
            .unwrap();

            // Not benchmarking challenge contribution as that is just serialization
            let challenge = Fr::rand(&mut rng);

            let proof = pok.gen_proof(&challenge).unwrap();
            challenges.push(challenge);
            proofs.push(proof);
        }

        challenges_range.push(challenges);
        proofs_range.push(proofs);
    }

    for (i, count) in message_count_range.iter().enumerate() {
        let params = &params_range[i];
        let keypair = &keypair_range[i];

        let mut verify_group = c.benchmark_group(format!("Verifying proof for Proof-of-knowledge of signature and corresponding multi-message of size {}", count));
        for j in 0..revealed_indices_range[i].len() {
            verify_group.bench_with_input(
                BenchmarkId::from_parameter(format!(
                    "Revealing {} messages",
                    revealed_indices_range[i][j].len()
                )),
                &j,
                |b, &_i| {
                    b.iter(|| {
                        proofs_range[i][j]
                            .verify(
                                black_box(&revealed_msgs_range[i][j]),
                                black_box(&challenges_range[i][j]),
                                black_box(&keypair.public_key),
                                black_box(&params),
                            )
                            .unwrap();
                    });
                },
            );
        }
        verify_group.finish();
    }
}

criterion_group!(benches, pok_sig_benchmark);
criterion_main!(benches);
