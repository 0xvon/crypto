use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use rand_core::OsRng;
use k256::ecdsa::{SigningKey, Signature, signature::Signer, VerifyingKey, signature::Verifier};
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};

// 署名のベンチマークを実行する関数
fn sign_benchmark(c: &mut Criterion) {
    let message_range = [20, 40];
    let signing_key = SigningKey::random(&mut OsRng);
    let verify_key = VerifyingKey::from(&signing_key);
    let messages = message_range
        .iter()
        .map(|c| {
            let mut _hasher = Blake2bVar::new(*c).unwrap();
            _hasher.update(b"test");
            let mut buf = vec![0u8; *c];
            _hasher.finalize_variable(&mut buf).unwrap();
            return buf;
        })
        .collect::<Vec<_>>();

        let mut sign_group = c.benchmark_group("ECDSA signing");
        for (i, count) in message_range.iter().enumerate() {
            sign_group.bench_with_input(BenchmarkId::from_parameter(*count), &i, |b, &i| {
                b.iter(|| {
                    let _signature: Signature = signing_key.sign(&messages[i]);
                });
            });
        }
        sign_group.finish();

        let signatures = messages
            .iter()
            .map(|message| signing_key.sign(message))
            .collect::<Vec<Signature>>();

        let mut verify_group: criterion::BenchmarkGroup<'_, criterion::measurement::WallTime> = c.benchmark_group("ECDSA verifying");
        for (i, count) in message_range.iter().enumerate() {
            verify_group.bench_with_input(BenchmarkId::from_parameter(*count), &i, |b, &i| {
                b.iter(|| {
                    assert!(verify_key.verify(&messages[i], &signatures[i]).is_ok());
                });
            });
        }
        verify_group.finish();
}

criterion_group!(benches, sign_benchmark);
criterion_main!(benches);