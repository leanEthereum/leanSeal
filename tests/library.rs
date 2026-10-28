// Regression coverage corresponding to tests/test.c, plus normative JSON vectors.
use leanseal::{
    backend::{Backend, Tail},
    hash::*,
    rng::TestRng,
    runtime::{hex, unhex},
    *,
};
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
fn build(n: u32, m: u64, b: u8) -> leanseal::Result<(Puzzle, [u8; 32])> {
    let mut rng = TestRng::new(b"leanseal unit tests");
    let mut salt = [0; 16];
    let mut x = vec![0; n as usize * b as usize];
    rng.fill(&mut salt);
    rng.fill(&mut x);
    let (p, k, _) = generate_from(n, m, b, salt, &x, &GenOptions::default())?;
    Ok((p, k))
}
#[test]
fn sha256_vectors_and_splits() -> TestResult {
    for (msg, want) in [
        (
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            "abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ] {
        assert_eq!(hex(&sha256(msg.as_bytes())), want);
    }
    let mut h = Sha256::new();
    for _ in 0..1000 {
        h.update(&[b'a'; 1000]);
    }
    assert_eq!(
        hex(&h.finish()),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
    let mut rng = TestRng::new(b"splits");
    let mut msg = [0; 200];
    rng.fill(&mut msg);
    for len in (0..=200).step_by(7) {
        for cut in (0..=len).step_by(3) {
            let mut h = Sha256::new();
            h.update(&msg[..cut]);
            h.update(&msg[cut..len]);
            assert_eq!(h.finish(), sha256(&msg[..len]));
        }
    }
    Ok(())
}
#[test]
fn hmac_rfc4231_and_labelled_hash() -> TestResult {
    for (key,msg,want) in [
        (vec![0x0b;20],b"Hi There".to_vec(),"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        (b"Jefe".to_vec(),b"what do ya want for nothing?".to_vec(),"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        (vec![0xaa;20],vec![0xdd;50],"773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
        (vec![0xaa;131],b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
        (vec![0xaa;131],b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".to_vec(),"9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
    ] {assert_eq!(hex(&hmac(&key,&msg)),want);}
    let label = "leanseal/v1/key";
    let a = [1, 2, 3, 4, 5];
    let b = [9, 8, 7];
    let mut input = vec![label.len() as u8];
    input.extend_from_slice(label.as_bytes());
    input.extend(a);
    input.extend(b);
    assert_eq!(labelled_hash(label, &[&a, &[], &b])?, sha256(&input));
    assert_eq!(labelled_hash(&"x".repeat(256), &[]), Err(Error::Range));
    Ok(())
}
#[test]
fn random_backend_agreement() -> TestResult {
    let all = Backend::available();
    assert_eq!(all.last(), Some(&Backend::PORTABLE));
    let mut rng = TestRng::new(b"random backend comparisons");
    for be in all {
        for lanes in 1..=4 {
            for steps in [0, 1, 2, 3, 17, 100, 257] {
                let mut states = Vec::new();
                let mut tails = Vec::new();
                let mut want = Vec::new();
                for _ in 0..lanes {
                    let mut salt = [0; 16];
                    let mut s = [0; 32];
                    let mut index = [0; 4];
                    rng.fill(&mut salt);
                    rng.fill(&mut s);
                    rng.fill(&mut index);
                    states.push(bytes_to_words(s));
                    tails.push(Tail::new(&salt, u32::from_ne_bytes(index)));
                    let mut input = [0; 52];
                    input[..32].copy_from_slice(&s);
                    input[32..48].copy_from_slice(&salt);
                    input[48..].copy_from_slice(&u32::from_ne_bytes(index).to_be_bytes());
                    for _ in 0..steps {
                        let h = sha256(&input);
                        input[..32].copy_from_slice(&h);
                    }
                    want.push(bytes_to_words(input[..32].try_into()?));
                }
                let mut portable = states.clone();
                Backend::PORTABLE.run_lanes(&mut portable, &tails, steps);
                assert_eq!(portable, want);
                let mut one = states.clone();
                for (s, t) in one.iter_mut().zip(&tails) {
                    be.run(s, t, steps);
                }
                assert_eq!(one, want, "{}", be.name());
                be.run_lanes(&mut states, &tails, steps);
                assert_eq!(states, want, "{} lanes={lanes} steps={steps}", be.name());
            }
        }
    }
    Ok(())
}
#[test]
fn round_trip_grid() -> TestResult {
    let mut rng = TestRng::new(b"round trips");
    let mut msg = [0; 1000];
    rng.fill(&mut msg);
    let lens = [0, 1, 31, 32, 33, 1000];
    let mut cases = 0;
    for (a, n) in [1, 2, 3, 7, 16].into_iter().enumerate() {
        for (c, m) in [1, 2, 10, 257].into_iter().enumerate() {
            for (d, b) in [1, 8, 12, 32].into_iter().enumerate() {
                let len = lens[(a + c + d) % 6];
                let (p, key) = build(n, m, b)?;
                let mut nonce = [0; 16];
                rng.fill(&mut nonce);
                let data = seal(&p, &key, &nonce, &msg[..len])?;
                assert_eq!(data.len(), 128 + n as usize * b as usize + len);
                let e = Envelope::decode(&data)?;
                for backend in Backend::available() {
                    let mut cur = e.puzzle.cursor();
                    assert_eq!(e.puzzle.solve(&mut cur, backend, 3, |_| false)?, key);
                }
                assert_eq!(e.open(&key)?, &msg[..len]);
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 80);
    Ok(())
}
#[test]
fn generation_in_several_blocks_matches_solving() -> TestResult {
    // Generation runs each chain in blocks of 2^22 steps; solving runs it in one call.
    let (p, key) = build(2, (1 << 22) + 3, 24)?;
    let mut cur = p.cursor();
    assert_eq!(p.solve(&mut cur, Backend::best()?, 0, |_| false)?, key);
    Ok(())
}
#[test]
fn threaded_determinism_and_masks() -> TestResult {
    let mut rng = TestRng::new(b"determinism");
    let mut salt = [0; 16];
    let mut x = [0; 480];
    rng.fill(&mut salt);
    rng.fill(&mut x);
    let (reference, key, ends) = generate_from(
        40,
        33,
        12,
        salt,
        &x,
        &GenOptions {
            threads: 1,
            backend: Some(Backend::PORTABLE),
            progress: None,
        },
    )?;
    let enc = reference.encode()?;
    for backend in Backend::available() {
        for threads in [1, 2, 3, 7, 64, 0] {
            let progress = std::cell::Cell::new(0);
            let cb = |done, total| {
                assert!(done <= total);
                progress.set(done);
            };
            let (p, k, y) = generate_from(
                40,
                33,
                12,
                salt,
                &x,
                &GenOptions {
                    threads,
                    backend: Some(backend),
                    progress: Some(&cb),
                },
            )?;
            assert_eq!(p.encode()?, enc);
            assert_eq!(k, key);
            assert_eq!(y, ends);
            assert_eq!(progress.get(), 40 * 33);
        }
    }
    assert_eq!(&reference.links()[..12], &x[..12]);
    for i in 1..40 {
        let mask = labelled_hash("leanseal/v1/mask", &[&reference.context(), &ends[i - 1]])?;
        for j in 0..12 {
            assert_eq!(reference.links()[i * 12 + j], mask[j] ^ x[i * 12 + j]);
        }
    }
    Ok(())
}
#[test]
fn failures_and_parameter_bounds() -> TestResult {
    let (p, key) = build(3, 20, 12)?;
    let data = seal(&p, &key, &[0; 16], &[4; 50])?;
    let e = Envelope::decode(&data)?;
    let mut bad = key;
    bad[31] ^= 1;
    assert_eq!(e.open(&bad), Err(Error::Commit));
    assert_eq!(seal(&p, &bad, &[0; 16], b"x"), Err(Error::Commit));
    assert_eq!(
        seal(&p, &key, &[0; 16], &vec![0; MAX_MSG + 1]),
        Err(Error::Range)
    );
    let mut data = data;
    let end = data.len() - 1;
    data[end] ^= 1;
    assert_eq!(Envelope::decode(&data)?.open(&key), Err(Error::Tag));
    let mut malformed = p.encode()?;
    malformed[68 + 12 + 3] ^= 0x40;
    let malformed = Puzzle::decode(&malformed)?;
    assert_eq!(
        malformed.solve(&mut malformed.cursor(), Backend::best()?, 0, |_| false),
        Err(Error::Puzzle)
    );
    for (n, m, b) in [
        (0, 1, 12),
        (MAX_N + 1, 1, 12),
        (1, 0, 12),
        (1, MAX_M + 1, 12),
        (1, 1, 0),
        (1, 1, 33),
        (MAX_N, MAX_WORK / u64::from(MAX_N) + 1, 12),
    ] {
        assert!(!params_ok(n, m, b));
        assert!(matches!(
            generate(n, m, b, &GenOptions::default()),
            Err(Error::Range)
        ));
    }
    assert!(params_ok(MAX_N, MAX_WORK / u64::from(MAX_N), 32));
    assert!(params_ok(1, MAX_M, 1));
    assert!(params_ok(1, 1, 1));
    Ok(())
}
#[test]
fn checkpoint_stop_resume_and_finished_states() -> TestResult {
    let (p, key) = build(4, 1000, 12)?;
    let (other, _) = build(4, 999, 12)?;
    let be = Backend::best()?;
    for (i, j) in [(1, 1), (1, 500), (2, 1000), (3, 7), (4, 999), (4, 1000)] {
        let mut cur = p.cursor();
        assert_eq!(
            p.solve(&mut cur, be, 7, |c| c.i == i && c.j >= j),
            Err(Error::Stopped)
        );
        assert_eq!(cur.i, i);
        let enc = cur.encode(&p)?;
        let mut back = Cursor::decode(&p, &enc)?;
        assert_eq!(back, cur);
        assert_eq!(Cursor::decode(&other, &enc), Err(Error::Mismatch));
        assert_eq!(Cursor::decode(&p, &enc[..115]), Err(Error::Format));
        assert_eq!(p.solve(&mut back, be, 0, |_| false)?, key);
    }
    for n in 1..=3 {
        let (q, k) = build(n, 5, 12)?;
        let mut cur = q.cursor();
        assert_eq!(q.solve(&mut cur, be, 0, |_| false)?, k);
        assert_eq!((cur.i, cur.j), (n, 5));
        assert_eq!(q.solve(&mut cur, be, 0, |_| false)?, k);
        let mut back = Cursor::decode(&q, &cur.encode(&q)?)?;
        assert_eq!(q.solve(&mut back, be, 0, |_| false)?, k);
    }
    let mut cur = p.cursor();
    assert_eq!(
        p.solve(&mut cur, be, 7, |c| c.i == 3 && c.j >= 7),
        Err(Error::Stopped)
    );
    let mut enc = cur.encode(&p)?;
    enc[115] ^= 1;
    let mut back = Cursor::decode(&p, &enc)?;
    assert_eq!(p.solve(&mut back, be, 0, |_| false), Err(Error::Puzzle));
    let seed = p.cursor().encode(&p)?;
    for (i, j) in [(5, 0), (1, 1001), (0, 0), (4097, MAX_M)] {
        let mut enc = seed.clone();
        enc[40..44].copy_from_slice(&(i as u32).to_be_bytes());
        enc[44..52].copy_from_slice(&j.to_be_bytes());
        assert_eq!(Cursor::decode(&p, &enc), Err(Error::Range));
    }
    let mut enc = seed.clone();
    enc[40..44].copy_from_slice(&4096u32.to_be_bytes());
    enc[44..52].copy_from_slice(&MAX_M.to_be_bytes());
    let (_, i, j) = checkpoint_peek(&enc)?;
    assert_eq!((i, j), (4096, MAX_M));
    for offset in [4, 5, 6, 7] {
        let mut enc = seed.clone();
        enc[offset] = 2;
        assert_eq!(checkpoint_peek(&enc), Err(Error::Format));
    }
    let (id, i, j) = checkpoint_peek(&seed)?;
    assert_eq!((id, i, j), (p.id(), 1, 0));
    let secret = secret_encode(&p, &key)?;
    assert_eq!(secret_decode(&secret)?, (p.clone(), key));
    let mut bad = secret;
    bad[8] ^= 1;
    assert_eq!(secret_decode(&bad), Err(Error::Commit));
    let mut wrong = key;
    wrong[0] ^= 1;
    assert_eq!(secret_encode(&p, &wrong), Err(Error::Commit));
    Ok(())
}
#[test]
fn guessing_requires_all_ends() -> TestResult {
    let be = Backend::best()?;
    let salt = [3; 16];
    let x = [47, 28, 91];
    let (p, key, ends) = generate_from(3, 10, 1, salt, &x, &GenOptions::default())?;
    for i in 1..=3 {
        assert_eq!(
            p.run_chain(i, &x[i as usize - 1..i as usize], be)?,
            ends[i as usize - 1]
        );
    }
    assert_eq!(p.key_from_ends(&ends)?, key);
    let mut winners = Vec::new();
    for guess in 0..=255 {
        let mut y = ends.clone();
        y[2] = p.run_chain(3, &[guess], be)?;
        if p.key_from_ends(&y).is_ok() {
            winners.push(guess);
        }
        let mut wrong = vec![[0; 32]; 3];
        wrong[2] = y[2];
        assert!(p.key_from_ends(&wrong).is_err());
    }
    assert_eq!(winners, vec![x[2]]);
    for i in 0..3 {
        let mut y = ends.clone();
        y[i][31] ^= 1;
        assert!(p.key_from_ends(&y).is_err());
    }
    let x = [71; 64];
    let (p, key, ends) = generate_from(2, 5, 32, salt, &x, &GenOptions::default())?;
    let mut y = ends.clone();
    for (v, (z, x)) in y[0].iter_mut().zip(p.links()[32..].iter().zip(&x[32..])) {
        *v = z ^ x;
    }
    assert!(p.key_from_ends(&y).is_err());
    y[0] = ends[0];
    assert_eq!(p.key_from_ends(&y)?, key);
    Ok(())
}
fn decode_hex(s: &str) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
    if s.len() % 2 != 0 {
        return Err("odd hex".into());
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|b| Ok(unhex::<1>(std::str::from_utf8(b)?)?[0]))
        .collect()
}
fn vstr<'a>(
    v: &'a serde_json::Value,
    k: &str,
) -> std::result::Result<&'a str, Box<dyn std::error::Error>> {
    v[k].as_str()
        .ok_or_else(|| format!("missing string {k}").into())
}
#[test]
fn normative_vectors_all_fields_and_invalid_cases() -> TestResult {
    let raw = include_str!("vectors.json");
    assert_eq!(vectors::generate_vectors()?, raw);
    let v: serde_json::Value = serde_json::from_str(raw)?;
    let cases = v["cases"].as_array().ok_or("cases")?;
    let mut puzzles = Vec::new();
    let mut keys = Vec::new();
    for c in cases {
        let p = Puzzle::decode(&decode_hex(vstr(c, "puzzle")?)?)?;
        let key = unhex(vstr(c, "key")?)?;
        assert_eq!(p.encode()?, decode_hex(vstr(c, "puzzle")?)?);
        assert_eq!(hex(&p.id()), vstr(c, "puzzle_id")?);
        let secret = decode_hex(vstr(c, "secret")?)?;
        assert_eq!(secret_decode(&secret)?, (p.clone(), key));
        let env = decode_hex(vstr(c, "envelope")?)?;
        assert_eq!(
            Envelope::decode(&env)?.open(&key)?,
            decode_hex(vstr(c, "message")?)?
        );
        let checkpoint = decode_hex(vstr(&c["checkpoint"], "hex")?)?;
        let mut cur = Cursor::decode(&p, &checkpoint)?;
        assert_eq!(cur.encode(&p)?, checkpoint);
        assert_eq!(p.solve(&mut cur, Backend::best()?, 0, |_| false)?, key);
        puzzles.push(p);
        keys.push(key);
    }
    for invalid in v["invalid"].as_array().ok_or("invalids")? {
        let i = invalid["case"].as_u64().ok_or("case index")? as usize;
        let d = decode_hex(vstr(invalid, "hex")?)?;
        let rejects = match vstr(invalid, "kind")? {
            "puzzle" => Puzzle::decode(&d).is_err(),
            "secret" => secret_decode(&d).is_err(),
            "envelope" => Envelope::decode(&d).and_then(|e| e.open(&keys[i])).is_err(),
            "checkpoint" => Cursor::decode(&puzzles[i], &d).is_err(),
            _ => false,
        };
        assert!(rejects, "{}", vstr(invalid, "why")?);
    }
    Ok(())
}
#[test]
fn decoder_truncation_extension_mutation_and_garbage() -> TestResult {
    let (p, key) = build(3, 20, 12)?;
    let env = seal(&p, &key, &[0; 16], &[5; 40])?;
    let mut cur = p.cursor();
    assert_eq!(
        p.solve(&mut cur, Backend::best()?, 1, |c| c.i == 2 && c.j == 7),
        Err(Error::Stopped)
    );
    let seeds = [p.encode()?, secret_encode(&p, &key)?, cur.encode(&p)?];
    fn canonical(kind: usize, p: &Puzzle, d: &[u8]) -> leanseal::Result<Vec<u8>> {
        match kind {
            0 => Puzzle::decode(d)?.encode(),
            1 => {
                let (p, k) = secret_decode(d)?;
                secret_encode(&p, &k)
            }
            _ => Cursor::decode(p, d)?.encode(p),
        }
    }
    let mut rng = TestRng::new(b"decoder mutations");
    fn rnd(r: &mut TestRng, n: usize) -> usize {
        let mut b = [0; 4];
        r.fill(&mut b);
        u32::from_le_bytes(b) as usize % n
    }
    for (kind, seed) in seeds.iter().enumerate() {
        assert_eq!(canonical(kind, &p, seed)?, *seed);
        for len in 0..seed.len() {
            assert!(canonical(kind, &p, &seed[..len]).is_err());
        }
        let mut extended = seed.clone();
        extended.push(0);
        assert!(canonical(kind, &p, &extended).is_err());
        let mut accepted = 0;
        for _ in 0..5000 {
            let mut data = seed.clone();
            for _ in 0..1 + rnd(&mut rng, 3) {
                let off = rnd(&mut rng, data.len());
                data[off] ^= (1 + rnd(&mut rng, 255)) as u8;
            }
            if let Ok(enc) = canonical(kind, &p, &data) {
                assert_eq!(enc, data);
                accepted += 1;
            }
        }
        assert!(accepted > 0 && accepted < 5000);
    }
    let mut decoded = 0;
    for _ in 0..20000 {
        let mut d = env.clone();
        for _ in 0..1 + rnd(&mut rng, 3) {
            match rnd(&mut rng, 4) {
                0 => {
                    let off = rnd(&mut rng, d.len());
                    d[off] ^= 1 << rnd(&mut rng, 8);
                }
                1 => {
                    let off = rnd(&mut rng, d.len());
                    d[off] = rnd(&mut rng, 256) as u8;
                }
                2 => {
                    let n = rnd(&mut rng, d.len() + 1);
                    d.truncate(n);
                }
                _ => d.push(rnd(&mut rng, 256) as u8),
            }
            if d.is_empty() {
                break;
            }
        }
        if d == env {
            continue;
        }
        let _ = Puzzle::decode(&d);
        let _ = secret_decode(&d);
        let _ = Cursor::decode(&p, &d);
        if let Ok(e) = Envelope::decode(&d) {
            decoded += 1;
            assert!(e.open(&key).is_err());
        }
    }
    assert!(decoded > 0);
    for _ in 0..20000 {
        let mut d = vec![0; rnd(&mut rng, 300)];
        rng.fill(&mut d);
        if d.len() >= 5 {
            d[..4].copy_from_slice([b"LSPZ", b"LSEN", b"LSSK", b"LSCK"][rnd(&mut rng, 4)]);
            d[4] = 1;
        }
        if d.len() >= 8 && rnd(&mut rng, 2) == 1 {
            d[5] = rnd(&mut rng, 33) as u8;
            d[6] = 0;
            d[7] = 0;
        }
        let _ = Puzzle::decode(&d);
        let _ = secret_decode(&d);
        let _ = Cursor::decode(&p, &d);
        if let Ok(e) = Envelope::decode(&d) {
            assert!(e.open(&key).is_err());
        }
    }
    Ok(())
}
