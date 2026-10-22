//! Deterministic interoperability vectors, generated using the library.
use crate::{
    hash::{th, words_to_bytes},
    rng::TestRng,
    runtime::hex,
    *,
};
use std::fmt::Write;
struct Built {
    p: Puzzle,
    key: [u8; 32],
    puzzle: Vec<u8>,
    envelope: Vec<u8>,
    secret: Vec<u8>,
    ckpt: Vec<u8>,
}
fn field(s: &mut String, name: &str, data: &[u8], after: &str) {
    let _ = write!(s, "\"{name}\": \"{}\"{after}", hex(data));
}
fn list(s: &mut String, name: &str, data: &[u8], width: usize) {
    let _ = write!(s, "\"{name}\": [");
    for (i, x) in data.chunks(width).enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        let _ = write!(s, "\"{}\"", hex(x));
    }
    s.push_str("],\n      ");
}
/// Compute and serialize the canonical JSON vectors, checking invalid cases as well.
pub fn generate_vectors() -> Result<String> {
    let cases = [
        (1, 1, 1, 0),
        (1, 5, 12, 1),
        (2, 3, 12, 21),
        (3, 10, 32, 32),
        (5, 100, 12, 33),
        (8, 1000, 7, 100),
        (16, 64, 12, 64),
    ];
    let mut out = String::from("{\n  \"spec\": \"chainseal v1\",\n  \"cases\": [\n");
    let mut built = Vec::new();
    for (k, (n, m, b, ml)) in cases.into_iter().enumerate() {
        let mut rng = TestRng::new(format!("chainseal/v1 vector {k}").as_bytes());
        let mut salt = [0; 16];
        let mut x = bytes(n as usize * b as usize)?;
        let mut nonce = [0; 16];
        let mut msg = bytes(ml)?;
        rng.fill(&mut salt);
        rng.fill(&mut x);
        rng.fill(&mut nonce);
        rng.fill(&mut msg);
        let (p, key, y) = generate_from(
            n,
            m,
            b,
            salt,
            &x,
            &GenOptions {
                threads: 1,
                ..Default::default()
            },
        )?;
        let mut starts = Vec::new();
        let mut accs = Vec::new();
        let mut acc = p.context();
        for (i, end) in y.iter().enumerate() {
            starts.extend_from_slice(
                &p.chain_start((i + 1) as u32, &x[i * b as usize..(i + 1) * b as usize])?,
            );
            acc = th("chainseal/v1/acc", &[&acc, end]);
            accs.extend_from_slice(&acc);
        }
        let puzzle = p.encode()?;
        let secret = secret_encode(&p, &key)?;
        let envelope = seal(&p, &key, &nonce, &msg)?;
        let mut cur = p.cursor();
        let stop_i = n.div_ceil(2);
        let stop_j = (m / 2).max(1);
        if p.solve(&mut cur, backend::Backend::best()?, 1, |c| {
            c.i == stop_i && c.j == stop_j
        }) != Err(Error::Stopped)
        {
            return Err(Error::Puzzle);
        }
        let ckpt = cur.encode(&p)?;
        let state = words_to_bytes(cur.state);
        let ca = cur.acc;
        if p.solve(&mut cur, backend::Backend::best()?, 0, |_| false)? != key {
            return Err(Error::Puzzle);
        }
        let _ = write!(out, "    {{\"n\": {n}, \"m\": {m}, \"b\": {b},\n      ");
        field(&mut out, "salt", &salt, ",\n      ");
        list(&mut out, "x", &x, b as usize);
        list(&mut out, "start", &starts, 32);
        let flat: Vec<u8> = y.iter().flatten().copied().collect();
        list(&mut out, "y", &flat, 32);
        list(&mut out, "acc", &accs, 32);
        for (name, data) in [
            ("key", key.as_slice()),
            ("commit", p.commitment()),
            ("puzzle", &puzzle),
            ("puzzle_id", &p.id()),
            ("secret", &secret),
            ("nonce", &nonce),
            ("message", &msg),
            ("envelope", &envelope),
        ] {
            field(&mut out, name, data, ",\n      ");
        }
        let _ = write!(out, "\"checkpoint\": {{\"i\": {stop_i}, \"j\": {stop_j}, ");
        field(&mut out, "state", &state, ", ");
        field(&mut out, "acc", &ca, ", ");
        field(&mut out, "hex", &ckpt, "}}");
        out.push_str(if k < 6 { ",\n" } else { "\n" });
        built.push(Built {
            p,
            key,
            puzzle,
            envelope,
            secret,
            ckpt,
        });
    }
    out.push_str("  ],\n  \"invalid\": [\n");
    let mut invalids: Vec<(&str, usize, &str, Vec<u8>)> = Vec::new();
    let o = &built[2];
    let p = &o.puzzle;
    let e = &o.envelope;
    let s = &o.secret;
    let k = &o.ckpt;
    let pl = p.len();
    let el = e.len();
    let ct = 8 + pl + 20;
    {
        let mut v = p.clone();
        v[0] ^= 1;
        invalids.push(("puzzle", 2, "bad magic", v));
    }
    {
        let mut v = p.clone();
        v[4] = 2;
        invalids.push(("puzzle", 2, "version 2", v));
    }
    {
        let mut v = p.clone();
        v[5] = 0;
        invalids.push(("puzzle", 2, "b = 0", v));
    }
    {
        let mut v = p.clone();
        v[5] = 33;
        invalids.push(("puzzle", 2, "b = 33", v));
    }
    {
        let mut v = p.clone();
        v[6] = 1;
        invalids.push(("puzzle", 2, "reserved byte 6 set", v));
    }
    {
        let mut v = p.clone();
        v[7] = 0x80;
        invalids.push(("puzzle", 2, "reserved byte 7 set", v));
    }
    {
        let mut v = p.clone();
        set_be(&mut v, 8, 0, 4);
        invalids.push(("puzzle", 2, "n = 0", v));
    }
    {
        let mut v = p.clone();
        set_be(&mut v, 8, (1 << 20) + 1, 4);
        invalids.push(("puzzle", 2, "n = 2^20 + 1", v));
    }
    {
        let mut v = p.clone();
        set_be(&mut v, 8, 3, 4);
        invalids.push(("puzzle", 2, "n = 3, links for n = 2", v));
    }
    {
        let mut v = p.clone();
        set_be(&mut v, 12, 0, 8);
        invalids.push(("puzzle", 2, "m = 0", v));
    }
    {
        let mut v = p.clone();
        set_be(&mut v, 12, (1 << 48) + 1, 8);
        invalids.push(("puzzle", 2, "m = 2^48 + 1", v));
    }
    {
        let mut v = p.clone();
        v.resize((v.len() as isize + (-1)) as usize, 0);
        invalids.push(("puzzle", 2, "one byte short", v));
    }
    {
        let mut v = p.clone();
        v.resize((v.len() as isize + (1)) as usize, 0);
        invalids.push(("puzzle", 2, "one trailing byte", v));
    }
    {
        let mut v = p.clone();
        v.resize(68, 0);
        invalids.push(("puzzle", 2, "header only", v));
    }
    {
        let mut v = p.clone();
        v.clear();
        invalids.push(("puzzle", 2, "empty", v));
    }
    {
        let mut big = bytes(68 + 4097)?;
        big[..68].copy_from_slice(&built[0].puzzle[..68]);
        set_be(&mut big, 8, 4097, 4);
        set_be(&mut big, 12, 1 << 48, 8);
        invalids.push(("puzzle", 0, "n*m = 4097 * 2^48, above 2^60", big));
    }
    {
        let mut v = e.clone();
        v[0] ^= 1;
        invalids.push(("envelope", 2, "bad magic", v));
    }
    {
        let mut v = e.clone();
        v[4] = 2;
        invalids.push(("envelope", 2, "version 2", v));
    }
    {
        let mut v = e.clone();
        v[5] = 1;
        invalids.push(("envelope", 2, "reserved byte 5 set", v));
    }
    {
        let mut v = e.clone();
        v[7] = 1;
        invalids.push(("envelope", 2, "reserved byte 7 set", v));
    }
    {
        let mut v = e.clone();
        v[8 + 5] = 33;
        invalids.push(("envelope", 2, "inner puzzle b = 33", v));
    }
    {
        let mut v = e.clone();
        v[8] ^= 1;
        invalids.push(("envelope", 2, "inner puzzle bad magic", v));
    }
    {
        let mut v = e.clone();
        set_be(&mut v, ct - 4, 22, 4);
        invalids.push(("envelope", 2, "length field one too large", v));
    }
    {
        let mut v = e.clone();
        set_be(&mut v, ct - 4, 20, 4);
        invalids.push(("envelope", 2, "length field one too small", v));
    }
    {
        let mut v = e.clone();
        set_be(&mut v, ct - 4, (1 << 24) + 1, 4);
        invalids.push(("envelope", 2, "length 2^24 + 1", v));
    }
    {
        let mut v = e.clone();
        v.resize((v.len() as isize + (-1)) as usize, 0);
        invalids.push(("envelope", 2, "one byte short", v));
    }
    {
        let mut v = e.clone();
        v.resize((v.len() as isize + (1)) as usize, 0);
        invalids.push(("envelope", 2, "one trailing byte", v));
    }
    {
        let mut v = e.clone();
        v[el - 1] ^= 1;
        invalids.push(("envelope", 2, "tag modified", v));
    }
    {
        let mut v = e.clone();
        v[ct] ^= 1;
        invalids.push(("envelope", 2, "ciphertext modified", v));
    }
    {
        let mut v = e.clone();
        v[ct - 20] ^= 1;
        invalids.push(("envelope", 2, "nonce modified", v));
    }
    {
        let mut v = e.clone();
        v[8 + 68 + 12] ^= 1;
        invalids.push(("envelope", 2, "link z_1 modified", v));
    }
    {
        let mut v = e.clone();
        v[8 + 68] ^= 1;
        invalids.push(("envelope", 2, "link x_1 modified", v));
    }
    {
        let mut v = e.clone();
        v[8 + 36] ^= 1;
        invalids.push(("envelope", 2, "commitment modified", v));
    }
    {
        let mut v = e.clone();
        v[8 + 20] ^= 1;
        invalids.push(("envelope", 2, "salt modified", v));
    }
    {
        let mut v = e.clone();
        v[8 + 19] ^= 1;
        invalids.push(("envelope", 2, "m modified", v));
    }
    {
        let mut v = s.clone();
        v[0] ^= 1;
        invalids.push(("secret", 2, "bad magic", v));
    }
    {
        let mut v = s.clone();
        v[4] = 2;
        invalids.push(("secret", 2, "version 2", v));
    }
    {
        let mut v = s.clone();
        v[6] = 1;
        invalids.push(("secret", 2, "reserved byte 6 set", v));
    }
    {
        let mut v = s.clone();
        v[8] ^= 1;
        invalids.push(("secret", 2, "key does not match the commitment", v));
    }
    {
        let mut v = s.clone();
        v[40 + 36] ^= 1;
        invalids.push(("secret", 2, "commitment does not match the key", v));
    }
    {
        let mut v = s.clone();
        v.resize((v.len() as isize + (-1)) as usize, 0);
        invalids.push(("secret", 2, "one byte short", v));
    }
    {
        let mut v = s.clone();
        v.resize((v.len() as isize + (1)) as usize, 0);
        invalids.push(("secret", 2, "one trailing byte", v));
    }
    {
        let mut v = k.clone();
        v[0] ^= 1;
        invalids.push(("checkpoint", 2, "bad magic", v));
    }
    {
        let mut v = k.clone();
        v[4] = 2;
        invalids.push(("checkpoint", 2, "version 2", v));
    }
    {
        let mut v = k.clone();
        v[5] = 1;
        invalids.push(("checkpoint", 2, "reserved byte 5 set", v));
    }
    {
        let mut v = k.clone();
        v[8] ^= 1;
        invalids.push(("checkpoint", 2, "different puzzle id", v));
    }
    {
        let mut v = k.clone();
        set_be(&mut v, 40, 0, 4);
        invalids.push(("checkpoint", 2, "i = 0", v));
    }
    {
        let mut v = k.clone();
        set_be(&mut v, 40, 3, 4);
        invalids.push(("checkpoint", 2, "i = n + 1", v));
    }
    {
        let mut v = k.clone();
        set_be(&mut v, 44, 4, 8);
        invalids.push(("checkpoint", 2, "j = m + 1", v));
    }
    {
        let mut v = k.clone();
        v.resize((v.len() as isize + (-1)) as usize, 0);
        invalids.push(("checkpoint", 2, "one byte short", v));
    }
    {
        let mut v = k.clone();
        v.resize((v.len() as isize + (1)) as usize, 0);
        invalids.push(("checkpoint", 2, "one trailing byte", v));
    }

    for (i, (kind, c, why, data)) in invalids.iter().enumerate() {
        let o = &built[*c];
        let rejects = match *kind {
            "puzzle" => Puzzle::decode(data).is_err(),
            "secret" => secret_decode(data).is_err(),
            "envelope" => Envelope::decode(data).and_then(|e| e.open(&o.key)).is_err(),
            _ => Cursor::decode(&o.p, data).is_err(),
        };
        if !rejects {
            return Err(Error::Format);
        }
        if i > 0 {
            out.push_str(",\n");
        }
        let _ = write!(
            out,
            "    {{\"kind\": \"{kind}\", \"case\": {c}, \"why\": \"{why}\", "
        );
        field(&mut out, "hex", data, "}");
    }
    out.push_str("\n  ]\n}\n");
    Ok(out)
}
fn set_be(v: &mut [u8], at: usize, value: u64, n: usize) {
    v[at..at + n].copy_from_slice(&value.to_be_bytes()[8 - n..]);
}
