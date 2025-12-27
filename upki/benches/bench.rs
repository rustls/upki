use std::process::Command;

#[cfg(feature = "__bench_codspeed")]
use codspeed_criterion_compat::{Criterion, criterion_group, criterion_main};
#[cfg(not(feature = "__bench_codspeed"))]
use criterion::{Criterion, criterion_group, criterion_main};

fn cli(c: &mut Criterion) {
    let upki = insta_cmd::get_cargo_bin("upki");
    println!("using {upki:?}");

    c.bench_function("show-config-path", |b| {
        b.iter(|| {
            Command::new(&upki)
                .arg("show-config-path")
                .output()
                .unwrap()
        })
    });

    c.bench_function("show-config", |b| {
        b.iter(|| {
            Command::new(&upki)
                .arg("show-config")
                .output()
                .unwrap()
        })
    });

    c.bench_function("low-revoked", |b| {
        b.iter(|| {
            Command::new(&upki)
                .arg("revocation-check")
                .args(REVOKED_ARGS)
                .output()
                .unwrap()
        })
    });

    c.bench_function("low-unrevoked", |b| {
        b.iter(|| {
            Command::new(&upki)
                .arg("revocation-check")
                .args(UNREVOKED_ARGS)
                .output()
                .unwrap()
        })
    });
}

criterion_group!(benches, cli);
criterion_main!(benches);

// Take one item from `decorated.json`
const REVOKED_ARGS: &[&str] = &[
    "Gm1yGFIXe2EEuwC7zi1P9A==",
    "gqB1V0MFQpiBCTz+E+8NcNvy/Y4bUkg+ByYHikZE2W4=",
    "1219ENGn9XfCx+lf1wC/+YLJM1pl4dCzAXMXwMjFaXc=:1758285229558",
    "rKswcGzr7IQx9BPS9JFfER5CJEOx8qaMTzwrO6ceAsM=:1758285229554",
    "wjF+V0UZo0XufzjespBB68fCIVoiv3/Vta12mtkOUs0=:1758285229582",
];

// Ditto, but choose one which is not revoked (or indeed for any other server)
const UNREVOKED_ARGS: &[&str] = &[
    "wyqZp+Kayh0AAAAAU/0uuQ==",
    "Wa2FjlVfGKwvkiH0LYWh+y+ihHlaTmVQ+gqZEsR3RwY=",
    "1219ENGn9XfCx+lf1wC/+YLJM1pl4dCzAXMXwMjFaXc=:1763606601277",
    "2AlVO5RPev/IFhlvlE+Fq7D4/F6HVSYPFdEucrtFSxQ=:1763606602960",
    "wjF+V0UZo0XufzjespBB68fCIVoiv3/Vta12mtkOUs0=:1763606603716",
];
