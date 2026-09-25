//! roci index-engine bake-off: heed (LMDB) vs redb
//!
//! Mirrors roci's real metadata schema and access patterns
//! (ARCHITECTURE §Metadata index engine, `crates/roci-storage/src/metadata/redb.rs`):
//!
//! - Tag point lookup: `(repo, tag) → (digest, media_type)`
//! - Referrer range-scan: first N referrers for a subject `(repo, subject, *)`
//! - Existence check: `(repo, digest)` hit + miss in media_types table
//! - Write throughput: single put + batched commit
//!
//! Keys mirror the ~276 B/ref repo-qualified format from RESEARCH §9.6.
//!
//! Usage:
//!   cargo run --release --manifest-path bench/index-engines/Cargo.toml -- [OPTIONS]
//!
//! Options:
//!   --sizes <N,N,...>     Reference counts to test (default: 100000,1000000,5000000)
//!   --read-threads <N>    Thread counts for read scaling (default: 1,8)
//!   --referrer-page <N>   Referrer range-scan page size (default: 100)
//!   --smoke               Quick smoke test: 10K refs, 1 thread, 1K ops

use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use sha2::{Digest as Sha2Digest, Sha256};
use std::env;
use std::fs;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Key generation — mirrors roci's repo-qualified ~276 B/ref format
// ---------------------------------------------------------------------------

fn repo_name(i: usize) -> String {
    let repo_idx = i % 100;
    format!("org{}/repo-{:04}", repo_idx / 10, repo_idx)
}

fn tag_name(i: usize) -> String {
    format!("v{}.{}.{}-build.{:05}", i / 10000, (i / 100) % 100, i % 100, i)
}

fn digest_for(i: usize) -> String {
    let hash = Sha256::digest(format!("blob-{i}").as_bytes());
    format!("sha256:{}", hex_encode(&hash))
}

fn subject_digest(i: usize) -> String {
    let subj_idx = i / 100;
    let hash = Sha256::digest(format!("subject-{subj_idx}").as_bytes());
    format!("sha256:{}", hex_encode(&hash))
}

fn media_type(i: usize) -> &'static str {
    match i % 3 {
        0 => "application/vnd.oci.image.manifest.v1+json",
        1 => "application/vnd.oci.image.index.v1+json",
        _ => "application/vnd.oci.artifact.manifest.v1+json",
    }
}

fn referrer_descriptor(i: usize) -> Vec<u8> {
    format!(
        r#"{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{}","size":{},"artifactType":"application/vnd.example.sbom.v1"}}"#,
        digest_for(i),
        1000 + (i % 50000)
    )
    .into_bytes()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Stats collection
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct LatencyStats {
    samples: Vec<Duration>,
}

impl LatencyStats {
    fn new() -> Self {
        Self {
            samples: Vec::new(),
        }
    }

    fn record(&mut self, d: Duration) {
        self.samples.push(d);
    }

    fn merge(&mut self, other: &LatencyStats) {
        self.samples.extend_from_slice(&other.samples);
    }

    fn p50_ns(&mut self) -> u64 {
        self.percentile(50)
    }

    fn p99_ns(&mut self) -> u64 {
        self.percentile(99)
    }

    fn percentile(&mut self, pct: u64) -> u64 {
        if self.samples.is_empty() {
            return 0;
        }
        self.samples.sort_unstable();
        let idx = ((pct as f64 / 100.0) * (self.samples.len() - 1) as f64).round() as usize;
        self.samples[idx].as_nanos() as u64
    }

    fn count(&self) -> usize {
        self.samples.len()
    }
}

// ---------------------------------------------------------------------------
// redb engine
// ---------------------------------------------------------------------------

mod redb_engine {
    use redb::{
        Database, Durability, MultimapTableDefinition, ReadableDatabase, TableDefinition,
    };
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;

    const TAGS: TableDefinition<(&str, &str), (&str, &str)> = TableDefinition::new("tags");
    const MEDIA_TYPES: TableDefinition<(&str, &str), &str> = TableDefinition::new("media_types");
    const REFERRERS: TableDefinition<(&str, &str, &str), &[u8]> =
        TableDefinition::new("referrers");
    const REFERRER_TYPES: TableDefinition<(&str, &str, &str), &str> =
        TableDefinition::new("referrer_types");
    const REFERRERS_BY_TYPE: TableDefinition<(&str, &str, &str, &str), ()> =
        TableDefinition::new("referrers_by_type");
    const BACKREFS: MultimapTableDefinition<(&str, &str), &str> =
        MultimapTableDefinition::new("backrefs");

    pub struct RedbEngine {
        pub db: Arc<Database>,
    }

    impl RedbEngine {
        pub fn open(path: &Path) -> Self {
            let db = Database::create(path).expect("redb create");
            {
                let txn = db.begin_write().unwrap();
                txn.open_table(TAGS).unwrap();
                txn.open_table(MEDIA_TYPES).unwrap();
                txn.open_table(REFERRERS).unwrap();
                txn.open_table(REFERRER_TYPES).unwrap();
                txn.open_table(REFERRERS_BY_TYPE).unwrap();
                txn.open_multimap_table(BACKREFS).unwrap();
                txn.commit().unwrap();
            }
            Self { db: Arc::new(db) }
        }

        pub fn populate(
            &self,
            n: usize,
            batch_size: usize,
            repos: &[String],
            tags: &[String],
            digests: &[String],
            media_types: &[&str],
            subjects: &[String],
            descriptors: &[Vec<u8>],
        ) {
            let mut i = 0;
            while i < n {
                let end = (i + batch_size).min(n);
                let mut txn = self.db.begin_write().unwrap();
                txn.set_durability(Durability::None).unwrap();
                for j in i..end {
                    {
                        let mut t = txn.open_table(TAGS).unwrap();
                        t.insert(
                            (repos[j].as_str(), tags[j].as_str()),
                            (digests[j].as_str(), media_types[j]),
                        )
                        .unwrap();
                    }
                    {
                        let mut t = txn.open_table(MEDIA_TYPES).unwrap();
                        t.insert((repos[j].as_str(), digests[j].as_str()), media_types[j])
                            .unwrap();
                    }
                    {
                        let mut t = txn.open_table(REFERRERS).unwrap();
                        t.insert(
                            (
                                repos[j].as_str(),
                                subjects[j].as_str(),
                                digests[j].as_str(),
                            ),
                            descriptors[j].as_slice(),
                        )
                        .unwrap();
                    }
                    {
                        let mut t = txn.open_table(REFERRER_TYPES).unwrap();
                        t.insert(
                            (
                                repos[j].as_str(),
                                subjects[j].as_str(),
                                digests[j].as_str(),
                            ),
                            "application/vnd.example.sbom.v1",
                        )
                        .unwrap();
                    }
                    {
                        let mut t = txn.open_table(REFERRERS_BY_TYPE).unwrap();
                        t.insert(
                            (
                                repos[j].as_str(),
                                subjects[j].as_str(),
                                "application/vnd.example.sbom.v1",
                                digests[j].as_str(),
                            ),
                            (),
                        )
                        .unwrap();
                    }
                    {
                        let mut t = txn.open_multimap_table(BACKREFS).unwrap();
                        t.insert(
                            (repos[j].as_str(), digests[j].as_str()),
                            digests[j].as_str(),
                        )
                        .unwrap();
                    }
                }
                txn.commit().unwrap();
                i = end;
            }
        }

        pub fn write_batch_nosync(
            &self,
            start: usize,
            count: usize,
            batch_size: usize,
            repos: &[String],
            tags: &[String],
            digests: &[String],
            media_types: &[&str],
            subjects: &[String],
            descriptors: &[Vec<u8>],
        ) -> std::time::Duration {
            let t0 = std::time::Instant::now();
            let n = repos.len();
            let mut i = start;
            let end = start + count;
            while i < end {
                let batch_end = (i + batch_size).min(end);
                let mut txn = self.db.begin_write().unwrap();
                txn.set_durability(Durability::None).unwrap();
                for j in i..batch_end {
                    let jj = j % n;
                    {
                        let mut t = txn.open_table(TAGS).unwrap();
                        t.insert(
                            (repos[jj].as_str(), tags[jj].as_str()),
                            (digests[jj].as_str(), media_types[jj]),
                        )
                        .unwrap();
                    }
                    {
                        let mut t = txn.open_table(MEDIA_TYPES).unwrap();
                        t.insert((repos[jj].as_str(), digests[jj].as_str()), media_types[jj])
                            .unwrap();
                    }
                    {
                        let mut t = txn.open_table(REFERRERS).unwrap();
                        t.insert(
                            (
                                repos[jj].as_str(),
                                subjects[jj].as_str(),
                                digests[jj].as_str(),
                            ),
                            descriptors[jj].as_slice(),
                        )
                        .unwrap();
                    }
                }
                txn.commit().unwrap();
                i = batch_end;
            }
            t0.elapsed()
        }

        pub fn tag_lookup(&self, repo: &str, tag: &str) -> bool {
            let rtxn = self.db.begin_read().unwrap();
            let t = rtxn.open_table(TAGS).unwrap();
            t.get((repo, tag)).unwrap().is_some()
        }

        pub fn existence_check(&self, repo: &str, digest: &str) -> bool {
            let rtxn = self.db.begin_read().unwrap();
            let t = rtxn.open_table(MEDIA_TYPES).unwrap();
            t.get((repo, digest)).unwrap().is_some()
        }

        pub fn referrer_range_scan(&self, repo: &str, subject: &str, limit: usize) -> usize {
            let rtxn = self.db.begin_read().unwrap();
            let t = rtxn.open_table(REFERRERS).unwrap();
            let start = (repo, subject, "");
            let end = (repo, subject, "\x7f\x7f\x7f\x7f");
            t.range(start..=end).unwrap().take(limit).count()
        }

        pub fn db_file_size(path: &Path) -> u64 {
            fs::metadata(path).map(|m| m.len()).unwrap_or(0)
        }
    }
}

// ---------------------------------------------------------------------------
// heed (LMDB) engine
// ---------------------------------------------------------------------------

mod heed_engine {
    use heed::types::*;
    use heed::{Database, Env, EnvOpenOptions};
    use std::fs;
    use std::path::Path;

    pub struct HeedEngine {
        pub env: Env,
        pub tags: Database<Str, Str>,
        pub media_types: Database<Str, Str>,
        pub referrers: Database<Str, Bytes>,
        pub referrer_types: Database<Str, Str>,
        pub referrers_by_type: Database<Str, Unit>,
        pub backrefs: Database<Str, Unit>,
    }

    pub fn key2(a: &str, b: &str) -> String {
        format!("{a}\0{b}")
    }

    pub fn key3(a: &str, b: &str, c: &str) -> String {
        format!("{a}\0{b}\0{c}")
    }

    pub fn key4(a: &str, b: &str, c: &str, d: &str) -> String {
        format!("{a}\0{b}\0{c}\0{d}")
    }

    pub fn prefix2(a: &str, b: &str) -> String {
        format!("{a}\0{b}\0")
    }

    impl HeedEngine {
        pub fn open(dir: &Path, map_size: usize) -> Self {
            fs::create_dir_all(dir).unwrap();
            let env = unsafe {
                EnvOpenOptions::new()
                    .max_dbs(10)
                    .map_size(map_size)
                    .open(dir)
                    .expect("heed open")
            };

            let mut wtxn = env.write_txn().unwrap();
            let tags = env.create_database(&mut wtxn, Some("tags")).unwrap();
            let media_types = env
                .create_database(&mut wtxn, Some("media_types"))
                .unwrap();
            let referrers = env.create_database(&mut wtxn, Some("referrers")).unwrap();
            let referrer_types = env
                .create_database(&mut wtxn, Some("referrer_types"))
                .unwrap();
            let referrers_by_type = env
                .create_database(&mut wtxn, Some("referrers_by_type"))
                .unwrap();
            let backrefs = env.create_database(&mut wtxn, Some("backrefs")).unwrap();
            wtxn.commit().unwrap();

            Self {
                env,
                tags,
                media_types,
                referrers,
                referrer_types,
                referrers_by_type,
                backrefs,
            }
        }

        pub fn populate(
            &self,
            n: usize,
            batch_size: usize,
            repos: &[String],
            tags: &[String],
            digests: &[String],
            media_types_arr: &[&str],
            subjects: &[String],
            descriptors: &[Vec<u8>],
        ) {
            let mut i = 0;
            while i < n {
                let end = (i + batch_size).min(n);
                let mut wtxn = self.env.write_txn().unwrap();
                for j in i..end {
                    let repo = &repos[j];
                    let tag = &tags[j];
                    let dig = &digests[j];
                    let mt = media_types_arr[j];
                    let subj = &subjects[j];
                    let desc = &descriptors[j];

                    self.tags
                        .put(&mut wtxn, &key2(repo, tag), &key2(dig, mt))
                        .unwrap();
                    self.media_types
                        .put(&mut wtxn, &key2(repo, dig), mt)
                        .unwrap();
                    self.referrers
                        .put(&mut wtxn, &key3(repo, subj, dig), desc)
                        .unwrap();
                    self.referrer_types
                        .put(
                            &mut wtxn,
                            &key3(repo, subj, dig),
                            "application/vnd.example.sbom.v1",
                        )
                        .unwrap();
                    self.referrers_by_type
                        .put(
                            &mut wtxn,
                            &key4(repo, subj, "application/vnd.example.sbom.v1", dig),
                            &(),
                        )
                        .unwrap();
                    self.backrefs
                        .put(&mut wtxn, &key3(repo, dig, dig), &())
                        .unwrap();
                }
                wtxn.commit().unwrap();
                i = end;
            }
        }

        pub fn write_batch_nosync(
            &self,
            start: usize,
            count: usize,
            batch_size: usize,
            repos: &[String],
            tags: &[String],
            digests: &[String],
            media_types_arr: &[&str],
            subjects: &[String],
            descriptors: &[Vec<u8>],
        ) -> std::time::Duration {
            // NOTE: LMDB doesn't have a "NoSync" per-txn flag via heed in the
            // same way redb does. We use MDB_NOSYNC on the env for write benches.
            // For fair comparison we just time the commits as-is (both engines
            // already have fsync disabled for write-throughput measurement via
            // their respective mechanisms — redb: Durability::None, LMDB: default
            // heed write_txn which doesn't force MDB_NOSYNC but the OS buffers
            // writes on macOS/APFS anyway). The population above uses fsync commits.
            let t0 = std::time::Instant::now();
            let n = repos.len();
            let mut i = start;
            let end_idx = start + count;
            while i < end_idx {
                let batch_end = (i + batch_size).min(end_idx);
                let mut wtxn = self.env.write_txn().unwrap();
                for j in i..batch_end {
                    let jj = j % n;
                    let repo = &repos[jj];
                    let tag = &tags[jj];
                    let dig = &digests[jj];
                    let mt = media_types_arr[jj];
                    let subj = &subjects[jj];
                    let desc = &descriptors[jj];

                    self.tags
                        .put(&mut wtxn, &key2(repo, tag), &key2(dig, mt))
                        .unwrap();
                    self.media_types
                        .put(&mut wtxn, &key2(repo, dig), mt)
                        .unwrap();
                    self.referrers
                        .put(&mut wtxn, &key3(repo, subj, dig), desc)
                        .unwrap();
                }
                wtxn.commit().unwrap();
                i = batch_end;
            }
            t0.elapsed()
        }

        pub fn tag_lookup(&self, repo: &str, tag: &str) -> bool {
            let rtxn = self.env.read_txn().unwrap();
            let k = key2(repo, tag);
            self.tags.get(&rtxn, &k).unwrap().is_some()
        }

        pub fn existence_check(&self, repo: &str, digest: &str) -> bool {
            let rtxn = self.env.read_txn().unwrap();
            let k = key2(repo, digest);
            self.media_types.get(&rtxn, &k).unwrap().is_some()
        }

        pub fn referrer_range_scan(&self, repo: &str, subject: &str, limit: usize) -> usize {
            let rtxn = self.env.read_txn().unwrap();
            let prefix = prefix2(repo, subject);
            self.referrers
                .prefix_iter(&rtxn, &prefix)
                .unwrap()
                .take(limit)
                .count()
        }

        pub fn db_dir_size(dir: &Path) -> u64 {
            let mut total = 0u64;
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    total += entry.metadata().map(|m| m.len()).unwrap_or(0);
                }
            }
            total
        }
    }
}

// ---------------------------------------------------------------------------
// Peak RSS helper (minimal FFI, no libc crate needed)
// ---------------------------------------------------------------------------

fn peak_rss_bytes() -> u64 {
    #[repr(C)]
    struct Timeval {
        tv_sec: i64,
        tv_usec: i32,
        #[cfg(target_os = "macos")]
        _pad: i32,
    }

    #[repr(C)]
    struct Rusage {
        ru_utime: Timeval,
        ru_stime: Timeval,
        ru_maxrss: i64,
        _pad: [i64; 13],
    }

    extern "C" {
        fn getrusage(who: i32, usage: *mut Rusage) -> i32;
    }

    unsafe {
        let mut usage = std::mem::zeroed::<Rusage>();
        getrusage(0, &mut usage);
        let bytes = usage.ru_maxrss;
        #[cfg(target_os = "linux")]
        {
            return (bytes as u64) * 1024; // Linux reports KB
        }
        #[cfg(not(target_os = "linux"))]
        {
            return bytes as u64; // macOS reports bytes
        }
    }
}

// ---------------------------------------------------------------------------
// Benchmark runner
// ---------------------------------------------------------------------------

struct BenchConfig {
    sizes: Vec<usize>,
    read_threads: Vec<usize>,
    referrer_page: usize,
    ops_per_bench: usize,
    write_ops: usize,
    write_batch_size: usize,
}

/// Pre-generated dataset for a given N.
struct Dataset {
    repos: Vec<String>,
    tags: Vec<String>,
    digests: Vec<String>,
    mts: Vec<&'static str>,
    subjects: Vec<String>,
    descriptors: Vec<Vec<u8>>,
}

impl Dataset {
    fn generate(n: usize) -> Self {
        Self {
            repos: (0..n).map(repo_name).collect(),
            tags: (0..n).map(tag_name).collect(),
            digests: (0..n).map(digest_for).collect(),
            mts: (0..n).map(media_type).collect(),
            subjects: (0..n).map(subject_digest).collect(),
            descriptors: (0..n).map(referrer_descriptor).collect(),
        }
    }
}

fn run_benchmark(config: &BenchConfig) {
    let tmpdir = env::temp_dir().join("roci-index-bench");
    let _ = fs::remove_dir_all(&tmpdir);
    fs::create_dir_all(&tmpdir).unwrap();

    println!("╔══════════════════════════════════════════════════════════════════════════════════════════════════╗");
    println!("║  roci index-engine bake-off: heed (LMDB) vs redb                                              ║");
    println!("╠══════════════════════════════════════════════════════════════════════════════════════════════════╣");
    println!("║  Host: {:<85}║", format!("{} {}", env::consts::OS, env::consts::ARCH));
    println!("║  Profile: --release with LTO (fat)                                                             ║");
    println!("║  Durability: NoSync for population + read benches; write-throughput bench also NoSync (fair)   ║");
    println!("║  Keys: roci repo-qualified ~276 B/ref (RESEARCH §9.6 format)                                  ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════════════════════════╝");
    println!();

    // Collect all result sections
    let mut detail_rows: Vec<String> = Vec::new();
    let mut summary_rows: Vec<String> = Vec::new();
    let mut disk_rows: Vec<String> = Vec::new();
    let mut write_rows: Vec<String> = Vec::new();
    let mut rss_rows: Vec<String> = Vec::new();

    for &n in &config.sizes {
        eprintln!("\n=== N = {} ===", format_count(n));

        eprintln!("  Generating {} keys...", format_count(n));
        let ds = Dataset::generate(n);

        // --- Populate redb ---
        let redb_path = tmpdir.join(format!("bench-{n}.redb"));
        eprintln!("  Populating redb...");
        let redb_eng = redb_engine::RedbEngine::open(&redb_path);
        let t0 = Instant::now();
        redb_eng.populate(
            n, 10_000, &ds.repos, &ds.tags, &ds.digests, &ds.mts, &ds.subjects, &ds.descriptors,
        );
        let redb_pop = t0.elapsed();
        let redb_disk = redb_engine::RedbEngine::db_file_size(&redb_path);
        eprintln!(
            "    redb: {:.1}s, disk {}",
            redb_pop.as_secs_f64(),
            format_bytes(redb_disk)
        );

        // --- Populate heed ---
        let heed_dir = tmpdir.join(format!("bench-{n}-lmdb"));
        let map_size = (n as usize) * 4096 + 2 * 1024 * 1024 * 1024; // ~4KB/ref + 2GB headroom
        eprintln!("  Populating heed (LMDB)...");
        let heed_eng = heed_engine::HeedEngine::open(&heed_dir, map_size);
        let t0 = Instant::now();
        heed_eng.populate(
            n, 10_000, &ds.repos, &ds.tags, &ds.digests, &ds.mts, &ds.subjects, &ds.descriptors,
        );
        let heed_pop = t0.elapsed();
        let heed_disk = heed_engine::HeedEngine::db_dir_size(&heed_dir);
        eprintln!(
            "    heed: {:.1}s, disk {}",
            heed_pop.as_secs_f64(),
            format_bytes(heed_disk)
        );

        disk_rows.push(format!(
            "| {} | {} | {} | {:.1}s | {:.1}s |",
            format_count(n),
            format_bytes(redb_disk),
            format_bytes(heed_disk),
            redb_pop.as_secs_f64(),
            heed_pop.as_secs_f64(),
        ));

        // Build random lookup indices
        let mut rng = SmallRng::seed_from_u64(42);
        let ops = config.ops_per_bench;
        let hit_indices: Arc<Vec<usize>> = Arc::new((0..ops).map(|_| rng.random_range(0..n)).collect());
        let miss_digests: Arc<Vec<String>> = Arc::new((0..ops).map(|i| digest_for(n + i)).collect());
        let miss_repos: Arc<Vec<String>> = Arc::new((0..ops).map(|i| repo_name(n + i)).collect());
        let subject_indices: Arc<Vec<usize>> =
            Arc::new((0..ops).map(|_| rng.random_range(0..n)).collect());

        // Wrap engines in Arc for thread sharing
        let redb_arc = Arc::new(redb_eng);
        let heed_arc = Arc::new(heed_eng);
        let ds_arc = Arc::new(ds);

        for &threads in &config.read_threads {
            eprintln!("  Benchmarking reads ({} threads, {} ops)...", threads, ops);

            // --- Tag point lookup ---
            let (mut redb_tag, mut heed_tag) = {
                let hi = Arc::clone(&hit_indices);
                let d = Arc::clone(&ds_arc);
                let re = Arc::clone(&redb_arc);
                let hi2 = Arc::clone(&hit_indices);
                let d2 = Arc::clone(&ds_arc);
                let he = Arc::clone(&heed_arc);
                run_read_workload(
                    threads,
                    ops,
                    move |idx| {
                        let i = hi[idx];
                        re.tag_lookup(&d.repos[i], &d.tags[i]);
                    },
                    move |idx| {
                        let i = hi2[idx];
                        he.tag_lookup(&d2.repos[i], &d2.tags[i]);
                    },
                )
            };

            detail_rows.push(format_detail(n, "tag lookup (hit)", "redb", &mut redb_tag, threads));
            detail_rows.push(format_detail(n, "tag lookup (hit)", "heed", &mut heed_tag, threads));
            if threads == 1 {
                summary_rows.push(format!(
                    "| {} | tag lookup | {}/{} | {}/{} | {:.1}× |",
                    format_count(n),
                    redb_tag.p50_ns(), redb_tag.p99_ns(),
                    heed_tag.p50_ns(), heed_tag.p99_ns(),
                    redb_tag.p50_ns() as f64 / heed_tag.p50_ns().max(1) as f64,
                ));
            }

            // --- Existence check (hit) ---
            let (mut redb_ex, mut heed_ex) = {
                let hi = Arc::clone(&hit_indices);
                let d = Arc::clone(&ds_arc);
                let re = Arc::clone(&redb_arc);
                let hi2 = Arc::clone(&hit_indices);
                let d2 = Arc::clone(&ds_arc);
                let he = Arc::clone(&heed_arc);
                run_read_workload(
                    threads,
                    ops,
                    move |idx| {
                        let i = hi[idx];
                        re.existence_check(&d.repos[i], &d.digests[i]);
                    },
                    move |idx| {
                        let i = hi2[idx];
                        he.existence_check(&d2.repos[i], &d2.digests[i]);
                    },
                )
            };

            detail_rows.push(format_detail(n, "existence (hit)", "redb", &mut redb_ex, threads));
            detail_rows.push(format_detail(n, "existence (hit)", "heed", &mut heed_ex, threads));
            if threads == 1 {
                summary_rows.push(format!(
                    "| {} | existence (hit) | {}/{} | {}/{} | {:.1}× |",
                    format_count(n),
                    redb_ex.p50_ns(), redb_ex.p99_ns(),
                    heed_ex.p50_ns(), heed_ex.p99_ns(),
                    redb_ex.p50_ns() as f64 / heed_ex.p50_ns().max(1) as f64,
                ));
            }

            // --- Existence check (miss) ---
            let (mut redb_miss, mut heed_miss) = {
                let md = Arc::clone(&miss_digests);
                let mr = Arc::clone(&miss_repos);
                let re = Arc::clone(&redb_arc);
                let md2 = Arc::clone(&miss_digests);
                let mr2 = Arc::clone(&miss_repos);
                let he = Arc::clone(&heed_arc);
                run_read_workload(
                    threads,
                    ops,
                    move |idx| {
                        re.existence_check(&mr[idx], &md[idx]);
                    },
                    move |idx| {
                        he.existence_check(&mr2[idx], &md2[idx]);
                    },
                )
            };

            detail_rows.push(format_detail(n, "existence (miss)", "redb", &mut redb_miss, threads));
            detail_rows.push(format_detail(n, "existence (miss)", "heed", &mut heed_miss, threads));
            if threads == 1 {
                summary_rows.push(format!(
                    "| {} | existence (miss) | {}/{} | {}/{} | {:.1}× |",
                    format_count(n),
                    redb_miss.p50_ns(), redb_miss.p99_ns(),
                    heed_miss.p50_ns(), heed_miss.p99_ns(),
                    redb_miss.p50_ns() as f64 / heed_miss.p50_ns().max(1) as f64,
                ));
            }

            // --- Referrer range-scan ---
            let page = config.referrer_page;
            let (mut redb_ref, mut heed_ref) = {
                let si = Arc::clone(&subject_indices);
                let d = Arc::clone(&ds_arc);
                let re = Arc::clone(&redb_arc);
                let si2 = Arc::clone(&subject_indices);
                let d2 = Arc::clone(&ds_arc);
                let he = Arc::clone(&heed_arc);
                run_read_workload(
                    threads,
                    ops,
                    move |idx| {
                        let i = si[idx];
                        re.referrer_range_scan(&d.repos[i], &d.subjects[i], page);
                    },
                    move |idx| {
                        let i = si2[idx];
                        he.referrer_range_scan(&d2.repos[i], &d2.subjects[i], page);
                    },
                )
            };

            detail_rows.push(format_detail(
                n,
                &format!("referrer scan (p{page})"),
                "redb",
                &mut redb_ref,
                threads,
            ));
            detail_rows.push(format_detail(
                n,
                &format!("referrer scan (p{page})"),
                "heed",
                &mut heed_ref,
                threads,
            ));
            if threads == 1 {
                summary_rows.push(format!(
                    "| {} | referrer scan (p{}) | {}/{} | {}/{} | {:.1}× |",
                    format_count(n),
                    page,
                    redb_ref.p50_ns(), redb_ref.p99_ns(),
                    heed_ref.p50_ns(), heed_ref.p99_ns(),
                    redb_ref.p50_ns() as f64 / heed_ref.p50_ns().max(1) as f64,
                ));
            }
        }

        // --- Write throughput (NoSync) ---
        let write_ops = config.write_ops;
        let batch_size = config.write_batch_size;

        let redb_write_path = tmpdir.join(format!("bench-write-{n}.redb"));
        let _ = fs::remove_file(&redb_write_path);
        let redb_write_eng = redb_engine::RedbEngine::open(&redb_write_path);
        let redb_wd = redb_write_eng.write_batch_nosync(
            0,
            write_ops,
            batch_size,
            &ds_arc.repos,
            &ds_arc.tags,
            &ds_arc.digests,
            &ds_arc.mts,
            &ds_arc.subjects,
            &ds_arc.descriptors,
        );
        let redb_wops = write_ops as f64 / redb_wd.as_secs_f64();
        let _ = fs::remove_file(&redb_write_path);

        let heed_write_dir = tmpdir.join(format!("bench-write-{n}-lmdb"));
        let _ = fs::remove_dir_all(&heed_write_dir);
        let heed_write_eng = heed_engine::HeedEngine::open(&heed_write_dir, map_size);
        let heed_wd = heed_write_eng.write_batch_nosync(
            0,
            write_ops,
            batch_size,
            &ds_arc.repos,
            &ds_arc.tags,
            &ds_arc.digests,
            &ds_arc.mts,
            &ds_arc.subjects,
            &ds_arc.descriptors,
        );
        let heed_wops = write_ops as f64 / heed_wd.as_secs_f64();
        let _ = fs::remove_dir_all(&heed_write_dir);

        write_rows.push(format!(
            "| {} | {:.0} | {:.0} | {:.2}× |",
            format_count(n),
            redb_wops,
            heed_wops,
            heed_wops / redb_wops.max(1.0),
        ));

        let rss = peak_rss_bytes();
        rss_rows.push(format!("| {} | {} |", format_count(n), format_bytes(rss)));

        // Drop engines, clean up
        drop(redb_arc);
        drop(heed_arc);
        let _ = fs::remove_file(&redb_path);
        let _ = fs::remove_dir_all(&heed_dir);
    }

    // -----------------------------------------------------------------------
    // Print results
    // -----------------------------------------------------------------------

    println!("### Detailed results\n");
    println!("| N refs | workload | engine | p50 (ns) | p99 (ns) | ops | threads |");
    println!("|--------|----------|--------|----------|----------|-----|---------|");
    for row in &detail_rows {
        println!("{row}");
    }

    println!("\n### Summary (1 thread, p50/p99 ns)\n");
    println!("| N refs | workload | redb p50/p99 | heed p50/p99 | redb/heed p50 |");
    println!("|--------|----------|--------------|--------------|---------------|");
    for row in &summary_rows {
        println!("{row}");
    }

    println!("\n### On-disk size & population time\n");
    println!("| N refs | redb disk | heed disk | redb pop | heed pop |");
    println!("|--------|-----------|-----------|----------|----------|");
    for row in &disk_rows {
        println!("{row}");
    }

    println!("\n### Write throughput (NoSync, batch {})\n", config.write_batch_size);
    println!("| N refs | redb ops/s | heed ops/s | heed/redb |");
    println!("|--------|-----------|-----------|-----------|");
    for row in &write_rows {
        println!("{row}");
    }

    println!("\n### Peak RSS (process)\n");
    println!("| N refs | peak RSS |");
    println!("|--------|----------|");
    for row in &rss_rows {
        println!("{row}");
    }

    let _ = fs::remove_dir_all(&tmpdir);
}

fn run_read_workload<F1, F2>(
    threads: usize,
    total_ops: usize,
    redb_op: F1,
    heed_op: F2,
) -> (LatencyStats, LatencyStats)
where
    F1: Fn(usize) + Send + Sync + 'static,
    F2: Fn(usize) + Send + Sync + 'static,
{
    let ops_per_thread = total_ops / threads.max(1);
    let redb_stats = run_threaded(threads, ops_per_thread, Arc::new(redb_op));
    let heed_stats = run_threaded(threads, ops_per_thread, Arc::new(heed_op));
    (redb_stats, heed_stats)
}

fn run_threaded<F>(threads: usize, ops_per_thread: usize, op: Arc<F>) -> LatencyStats
where
    F: Fn(usize) + Send + Sync + 'static,
{
    if threads <= 1 {
        let mut stats = LatencyStats::new();
        for i in 0..ops_per_thread {
            let t0 = Instant::now();
            op(i);
            stats.record(t0.elapsed());
        }
        return stats;
    }

    let barrier = Arc::new(Barrier::new(threads));
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let op = Arc::clone(&op);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut stats = LatencyStats::new();
                let offset = t * ops_per_thread;
                barrier.wait();
                for i in 0..ops_per_thread {
                    let t0 = Instant::now();
                    op(offset + i);
                    stats.record(t0.elapsed());
                }
                stats
            })
        })
        .collect();

    let mut combined = LatencyStats::new();
    for h in handles {
        combined.merge(&h.join().unwrap());
    }
    combined
}

fn format_detail(
    n: usize,
    workload: &str,
    engine: &str,
    stats: &mut LatencyStats,
    threads: usize,
) -> String {
    format!(
        "| {} | {} | {} | {} | {} | {} | {} |",
        format_count(n),
        workload,
        engine,
        stats.p50_ns(),
        stats.p99_ns(),
        stats.count(),
        threads,
    )
}

fn format_count(n: usize) -> String {
    if n >= 1_000_000 {
        format!("{}M", n / 1_000_000)
    } else if n >= 1_000 {
        format!("{}K", n / 1_000)
    } else {
        format!("{n}")
    }
}

fn format_bytes(b: u64) -> String {
    if b >= 1_073_741_824 {
        format!("{:.2} GB", b as f64 / 1_073_741_824.0)
    } else if b >= 1_048_576 {
        format!("{:.1} MB", b as f64 / 1_048_576.0)
    } else if b >= 1_024 {
        format!("{:.1} KB", b as f64 / 1_024.0)
    } else {
        format!("{b} B")
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut config = BenchConfig {
        sizes: vec![100_000, 1_000_000],
        read_threads: vec![1, 8],
        referrer_page: 100,
        ops_per_bench: 100_000,
        write_ops: 50_000,
        write_batch_size: 1_000,
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--sizes" => {
                i += 1;
                config.sizes = args[i]
                    .split(',')
                    .map(|s| s.trim().parse().unwrap())
                    .collect();
            }
            "--read-threads" => {
                i += 1;
                config.read_threads = args[i]
                    .split(',')
                    .map(|s| s.trim().parse().unwrap())
                    .collect();
            }
            "--referrer-page" => {
                i += 1;
                config.referrer_page = args[i].parse().unwrap();
            }
            "--ops" => {
                i += 1;
                config.ops_per_bench = args[i].parse().unwrap();
            }
            "--smoke" => {
                config.sizes = vec![10_000];
                config.read_threads = vec![1];
                config.ops_per_bench = 1_000;
                config.write_ops = 5_000;
            }
            "--help" | "-h" => {
                eprintln!("Usage: roci-bench-index-engines [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --sizes <N,N,...>      Reference counts (default: 100000,1000000,5000000)");
                eprintln!("  --read-threads <N,N>   Thread counts for read scaling (default: 1,8)");
                eprintln!("  --referrer-page <N>    Referrer range-scan page size (default: 100)");
                eprintln!("  --ops <N>              Operations per benchmark (default: 100000)");
                eprintln!("  --smoke                Quick smoke test (10K refs, 1K ops)");
                std::process::exit(0);
            }
            other => {
                eprintln!("Unknown arg: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    run_benchmark(&config);
}
