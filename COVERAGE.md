# Coverage

Line coverage is enforced at a **95%** floor by the `coverage`
step of the `CI` workflow and the pre-commit hook (lcov line metric), excluding
the thin binary entrypoint `crates/roci-cli/src/main.rs` (a `#[tokio::main]`
shim over the fully-covered library). Any uncovered lines are listed at gate
time for triage; the few that remain are unreachable-in-CI defensive
syscall-error arms in the beneath-root storage path.

Current line coverage: **98.82%** (6634/6713 lines).

Regenerate with `just coverage` (or on every commit via the pre-commit hook).
Inspect region-level gaps with `just coverage-report`.

```
Filename                         Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
roci-cli/src/lib.rs                  171                 5    97.08%          15                 1    93.33%         107                 1    99.07%           0                 0         -
roci-cli/src/main.rs                  17                 0   100.00%           4                 0   100.00%          15                 0   100.00%           0                 0         -
roci-cluster/src/lib.rs                3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-config/src/lib.rs                56                 3    94.64%           9                 1    88.89%          41                 3    92.68%           0                 0         -
roci-core/src/error.rs               232                 0   100.00%          23                 0   100.00%         167                 0   100.00%           0                 0         -
roci-core/src/lib.rs                5277                11    99.79%         241                 0   100.00%        3357                 1    99.97%           0                 0         -
roci-core/src/names.rs               156                 0   100.00%          13                 0   100.00%         111                 0   100.00%           0                 0         -
roci-ext-scan/src/lib.rs               3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-search/src/lib.rs             3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sig/src/lib.rs                3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sync/src/lib.rs               3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-storage-s3/src/lib.rs             3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-storage/src/cache.rs            304                 0   100.00%          15                 0   100.00%         112                 0   100.00%           0                 0         -
roci-storage/src/filter.rs           169                 0   100.00%          12                 0   100.00%          83                 0   100.00%           0                 0         -
roci-storage/src/lib.rs             6348               350    94.49%         339                15    95.58%        2929                98    96.65%           0                 0         -
roci-storage/src/metadata.rs        1038                17    98.36%          54                 0   100.00%         497                 0   100.00%           0                 0         -
roci-telemetry/src/lib.rs             33                 0   100.00%           5                 0   100.00%          22                 0   100.00%           0                 0         -
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                              13819               386    97.21%         736                17    97.69%        7459               103    98.62%           0                 0         -
```
