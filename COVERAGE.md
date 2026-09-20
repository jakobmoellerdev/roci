# Coverage

Line coverage is enforced at **100%** by the `coverage` step of the `CI`
workflow and the pre-commit hook. The gate asserts every executable line runs
at least once (lcov), excluding the thin binary entrypoint
`crates/roci-cli/src/main.rs` (a `#[tokio::main]` shim over the fully-covered
library).

Current line coverage: **99.96%** (5401/5403 lines).

Regenerate with `just coverage` (or on every commit via the pre-commit hook).
Inspect region-level gaps with `just coverage-report`.

```
Filename                         Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
roci-cli/src/lib.rs                  162                 5    96.91%          15                 1    93.33%         103                 1    99.03%           0                 0         -
roci-cli/src/main.rs                  17                 0   100.00%           4                 0   100.00%          15                 0   100.00%           0                 0         -
roci-cluster/src/lib.rs                3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-config/src/lib.rs                22                 0   100.00%           4                 0   100.00%          17                 0   100.00%           0                 0         -
roci-core/src/error.rs               228                 0   100.00%          22                 0   100.00%         164                 0   100.00%           0                 0         -
roci-core/src/lib.rs                4854                 7    99.86%         227                 0   100.00%        3066                 0   100.00%           0                 0         -
roci-core/src/names.rs               156                 0   100.00%          13                 0   100.00%         111                 0   100.00%           0                 0         -
roci-ext-scan/src/lib.rs               3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-search/src/lib.rs             3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sig/src/lib.rs                3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sync/src/lib.rs               3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-storage-s3/src/lib.rs             3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-storage/src/cache.rs            304                 0   100.00%          15                 0   100.00%         112                 0   100.00%           0                 0         -
roci-storage/src/filter.rs           169                 0   100.00%          12                 0   100.00%          83                 0   100.00%           0                 0         -
roci-storage/src/lib.rs             3929               170    95.67%         226                10    95.58%        1799                12    99.33%           0                 0         -
roci-storage/src/metadata.rs         962                17    98.23%          43                 0   100.00%         451                 0   100.00%           0                 0         -
roci-telemetry/src/lib.rs             33                 0   100.00%           5                 0   100.00%          22                 0   100.00%           0                 0         -
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                              10854               199    98.17%         592                11    98.14%        5961                13    99.78%           0                 0         -
```
