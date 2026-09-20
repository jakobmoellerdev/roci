# Coverage

Line coverage is enforced at **100%** by the `coverage` step of the `CI`
workflow and the pre-commit hook. The gate asserts every executable line runs
at least once (lcov), excluding the thin binary entrypoint
`crates/roci-cli/src/main.rs` (a `#[tokio::main]` shim over the fully-covered
library).

Current line coverage: **100.00%** (6594/6594 lines).

Regenerate with `just coverage` (or on every commit via the pre-commit hook).
Inspect region-level gaps with `just coverage-report`.

```
Filename                         Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
roci-cli/src/lib.rs                  162                 5    96.91%          15                 1    93.33%         103                 1    99.03%           0                 0         -
roci-cli/src/main.rs                  17                 0   100.00%           4                 0   100.00%          15                 0   100.00%           0                 0         -
roci-cluster/src/lib.rs                3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-config/src/lib.rs                22                 0   100.00%           4                 0   100.00%          17                 0   100.00%           0                 0         -
roci-core/src/error.rs               376                 0   100.00%          34                 0   100.00%         256                 0   100.00%           0                 0         -
roci-core/src/lib.rs               22235                26    99.88%        1069                 0   100.00%       14307                 3    99.98%           0                 0         -
roci-core/src/names.rs               156                 0   100.00%          13                 0   100.00%         111                 0   100.00%           0                 0         -
roci-ext-scan/src/lib.rs               3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-search/src/lib.rs             3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sig/src/lib.rs                3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sync/src/lib.rs               3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-storage-s3/src/lib.rs             3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-storage/src/cache.rs            579                 0   100.00%          25                 0   100.00%         197                 0   100.00%           0                 0         -
roci-storage/src/filter.rs           169                 0   100.00%          12                 0   100.00%          83                 0   100.00%           0                 0         -
roci-storage/src/lib.rs            12257               541    95.59%         756                34    95.50%        5673                47    99.17%           0                 0         -
roci-storage/src/metadata.rs        2423                46    98.10%          98                 0   100.00%        1109                 0   100.00%           0                 0         -
roci-telemetry/src/lib.rs             46                 0   100.00%           8                 0   100.00%          31                 0   100.00%           0                 0         -
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                              38460               618    98.39%        2044                35    98.29%       21920                51    99.77%           0                 0         -
```
