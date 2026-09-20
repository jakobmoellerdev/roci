# Coverage

Line coverage is enforced at **100%** by the `coverage` step of the `CI`
workflow and the pre-commit hook. The gate asserts every executable line runs
at least once (lcov), excluding the thin binary entrypoint
`crates/roci-cli/src/main.rs` (a `#[tokio::main]` shim over the fully-covered
library).

Current line coverage: **100.00%** (6809/6809 lines).

Regenerate with `just coverage` (or on every commit via the pre-commit hook).
Inspect region-level gaps with `just coverage-report`.

```
Filename                         Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
roci-cli/src/lib.rs                  162                 5    96.91%          15                 1    93.33%         103                 1    99.03%           0                 0         -
roci-cli/src/main.rs                  17                 0   100.00%           4                 0   100.00%          15                 0   100.00%           0                 0         -
roci-cluster/src/lib.rs                3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-config/src/lib.rs                22                 0   100.00%           4                 0   100.00%          17                 0   100.00%           0                 0         -
roci-core/src/error.rs               381                 0   100.00%          34                 0   100.00%         264                 0   100.00%           0                 0         -
roci-core/src/lib.rs               22486                26    99.88%        1084                 0   100.00%       14458                 3    99.98%           0                 0         -
roci-core/src/names.rs               156                 0   100.00%          13                 0   100.00%         111                 0   100.00%           0                 0         -
roci-ext-scan/src/lib.rs               3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-search/src/lib.rs             3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sig/src/lib.rs                3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sync/src/lib.rs               3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-storage-s3/src/lib.rs             3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-storage/src/cache.rs            579                 0   100.00%          25                 0   100.00%         197                 0   100.00%           0                 0         -
roci-storage/src/filter.rs           169                 0   100.00%          12                 0   100.00%          83                 0   100.00%           0                 0         -
roci-storage/src/lib.rs            12439               542    95.64%         730                30    95.89%        5686                40    99.30%           0                 0         -
roci-storage/src/metadata.rs        1672                29    98.27%          75                 0   100.00%         785                 0   100.00%           0                 0         -
roci-telemetry/src/lib.rs             46                 0   100.00%           8                 0   100.00%          31                 0   100.00%           0                 0         -
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                              38147               602    98.42%        2010                31    98.46%       21768                44    99.80%           0                 0         -
```
