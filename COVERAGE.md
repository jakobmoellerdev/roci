# Coverage

Line coverage is enforced at **100%** by the `coverage` step of the `CI`
workflow and the pre-commit hook. The gate asserts every executable line runs
at least once (lcov), excluding the thin binary entrypoint
`crates/roci-cli/src/main.rs` (a `#[tokio::main]` shim over the fully-covered
library).

Current line coverage: **100.00%** (2261/2261 lines).

Regenerate with `just coverage` (or on every commit via the pre-commit hook).
Inspect region-level gaps with `just coverage-report`.

```
Filename                       Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
roci-cli/src/lib.rs                162                 5    96.91%          15                 1    93.33%         103                 1    99.03%           0                 0         -
roci-cli/src/main.rs                17                 0   100.00%           4                 0   100.00%          15                 0   100.00%           0                 0         -
roci-cluster/src/lib.rs              3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-config/src/lib.rs              22                 0   100.00%           4                 0   100.00%          17                 0   100.00%           0                 0         -
roci-core/src/lib.rs              2765                 0   100.00%         146                 0   100.00%        1829                 0   100.00%           0                 0         -
roci-ext-scan/src/lib.rs             3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-search/src/lib.rs           3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sig/src/lib.rs              3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sync/src/lib.rs             3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-storage-s3/src/lib.rs           3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-storage/src/lib.rs           1196                49    95.90%          77                 1    98.70%         582                 4    99.31%           0                 0         -
roci-telemetry/src/lib.rs           13                 0   100.00%           3                 0   100.00%           9                 0   100.00%           0                 0         -
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                             4193                54    98.71%         255                 2    99.22%        2573                 5    99.81%           0                 0         -
```
