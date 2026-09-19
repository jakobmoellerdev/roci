# Coverage

Line coverage is enforced at **100%** by the `coverage` CI job and the
pre-commit hook (`cargo llvm-cov --workspace --all-features --fail-under-lines 100`).

Latest local measurement: **99.84%** (on `Darwin`). On Linux CI this
is **100%**; on other platforms a few Unix-filesystem-specific lines cannot be
exercised locally but are covered on the Linux CI runner, which is authoritative.

Regenerate this report with `just coverage` (or on every commit via the
pre-commit hook). Inspect uncovered lines with `just coverage-report`.

```
Filename                       Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
roci-cli/src/main.rs               185                 5    97.30%          21                 1    95.24%         122                 1    99.18%           0                 0         -
roci-cluster/src/lib.rs              3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-config/src/lib.rs              22                 0   100.00%           4                 0   100.00%          17                 0   100.00%           0                 0         -
roci-core/src/lib.rs              2765                 0   100.00%         146                 0   100.00%        1829                 0   100.00%           0                 0         -
roci-ext-scan/src/lib.rs             3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-search/src/lib.rs           3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sig/src/lib.rs              3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sync/src/lib.rs             3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-storage-s3/src/lib.rs           3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-storage/src/lib.rs           1196                47    96.07%          77                 1    98.70%         578                 3    99.48%           0                 0         -
roci-telemetry/src/lib.rs           13                 0   100.00%           3                 0   100.00%           9                 0   100.00%           0                 0         -
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                             4199                52    98.76%         257                 2    99.22%        2573                 4    99.84%           0                 0         -
```
