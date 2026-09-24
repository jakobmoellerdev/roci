# Coverage

Line coverage is enforced at a **95%** floor by the `coverage`
step of the `CI` workflow and the pre-commit hook (lcov line metric), excluding
the thin binary entrypoint `crates/roci-cli/src/main.rs` (a `#[tokio::main]`
shim over the fully-covered library). Any uncovered lines are listed at gate
time for triage; the few that remain are unreachable-in-CI defensive
syscall-error arms in the beneath-root storage path.

Current line coverage: **97.99%** (4434/4525 lines).

Regenerate with `just coverage` (or on every commit via the pre-commit hook).
Inspect region-level gaps with `just coverage-report`.

```
Filename                                        Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
roci-cli/src/lib.rs                                1241                25    97.99%          79                 6    92.41%         665                 7    98.95%           0                 0         -
roci-cli/src/main.rs                                 26                 4    84.62%           5                 1    80.00%          21                 3    85.71%           0                 0         -
roci-cluster/src/lib.rs                               3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-config/src/lib.rs                              262                 3    98.85%          23                 0   100.00%         230                 0   100.00%           0                 0         -
roci-core/src/blobs.rs                               84                 0   100.00%           7                 0   100.00%          67                 0   100.00%           0                 0         -
roci-core/src/error.rs                              254                 2    99.21%          25                 0   100.00%         179                 1    99.44%           0                 0         -
roci-core/src/http_util.rs                          152                 0   100.00%          12                 0   100.00%          80                 0   100.00%           0                 0         -
roci-core/src/lib.rs                                224                 2    99.11%          18                 0   100.00%         136                 1    99.26%           0                 0         -
roci-core/src/listing.rs                            140                 2    98.57%           9                 0   100.00%          87                 0   100.00%           0                 0         -
roci-core/src/manifests.rs                          259                 1    99.61%          29                 0   100.00%         186                 0   100.00%           0                 0         -
roci-core/src/names.rs                              156                 0   100.00%          13                 0   100.00%         111                 0   100.00%           0                 0         -
roci-core/src/ratelimit.rs                           93                 1    98.92%           7                 0   100.00%          69                 0   100.00%           0                 0         -
roci-core/src/routes.rs                             211                 4    98.10%           7                 0   100.00%          96                 0   100.00%           0                 0         -
roci-core/src/uploads.rs                            107                 0   100.00%          16                 0   100.00%          81                 0   100.00%           0                 0         -
roci-ext-scan/src/lib.rs                              3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-search/src/lib.rs                            3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sig/src/lib.rs                               3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sync/src/lib.rs                              3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-storage-s3/src/lib.rs                            3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-storage/src/beneath.rs                         394                44    88.83%          28                 0   100.00%         237                22    90.72%           0                 0         -
roci-storage/src/cache.rs                           304                 0   100.00%          15                 0   100.00%         112                 0   100.00%           0                 0         -
roci-storage/src/digest.rs                          112                 1    99.11%          15                 0   100.00%          74                 0   100.00%           0                 0         -
roci-storage/src/error.rs                             5                 0   100.00%           1                 0   100.00%           5                 0   100.00%           0                 0         -
roci-storage/src/filter.rs                          169                 0   100.00%          12                 0   100.00%          83                 0   100.00%           0                 0         -
roci-storage/src/fs_storage/index.rs                690                62    91.01%          44                 6    86.36%         350                24    93.14%           0                 0         -
roci-storage/src/fs_storage/mod.rs                  257                14    94.55%          13                 0   100.00%         130                 4    96.92%           0                 0         -
roci-storage/src/fs_storage/paths.rs                100                 8    92.00%          12                 0   100.00%          44                 0   100.00%           0                 0         -
roci-storage/src/fs_storage/storage_impl.rs         857               105    87.75%          50                 4    92.00%         437                20    95.42%           0                 0         -
roci-storage/src/layout.rs                          160                 1    99.38%          24                 0   100.00%         101                 0   100.00%           0                 0         -
roci-storage/src/metadata.rs                       1348                18    98.66%          70                 0   100.00%         663                 1    99.85%           0                 0         -
roci-storage/src/publish.rs                         296                96    67.57%          13                 1    92.31%         177                44    75.14%           0                 0         -
roci-telemetry/src/lib.rs                           244                18    92.62%          14                 1    92.86%         151                 1    99.34%           0                 0         -
roci-telemetry/src/metrics.rs                       330                 2    99.39%          25                 0   100.00%         198                 0   100.00%           0                 0         -
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                                              8493               413    95.14%         592                19    96.79%        4788               128    97.33%           0                 0         -
```
