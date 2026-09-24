# Coverage

Line coverage is enforced at a **95%** floor by the `coverage`
step of the `CI` workflow and the pre-commit hook (lcov line metric), excluding
the thin binary entrypoint `crates/roci-cli/src/main.rs` (a `#[tokio::main]`
shim over the fully-covered library). Any uncovered lines are listed at gate
time for triage; the few that remain are unreachable-in-CI defensive
syscall-error arms in the beneath-root storage path.

Current line coverage: **98.03%** (3439/3508 lines).

Regenerate with `just coverage` (or on every commit via the pre-commit hook).
Inspect region-level gaps with `just coverage-report`.

```
Filename                                        Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
roci-cli/src/lib.rs                                 171                 5    97.08%          15                 1    93.33%         107                 1    99.07%           0                 0         -
roci-cli/src/main.rs                                 17                 0   100.00%           4                 0   100.00%          15                 0   100.00%           0                 0         -
roci-cluster/src/lib.rs                               3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-config/src/lib.rs                               59                 0   100.00%           9                 0   100.00%          40                 0   100.00%           0                 0         -
roci-core/src/blobs.rs                              151                 2    98.68%           7                 0   100.00%          90                 0   100.00%           0                 0         -
roci-core/src/error.rs                              240                 2    99.17%          25                 0   100.00%         173                 1    99.42%           0                 0         -
roci-core/src/http_util.rs                          152                 0   100.00%          12                 0   100.00%          80                 0   100.00%           0                 0         -
roci-core/src/lib.rs                                 70                 0   100.00%          10                 0   100.00%          58                 0   100.00%           0                 0         -
roci-core/src/listing.rs                            132                 3    97.73%           9                 0   100.00%          88                 1    98.86%           0                 0         -
roci-core/src/manifests.rs                          424                 1    99.76%          29                 0   100.00%         267                 0   100.00%           0                 0         -
roci-core/src/names.rs                              156                 0   100.00%          13                 0   100.00%         111                 0   100.00%           0                 0         -
roci-core/src/routes.rs                             211                 4    98.10%           7                 0   100.00%          96                 0   100.00%           0                 0         -
roci-core/src/uploads.rs                            175                 0   100.00%          16                 0   100.00%         109                 0   100.00%           0                 0         -
roci-ext-scan/src/lib.rs                              3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-search/src/lib.rs                            3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sig/src/lib.rs                               3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sync/src/lib.rs                              3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-storage-s3/src/lib.rs                            3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-storage/src/beneath.rs                         394                38    90.36%          28                 0   100.00%         237                18    92.41%           0                 0         -
roci-storage/src/cache.rs                           304                 0   100.00%          15                 0   100.00%         112                 0   100.00%           0                 0         -
roci-storage/src/digest.rs                          112                 1    99.11%          15                 0   100.00%          74                 0   100.00%           0                 0         -
roci-storage/src/error.rs                             5                 0   100.00%           1                 0   100.00%           5                 0   100.00%           0                 0         -
roci-storage/src/fault.rs                             2                 0   100.00%           1                 0   100.00%           1                 0   100.00%           0                 0         -
roci-storage/src/filter.rs                          169                 0   100.00%          12                 0   100.00%          83                 0   100.00%           0                 0         -
roci-storage/src/fs_storage/index.rs                690                62    91.01%          44                 6    86.36%         350                24    93.14%           0                 0         -
roci-storage/src/fs_storage/mod.rs                  212                 9    95.75%          12                 0   100.00%         107                 3    97.20%           0                 0         -
roci-storage/src/fs_storage/paths.rs                100                 8    92.00%          12                 0   100.00%          44                 0   100.00%           0                 0         -
roci-storage/src/fs_storage/storage_impl.rs         857               105    87.75%          50                 4    92.00%         437                20    95.42%           0                 0         -
roci-storage/src/layout.rs                          160                 1    99.38%          24                 0   100.00%         101                 0   100.00%           0                 0         -
roci-storage/src/metadata.rs                       1348                18    98.66%          70                 0   100.00%         663                 1    99.85%           0                 0         -
roci-storage/src/publish.rs                         381                72    81.10%          14                 0   100.00%         227                28    87.67%           0                 0         -
roci-telemetry/src/lib.rs                            33                 0   100.00%           5                 0   100.00%          22                 0   100.00%           0                 0         -
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                                              6743               331    95.09%         465                11    97.63%        3715                97    97.39%           0                 0         -
```
