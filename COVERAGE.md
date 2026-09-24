# Coverage

Line coverage is enforced at a **95%** floor by the `coverage`
step of the `CI` workflow and the pre-commit hook (lcov line metric), excluding
the thin binary entrypoint `crates/roci-cli/src/main.rs` (a `#[tokio::main]`
shim over the fully-covered library). Any uncovered lines are listed at gate
time for triage; the few that remain are unreachable-in-CI defensive
syscall-error arms in the beneath-root storage path.

Current line coverage: **96.61%** (12114/12539 lines).

Regenerate with `just coverage` (or on every commit via the pre-commit hook).
Inspect region-level gaps with `just coverage-report`.

```
Filename                                        Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
roci-cli/src/lib.rs                                1867                48    97.43%         113                 8    92.92%        1024                16    98.44%           0                 0         -
roci-cli/src/main.rs                                 26                 4    84.62%           5                 1    80.00%          21                 3    85.71%           0                 0         -
roci-cluster/src/lib.rs                               3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-config/src/lib.rs                              550                 5    99.09%          42                 1    97.62%         532                 2    99.62%           0                 0         -
roci-core/src/blobs.rs                               84                 0   100.00%           7                 0   100.00%          67                 0   100.00%           0                 0         -
roci-core/src/error.rs                              299                 2    99.33%          27                 0   100.00%         209                 1    99.52%           0                 0         -
roci-core/src/http_util.rs                          152                 0   100.00%          12                 0   100.00%          80                 0   100.00%           0                 0         -
roci-core/src/lib.rs                                224                 2    99.11%          18                 0   100.00%         136                 1    99.26%           0                 0         -
roci-core/src/listing.rs                            140                 2    98.57%           9                 0   100.00%          87                 0   100.00%           0                 0         -
roci-core/src/manifests.rs                          238                 0   100.00%          28                 0   100.00%         174                 0   100.00%           0                 0         -
roci-core/src/names.rs                              156                 0   100.00%          13                 0   100.00%         111                 0   100.00%           0                 0         -
roci-core/src/ratelimit.rs                           93                 1    98.92%           7                 0   100.00%          69                 0   100.00%           0                 0         -
roci-core/src/routes.rs                             211                 4    98.10%           7                 0   100.00%          96                 0   100.00%           0                 0         -
roci-core/src/uploads.rs                            107                 0   100.00%          16                 0   100.00%          81                 0   100.00%           0                 0         -
roci-ext-scan/src/lib.rs                              3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-search/src/lib.rs                            3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sig/src/lib.rs                               3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sync/src/lib.rs                              3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-storage-s3/src/client.rs                        76                 6    92.11%           5                 1    80.00%          72                 6    91.67%           0                 0         -
roci-storage-s3/src/keys.rs                         117                 2    98.29%          12                 0   100.00%          64                 0   100.00%           0                 0         -
roci-storage-s3/src/lib.rs                          105                 5    95.24%           7                 0   100.00%          65                 0   100.00%           0                 0         -
roci-storage-s3/src/storage_impl.rs                2357               499    78.83%         153                34    77.78%        1282               250    80.50%           0                 0         -
roci-storage-s3/src/uploads.rs                      344                40    88.37%          26                 1    96.15%         191                12    93.72%           0                 0         -
roci-storage/src/beneath.rs                         394                26    93.40%          28                 0   100.00%         237                 5    97.89%           0                 0         -
roci-storage/src/cache.rs                           304                 0   100.00%          15                 0   100.00%         112                 0   100.00%           0                 0         -
roci-storage/src/dedupe.rs                          114                 0   100.00%          10                 0   100.00%          54                 0   100.00%           0                 0         -
roci-storage/src/digest.rs                          117                 1    99.15%          15                 0   100.00%          82                 0   100.00%           0                 0         -
roci-storage/src/error.rs                            12                 0   100.00%           2                 0   100.00%          10                 0   100.00%           0                 0         -
roci-storage/src/fault.rs                             2                 0   100.00%           1                 0   100.00%           1                 0   100.00%           0                 0         -
roci-storage/src/filter.rs                          169                 0   100.00%          12                 0   100.00%          83                 0   100.00%           0                 0         -
roci-storage/src/fs_storage/gc.rs                   530                60    88.68%          24                 1    95.83%         272                37    86.40%           0                 0         -
roci-storage/src/fs_storage/index.rs                411                54    86.86%          36                 7    80.56%         220                19    91.36%           0                 0         -
roci-storage/src/fs_storage/lifecycle.rs             98                 7    92.86%           6                 0   100.00%          61                 3    95.08%           0                 0         -
roci-storage/src/fs_storage/maintenance.rs           79                21    73.42%           9                 3    66.67%          57                14    75.44%           0                 0         -
roci-storage/src/fs_storage/mod.rs                  248                10    95.97%          17                 0   100.00%         136                 5    96.32%           0                 0         -
roci-storage/src/fs_storage/paths.rs                100                 8    92.00%          12                 0   100.00%          44                 0   100.00%           0                 0         -
roci-storage/src/fs_storage/scrub.rs               1165                39    96.65%          78                 1    98.72%         661                19    97.13%           0                 0         -
roci-storage/src/fs_storage/storage_impl.rs        1087               123    88.68%          52                 2    96.15%         531                39    92.66%           0                 0         -
roci-storage/src/gc.rs                              341                 2    99.41%          35                 0   100.00%         179                 1    99.44%           0                 0         -
roci-storage/src/layout.rs                          543                22    95.95%          42                 0   100.00%         284                 9    96.83%           0                 0         -
roci-storage/src/metadata/log.rs                   5301               108    97.96%         173                 1    99.42%        2447                25    98.98%           0                 0         -
roci-storage/src/metadata/mod.rs                   1239                 2    99.84%          30                 0   100.00%         641                 0   100.00%           0                 0         -
roci-storage/src/metadata/redb.rs                  1974               137    93.06%          54                 1    98.15%         922                24    97.40%           0                 0         -
roci-storage/src/metadata/snapshot.rs               601                10    98.34%          24                 0   100.00%         255                 1    99.61%           0                 0         -
roci-storage/src/metadata/wal_hmac.rs               210                 1    99.52%          13                 0   100.00%         105                 0   100.00%           0                 0         -
roci-storage/src/publish.rs                         395                58    85.32%          15                 0   100.00%         240                23    90.42%           0                 0         -
roci-storage/src/quota.rs                           280                 3    98.93%          21                 0   100.00%         154                 0   100.00%           0                 0         -
roci-storage/src/routing.rs                        1163                 0   100.00%          77                 0   100.00%         535                 0   100.00%           0                 0         -
roci-storage/src/storage.rs                          37                 5    86.49%           7                 0   100.00%          40                 5    87.50%           0                 0         -
roci-telemetry/src/lib.rs                           244                18    92.62%          14                 1    92.86%         151                 1    99.34%           0                 0         -
roci-telemetry/src/metrics.rs                       393                 2    99.49%          30                 0   100.00%         253                 0   100.00%           0                 0         -
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                                             24712              1337    94.59%        1364                63    95.38%       13143               521    96.04%           0                 0         -
```
