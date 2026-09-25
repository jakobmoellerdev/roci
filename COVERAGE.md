# Coverage

Line coverage is enforced at a **95%** floor by the `coverage`
step of the `CI` workflow and the pre-commit hook (lcov line metric), excluding
the thin binary entrypoint `crates/roci-cli/src/main.rs` (a `#[tokio::main]`
shim over the fully-covered library). Any uncovered lines are listed at gate
time for triage; the few that remain are unreachable-in-CI defensive
syscall-error arms in the beneath-root storage path.

Current line coverage: **96.62%** (16573/17152 lines).

Regenerate with `just coverage` (or on every commit via the pre-commit hook).
Inspect region-level gaps with `just coverage-report`.

```
Filename                                        Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
roci-cli/src/lib.rs                                3638                78    97.86%         228                16    92.98%        2014                34    98.31%           0                 0         -
roci-cli/src/main.rs                                 66                 9    86.36%          12                 2    83.33%          50                 6    88.00%           0                 0         -
roci-cluster/src/lib.rs                               3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-config/src/lib.rs                              876               181    79.34%          71                14    80.28%         847               155    81.70%           0                 0         -
roci-core/src/blobs.rs                               84                 0   100.00%           7                 0   100.00%          67                 0   100.00%           0                 0         -
roci-core/src/error.rs                              302                 5    98.34%          27                 0   100.00%         211                 3    98.58%           0                 0         -
roci-core/src/http_util.rs                          152                 0   100.00%          12                 0   100.00%          80                 0   100.00%           0                 0         -
roci-core/src/lib.rs                                224                 2    99.11%          18                 0   100.00%         136                 1    99.26%           0                 0         -
roci-core/src/listing.rs                            140                 2    98.57%           9                 0   100.00%          87                 0   100.00%           0                 0         -
roci-core/src/manifests.rs                          238                 0   100.00%          28                 0   100.00%         174                 0   100.00%           0                 0         -
roci-core/src/names.rs                              156                 0   100.00%          13                 0   100.00%         111                 0   100.00%           0                 0         -
roci-core/src/ratelimit.rs                           93                 1    98.92%           7                 0   100.00%          69                 0   100.00%           0                 0         -
roci-core/src/routes.rs                             211                 4    98.10%           7                 0   100.00%          96                 0   100.00%           0                 0         -
roci-core/src/uploads.rs                            234                 0   100.00%          34                 0   100.00%         180                 0   100.00%           0                 0         -
roci-ext-scan/src/lib.rs                              3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-search/src/lib.rs                            3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sig/src/lib.rs                               3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sync/src/lib.rs                              3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-storage-s3/src/client.rs                        76                 6    92.11%           5                 1    80.00%          72                 6    91.67%           0                 0         -
roci-storage-s3/src/keys.rs                         117                 2    98.29%          12                 0   100.00%          64                 0   100.00%           0                 0         -
roci-storage-s3/src/lib.rs                          143                 6    95.80%          11                 0   100.00%          82                 0   100.00%           0                 0         -
roci-storage-s3/src/storage_impl.rs                4782              1033    78.40%         286                61    78.67%        2570               527    79.49%           0                 0         -
roci-storage-s3/src/tests.rs                       7934                57    99.28%         353                 1    99.72%        4690                10    99.79%           0                 0         -
roci-storage-s3/src/uploads.rs                      635                76    88.03%          48                 3    93.75%         355                27    92.39%           0                 0         -
roci-storage/src/beneath.rs                         678                52    92.33%          48                 0   100.00%         393                15    96.18%           0                 0         -
roci-storage/src/bufpool.rs                          96                 6    93.75%           9                 1    88.89%          55                 7    87.27%           0                 0         -
roci-storage/src/cache.rs                           304                 0   100.00%          15                 0   100.00%         112                 0   100.00%           0                 0         -
roci-storage/src/dedupe.rs                          114                 0   100.00%          10                 0   100.00%          54                 0   100.00%           0                 0         -
roci-storage/src/digest.rs                          142                 1    99.30%          19                 0   100.00%          99                 0   100.00%           0                 0         -
roci-storage/src/error.rs                            12                 0   100.00%           2                 0   100.00%          10                 0   100.00%           0                 0         -
roci-storage/src/filter.rs                          169                 0   100.00%          12                 0   100.00%          83                 0   100.00%           0                 0         -
roci-storage/src/fs_storage/gc.rs                   601                67    88.85%          26                 1    96.15%         318                40    87.42%           0                 0         -
roci-storage/src/fs_storage/index.rs                416                54    87.02%          37                 7    81.08%         223                19    91.48%           0                 0         -
roci-storage/src/fs_storage/lifecycle.rs             98                 7    92.86%           6                 0   100.00%          61                 3    95.08%           0                 0         -
roci-storage/src/fs_storage/maintenance.rs           79                21    73.42%           9                 3    66.67%          57                14    75.44%           0                 0         -
roci-storage/src/fs_storage/mod.rs                  440                17    96.14%          36                 0   100.00%         239                 7    97.07%           0                 0         -
roci-storage/src/fs_storage/paths.rs                100                 8    92.00%          12                 0   100.00%          44                 0   100.00%           0                 0         -
roci-storage/src/fs_storage/scrub.rs               1364                47    96.55%          85                 1    98.82%         763                29    96.20%           0                 0         -
roci-storage/src/fs_storage/storage_impl.rs        2482               260    89.52%         108                 4    96.30%        1208                87    92.80%           0                 0         -
roci-storage/src/gc.rs                              341                 2    99.41%          35                 0   100.00%         179                 1    99.44%           0                 0         -
roci-storage/src/layout.rs                          585                24    95.90%          46                 0   100.00%         305                11    96.39%           0                 0         -
roci-storage/src/metadata/log.rs                   5301               108    97.96%         173                 1    99.42%        2447                25    98.98%           0                 0         -
roci-storage/src/metadata/mod.rs                   1239                 2    99.84%          30                 0   100.00%         641                 0   100.00%           0                 0         -
roci-storage/src/metadata/redb.rs                  1974               137    93.06%          54                 1    98.15%         922                24    97.40%           0                 0         -
roci-storage/src/metadata/snapshot.rs               601                10    98.34%          24                 0   100.00%         255                 1    99.61%           0                 0         -
roci-storage/src/metadata/wal_hmac.rs               210                 1    99.52%          13                 0   100.00%         105                 0   100.00%           0                 0         -
roci-storage/src/publish.rs                         628               214    65.92%          26                 2    92.31%         382               104    72.77%           0                 0         -
roci-storage/src/quota.rs                           341                 3    99.12%          24                 0   100.00%         177                 0   100.00%           0                 0         -
roci-storage/src/routing.rs                        2231                 0   100.00%         134                 0   100.00%        1021                 0   100.00%           0                 0         -
roci-storage/src/storage.rs                         221                12    94.57%          26                 0   100.00%         152                 4    97.37%           0                 0         -
roci-storage/src/upload_body.rs                     160                10    93.75%          16                 2    87.50%         109                 6    94.50%           0                 0         -
roci-telemetry/src/lib.rs                           244                18    92.62%          14                 1    92.86%         151                 1    99.34%           0                 0         -
roci-telemetry/src/metrics.rs                       393                 2    99.49%          30                 0   100.00%         253                 0   100.00%           0                 0         -
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                                             41680              2545    93.89%        2272               122    94.63%       22788              1167    94.88%           0                 0         -
```
