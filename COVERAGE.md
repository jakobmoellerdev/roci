# Coverage

Line coverage is enforced at a **95%** floor by the `coverage`
step of the `CI` workflow and the pre-commit hook (lcov line metric), excluding
the thin binary entrypoint `crates/roci-cli/src/main.rs` (a `#[tokio::main]`
shim over the fully-covered library). Any uncovered lines are listed at gate
time for triage; the few that remain are unreachable-in-CI defensive
syscall-error arms in the beneath-root storage path.

Current line coverage: **97.08%** (19417/20002 lines).

Regenerate with `just coverage` (or on every commit via the pre-commit hook).
Inspect region-level gaps with `just coverage-report`.

```
Filename                                        Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
roci-cli/src/auth_tests.rs                          656                 7    98.93%          27                 1    96.30%         312                 1    99.68%           0                 0         -
roci-cli/src/lib.rs                                2000                66    96.70%         119                12    89.92%        1165                24    97.94%           0                 0         -
roci-cli/src/main.rs                                 52                 8    84.62%           8                 1    87.50%          33                 4    87.88%           0                 0         -
roci-config/src/lib.rs                             1138                 6    99.47%          71                 1    98.59%        1072                 1    99.91%           0                 0         -
roci-core/src/auth/bearer.rs                        617                 7    98.87%          26                 0   100.00%         318                 1    99.69%           0                 0         -
roci-core/src/auth/cache.rs                          81                 0   100.00%           4                 0   100.00%          60                 0   100.00%           0                 0         -
roci-core/src/auth/htpasswd.rs                      110                 1    99.09%          12                 0   100.00%          59                 0   100.00%           0                 0         -
roci-core/src/auth/identity.rs                      110                 0   100.00%           9                 0   100.00%          56                 0   100.00%           0                 0         -
roci-core/src/auth/ldap.rs                          170                 5    97.06%          11                 0   100.00%         105                 0   100.00%           0                 0         -
roci-core/src/auth/middleware.rs                     47                 0   100.00%           5                 0   100.00%          29                 0   100.00%           0                 0         -
roci-core/src/auth/mod.rs                           432                 5    98.84%          40                 1    97.50%         292                 1    99.66%           0                 0         -
roci-core/src/auth/policy.rs                        411                 0   100.00%          23                 0   100.00%         244                 0   100.00%           0                 0         -
roci-core/src/blobs.rs                               93                 0   100.00%          10                 0   100.00%          81                 0   100.00%           0                 0         -
roci-core/src/conn_close.rs                          91                 4    95.60%           8                 1    87.50%          61                 3    95.08%           0                 0         -
roci-core/src/error.rs                              322                 6    98.14%          26                 0   100.00%         270                 2    99.26%           0                 0         -
roci-core/src/http_util.rs                          152                 0   100.00%          12                 0   100.00%          80                 0   100.00%           0                 0         -
roci-core/src/lib.rs                                332                 1    99.70%          28                 0   100.00%         221                 1    99.55%           0                 0         -
roci-core/src/listing.rs                            140                 2    98.57%           9                 0   100.00%          87                 0   100.00%           0                 0         -
roci-core/src/manifests.rs                          248                 0   100.00%          31                 0   100.00%         188                 0   100.00%           0                 0         -
roci-core/src/names.rs                              141                11    92.20%          12                 3    75.00%         105                 9    91.43%           0                 0         -
roci-core/src/ratelimit.rs                          383                 1    99.74%          25                 0   100.00%         263                 0   100.00%           0                 0         -
roci-core/src/routes.rs                             242                 8    96.69%           8                 0   100.00%         114                 0   100.00%           0                 0         -
roci-core/src/uploads.rs                            134                 0   100.00%          19                 0   100.00%         106                 0   100.00%           0                 0         -
roci-storage-s3/src/client.rs                       194                25    87.11%          15                 3    80.00%         149                22    85.23%           0                 0         -
roci-storage-s3/src/keys.rs                         117                 2    98.29%          12                 0   100.00%          64                 0   100.00%           0                 0         -
roci-storage-s3/src/lib.rs                           88                 6    93.18%           4                 0   100.00%          57                 0   100.00%           0                 0         -
roci-storage-s3/src/storage_impl.rs                2295               400    82.57%         141                26    81.56%        1253               191    84.76%           0                 0         -
roci-storage-s3/src/tests.rs                       4649                38    99.18%         266                 1    99.62%        2624                10    99.62%           0                 0         -
roci-storage-s3/src/uploads.rs                      341                42    87.68%          26                 2    92.31%         191                15    92.15%           0                 0         -
roci-storage/src/beneath.rs                         439                49    88.84%          32                 0   100.00%         274                15    94.53%           0                 0         -
roci-storage/src/bufpool.rs                          96                 6    93.75%           9                 1    88.89%          55                 7    87.27%           0                 0         -
roci-storage/src/cache.rs                           371                 0   100.00%          18                 0   100.00%         132                 0   100.00%           0                 0         -
roci-storage/src/dedupe.rs                          125                 0   100.00%          12                 0   100.00%          63                 0   100.00%           0                 0         -
roci-storage/src/digest.rs                          159                 5    96.86%          18                 0   100.00%         111                 1    99.10%           0                 0         -
roci-storage/src/error.rs                            12                 0   100.00%           2                 0   100.00%          10                 0   100.00%           0                 0         -
roci-storage/src/filter.rs                          169                 0   100.00%          12                 0   100.00%          82                 0   100.00%           0                 0         -
roci-storage/src/fs_storage/fast_restart.rs         564                56    90.07%          22                 2    90.91%         300                21    93.00%           0                 0         -
roci-storage/src/fs_storage/gc.rs                   509                57    88.80%          26                 1    96.15%         274                35    87.23%           0                 0         -
roci-storage/src/fs_storage/index.rs                466                44    90.56%          39                 5    87.18%         255                14    94.51%           0                 0         -
roci-storage/src/fs_storage/lifecycle.rs             56                 2    96.43%           6                 0   100.00%          39                 0   100.00%           0                 0         -
roci-storage/src/fs_storage/maintenance.rs           63                28    55.56%           8                 3    62.50%          45                19    57.78%           0                 0         -
roci-storage/src/fs_storage/mod.rs                  247                14    94.33%          16                 0   100.00%         148                 5    96.62%           0                 0         -
roci-storage/src/fs_storage/paths.rs                100                 8    92.00%          12                 0   100.00%          44                 0   100.00%           0                 0         -
roci-storage/src/fs_storage/scrub.rs               1318                47    96.43%          79                 1    98.73%         817                29    96.45%           0                 0         -
roci-storage/src/fs_storage/storage_impl.rs        1575               155    90.16%          65                 1    98.46%         861                62    92.80%           0                 0         -
roci-storage/src/gc.rs                              602                11    98.17%          58                 2    96.55%         327                 6    98.17%           0                 0         -
roci-storage/src/layout.rs                         1000                26    97.40%          71                 0   100.00%         530                12    97.74%           0                 0         -
roci-storage/src/lifecycle.rs                        64                 5    92.19%           2                 0   100.00%          48                 3    93.75%           0                 0         -
roci-storage/src/lock_map.rs                         54                 0   100.00%           7                 0   100.00%          32                 0   100.00%           0                 0         -
roci-storage/src/metadata/lmdb.rs                  2271               138    93.92%          83                 3    96.39%        1131                41    96.37%           0                 0         -
roci-storage/src/metadata/log.rs                   5303               129    97.57%         181                 3    98.34%        2448                38    98.45%           0                 0         -
roci-storage/src/metadata/mod.rs                   3201                88    97.25%         110                 6    94.55%        1758                37    97.90%           0                 0         -
roci-storage/src/metadata/snapshot.rs               534                10    98.13%          17                 0   100.00%         258                 1    99.61%           0                 0         -
roci-storage/src/metadata/wal_hmac.rs               198                 1    99.49%          12                 0   100.00%          99                 0   100.00%           0                 0         -
roci-storage/src/publish.rs                         350               112    68.00%          14                 1    92.86%         223                56    74.89%           0                 0         -
roci-storage/src/quota.rs                           362                 4    98.90%          26                 0   100.00%         192                 0   100.00%           0                 0         -
roci-storage/src/routing.rs                         400                14    96.50%          32                 2    93.75%         192                12    93.75%           0                 0         -
roci-storage/src/storage.rs                         170                 9    94.71%          18                 1    94.44%         115                 7    93.91%           0                 0         -
roci-storage/src/upload_body.rs                     305                 8    97.38%          24                 0   100.00%         196                 2    98.98%           0                 0         -
roci-telemetry/src/lib.rs                           244                18    92.62%          14                 1    92.86%         149                 1    99.33%           0                 0         -
roci-telemetry/src/metrics.rs                       517                 2    99.61%          40                 0   100.00%         360                 0   100.00%           0                 0         -
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                                             37630              1697    95.49%        2092                85    95.94%       21227               709    96.66%           0                 0         -
```
