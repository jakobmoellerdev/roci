# Coverage

Line coverage is enforced at a **95%** floor by the `coverage`
step of the `CI` workflow and the pre-commit hook (lcov line metric), excluding
the thin binary entrypoint `crates/roci-cli/src/main.rs` (a `#[tokio::main]`
shim over the fully-covered library). Any uncovered lines are listed at gate
time for triage; the few that remain are unreachable-in-CI defensive
syscall-error arms in the beneath-root storage path.

Current line coverage: **97.56%** (20039/20540 lines).

Regenerate with `just coverage` (or on every commit via the pre-commit hook).
Inspect region-level gaps with `just coverage-report`.

```
Filename                                        Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
roci-cli/src/auth_tests.rs                          686                 7    98.98%          32                 1    96.88%         336                 1    99.70%           0                 0         -
roci-cli/src/lib.rs                                4781               115    97.59%         310                22    92.90%        2687                42    98.44%           0                 0         -
roci-cli/src/main.rs                                 68                 9    86.76%          12                 2    83.33%          50                 6    88.00%           0                 0         -
roci-cluster/src/lib.rs                               3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-config/src/lib.rs                             1707                15    99.12%         122                 1    99.18%        1647                 4    99.76%           0                 0         -
roci-core/src/auth/bearer.rs                        619                 7    98.87%          26                 0   100.00%         320                 1    99.69%           0                 0         -
roci-core/src/auth/cache.rs                         169                 0   100.00%           6                 0   100.00%          83                 0   100.00%           0                 0         -
roci-core/src/auth/htpasswd.rs                      179                 4    97.77%          15                 0   100.00%          94                 0   100.00%           0                 0         -
roci-core/src/auth/identity.rs                      110                 0   100.00%           9                 0   100.00%          56                 0   100.00%           0                 0         -
roci-core/src/auth/ldap.rs                          170                 5    97.06%          11                 0   100.00%         105                 0   100.00%           0                 0         -
roci-core/src/auth/middleware.rs                     47                 0   100.00%           5                 0   100.00%          29                 0   100.00%           0                 0         -
roci-core/src/auth/mod.rs                           471                 5    98.94%          43                 1    97.67%         310                 1    99.68%           0                 0         -
roci-core/src/auth/policy.rs                        411                 0   100.00%          23                 0   100.00%         245                 0   100.00%           0                 0         -
roci-core/src/blobs.rs                              168                 0   100.00%          14                 0   100.00%         134                 0   100.00%           0                 0         -
roci-core/src/error.rs                              790                13    98.35%          68                 0   100.00%         537                 6    98.88%           0                 0         -
roci-core/src/http_util.rs                          152                 0   100.00%          12                 0   100.00%          80                 0   100.00%           0                 0         -
roci-core/src/lib.rs                                469                 3    99.36%          38                 0   100.00%         288                 2    99.31%           0                 0         -
roci-core/src/listing.rs                            140                 2    98.57%           9                 0   100.00%          87                 0   100.00%           0                 0         -
roci-core/src/manifests.rs                          527                 1    99.81%          60                 0   100.00%         382                 0   100.00%           0                 0         -
roci-core/src/names.rs                              156                 0   100.00%          13                 0   100.00%         111                 0   100.00%           0                 0         -
roci-core/src/ratelimit.rs                           93                 1    98.92%           7                 0   100.00%          69                 0   100.00%           0                 0         -
roci-core/src/routes.rs                             453                12    97.35%          15                 0   100.00%         207                 0   100.00%           0                 0         -
roci-core/src/uploads.rs                            241                 0   100.00%          35                 0   100.00%         187                 0   100.00%           0                 0         -
roci-ext-scan/src/lib.rs                              3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-search/src/lib.rs                            3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sig/src/lib.rs                               3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sync/src/lib.rs                              3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-storage-s3/src/client.rs                       134                 6    95.52%          11                 1    90.91%         107                 6    94.39%           0                 0         -
roci-storage-s3/src/keys.rs                         117                 2    98.29%          12                 0   100.00%          64                 0   100.00%           0                 0         -
roci-storage-s3/src/lib.rs                          146                 6    95.89%          12                 0   100.00%          85                 0   100.00%           0                 0         -
roci-storage-s3/src/storage_impl.rs                2504               531    78.79%         156                33    78.85%        1345               267    80.15%           0                 0         -
roci-storage-s3/src/tests.rs                       4346                33    99.24%         197                 1    99.49%        2616                 8    99.69%           0                 0         -
roci-storage-s3/src/uploads.rs                      348                42    87.93%          28                 2    92.86%         194                15    92.27%           0                 0         -
roci-storage/src/beneath.rs                         678                65    90.41%          48                 0   100.00%         397                28    92.95%           0                 0         -
roci-storage/src/bufpool.rs                          96                 6    93.75%           9                 1    88.89%          55                 7    87.27%           0                 0         -
roci-storage/src/cache.rs                           304                 0   100.00%          15                 0   100.00%         112                 0   100.00%           0                 0         -
roci-storage/src/dedupe.rs                          114                 0   100.00%          10                 0   100.00%          54                 0   100.00%           0                 0         -
roci-storage/src/digest.rs                          188                 2    98.94%          25                 0   100.00%         127                 0   100.00%           0                 0         -
roci-storage/src/error.rs                            29                 0   100.00%           5                 0   100.00%          25                 0   100.00%           0                 0         -
roci-storage/src/filter.rs                          169                 0   100.00%          12                 0   100.00%          83                 0   100.00%           0                 0         -
roci-storage/src/fs_storage/gc.rs                   601                67    88.85%          26                 1    96.15%         318                40    87.42%           0                 0         -
roci-storage/src/fs_storage/index.rs               1493               161    89.22%         106                18    83.02%         752                58    92.29%           0                 0         -
roci-storage/src/fs_storage/lifecycle.rs             98                 7    92.86%           6                 0   100.00%          61                 3    95.08%           0                 0         -
roci-storage/src/fs_storage/maintenance.rs          136                46    66.18%          15                 6    60.00%         100                31    69.00%           0                 0         -
roci-storage/src/fs_storage/mod.rs                  781                49    93.73%          49                 1    97.96%         414                20    95.17%           0                 0         -
roci-storage/src/fs_storage/paths.rs                100                 8    92.00%          12                 0   100.00%          44                 0   100.00%           0                 0         -
roci-storage/src/fs_storage/scrub.rs               1364                47    96.55%          85                 1    98.82%         763                29    96.20%           0                 0         -
roci-storage/src/fs_storage/storage_impl.rs        3198               388    87.87%         157                 9    94.27%        1588               110    93.07%           0                 0         -
roci-storage/src/gc.rs                              554                 7    98.74%          60                 1    98.33%         295                 5    98.31%           0                 0         -
roci-storage/src/layout.rs                          927                28    96.98%          88                 0   100.00%         509                11    97.84%           0                 0         -
roci-storage/src/metadata.rs                       1348                18    98.66%          70                 0   100.00%         663                 1    99.85%           0                 0         -
roci-storage/src/metadata/log.rs                   6744               141    97.91%         243                 2    99.18%        3158                32    98.99%           0                 0         -
roci-storage/src/metadata/mod.rs                   1260                 4    99.68%          32                 0   100.00%         654                 2    99.69%           0                 0         -
roci-storage/src/metadata/redb.rs                  1974               137    93.06%          54                 1    98.15%         922                24    97.40%           0                 0         -
roci-storage/src/metadata/snapshot.rs               601                10    98.34%          24                 0   100.00%         255                 1    99.61%           0                 0         -
roci-storage/src/metadata/wal_hmac.rs               210                 1    99.52%          13                 0   100.00%         105                 0   100.00%           0                 0         -
roci-storage/src/publish.rs                         911               299    67.18%          37                 2    94.59%         544               136    75.00%           0                 0         -
roci-storage/src/quota.rs                           556                 8    98.56%          39                 0   100.00%         286                 1    99.65%           0                 0         -
roci-storage/src/routing.rs                        1168                 0   100.00%          77                 0   100.00%         553                 0   100.00%           0                 0         -
roci-storage/src/storage.rs                         153                19    87.58%          20                 2    90.00%         119                20    83.19%           0                 0         -
roci-storage/src/upload_body.rs                     160                10    93.75%          16                 2    87.50%         109                 6    94.50%           0                 0         -
roci-telemetry/src/lib.rs                           732                54    92.62%          42                 3    92.86%         453                 3    99.34%           0                 0         -
roci-telemetry/src/metrics.rs                      1065                31    97.09%          71                 1    98.59%         658                16    97.57%           0                 0         -
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                                             47929              2432    94.93%        2772               115    95.85%       26646               943    96.46%           0                 0         -
```
