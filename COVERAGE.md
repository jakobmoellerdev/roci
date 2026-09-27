# Coverage

Line coverage is enforced at a **95%** floor by the `coverage`
step of the `CI` workflow and the pre-commit hook (lcov line metric), excluding
the thin binary entrypoint `crates/roci-cli/src/main.rs` (a `#[tokio::main]`
shim over the fully-covered library). Any uncovered lines are listed at gate
time for triage; the few that remain are unreachable-in-CI defensive
syscall-error arms in the beneath-root storage path.

Current line coverage: **95.70%** (17549/18337 lines).

Regenerate with `just coverage` (or on every commit via the pre-commit hook).
Inspect region-level gaps with `just coverage-report`.

```
Filename                                        Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
roci-cli/src/auth_tests.rs                          656                 7    98.93%          27                 1    96.30%         312                 1    99.68%           0                 0         -
roci-cli/src/lib.rs                                1970                78    96.04%         117                13    88.89%        1152                35    96.96%           0                 0         -
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
roci-core/src/conn_close.rs                          64                14    78.12%           6                 2    66.67%          43                10    76.74%           0                 0         -
roci-core/src/error.rs                              288                10    96.53%          23                 0   100.00%         255                 7    97.25%           0                 0         -
roci-core/src/http_util.rs                          152                 0   100.00%          12                 0   100.00%          80                 0   100.00%           0                 0         -
roci-core/src/lib.rs                                332                 1    99.70%          28                 0   100.00%         221                 1    99.55%           0                 0         -
roci-core/src/listing.rs                            140                 2    98.57%           9                 0   100.00%          87                 0   100.00%           0                 0         -
roci-core/src/manifests.rs                          248                 0   100.00%          31                 0   100.00%         188                 0   100.00%           0                 0         -
roci-core/src/names.rs                              141                11    92.20%          12                 3    75.00%         105                 9    91.43%           0                 0         -
roci-core/src/ratelimit.rs                          372                 3    99.19%          24                 0   100.00%         255                 2    99.22%           0                 0         -
roci-core/src/routes.rs                             242                 8    96.69%           8                 0   100.00%         114                 0   100.00%           0                 0         -
roci-core/src/uploads.rs                            134                 0   100.00%          19                 0   100.00%         106                 0   100.00%           0                 0         -
roci-storage-s3/src/client.rs                       194                32    83.51%          15                 4    73.33%         149                28    81.21%           0                 0         -
roci-storage-s3/src/keys.rs                         117                 2    98.29%          12                 0   100.00%          64                 0   100.00%           0                 0         -
roci-storage-s3/src/lib.rs                           88                 6    93.18%           4                 0   100.00%          57                 0   100.00%           0                 0         -
roci-storage-s3/src/storage_impl.rs                2295               484    78.91%         141                31    78.01%        1253               241    80.77%           0                 0         -
roci-storage-s3/src/tests.rs                       2755                30    98.91%         158                 1    99.37%        1625                10    99.38%           0                 0         -
roci-storage-s3/src/uploads.rs                      341                42    87.68%          26                 2    92.31%         191                15    92.15%           0                 0         -
roci-storage/src/beneath.rs                         439                49    88.84%          32                 0   100.00%         274                15    94.53%           0                 0         -
roci-storage/src/bufpool.rs                          96                 6    93.75%           9                 1    88.89%          55                 7    87.27%           0                 0         -
roci-storage/src/cache.rs                           304                 0   100.00%          15                 0   100.00%         111                 0   100.00%           0                 0         -
roci-storage/src/dedupe.rs                          125                 0   100.00%          12                 0   100.00%          63                 0   100.00%           0                 0         -
roci-storage/src/digest.rs                          159                 5    96.86%          18                 0   100.00%         111                 1    99.10%           0                 0         -
roci-storage/src/error.rs                            12                 0   100.00%           2                 0   100.00%          10                 0   100.00%           0                 0         -
roci-storage/src/filter.rs                          169                 0   100.00%          12                 0   100.00%          82                 0   100.00%           0                 0         -
roci-storage/src/fs_storage/fast_restart.rs         497                60    87.93%          21                 2    90.48%         264                31    88.26%           0                 0         -
roci-storage/src/fs_storage/gc.rs                   509                63    87.62%          26                 1    96.15%         274                38    86.13%           0                 0         -
roci-storage/src/fs_storage/index.rs                466                62    86.70%          39                 7    82.05%         255                23    90.98%           0                 0         -
roci-storage/src/fs_storage/lifecycle.rs             56                 2    96.43%           6                 0   100.00%          39                 0   100.00%           0                 0         -
roci-storage/src/fs_storage/maintenance.rs           63                29    53.97%           8                 3    62.50%          45                19    57.78%           0                 0         -
roci-storage/src/fs_storage/mod.rs                  247                15    93.93%          16                 0   100.00%         148                 6    95.95%           0                 0         -
roci-storage/src/fs_storage/paths.rs                100                 8    92.00%          12                 0   100.00%          44                 0   100.00%           0                 0         -
roci-storage/src/fs_storage/scrub.rs               1220                47    96.15%          75                 1    98.67%         771                29    96.24%           0                 0         -
roci-storage/src/fs_storage/storage_impl.rs        1617               168    89.61%          66                 1    98.48%         878                72    91.80%           0                 0         -
roci-storage/src/gc.rs                              455                 8    98.24%          41                 0   100.00%         258                 5    98.06%           0                 0         -
roci-storage/src/layout.rs                          812                26    96.80%          60                 0   100.00%         426                12    97.18%           0                 0         -
roci-storage/src/lifecycle.rs                        64                 5    92.19%           2                 0   100.00%          48                 3    93.75%           0                 0         -
roci-storage/src/lock_map.rs                         54                 0   100.00%           7                 0   100.00%          32                 0   100.00%           0                 0         -
roci-storage/src/metadata/lmdb.rs                  2129               220    89.67%          83                10    87.95%        1107                95    91.42%           0                 0         -
roci-storage/src/metadata/log.rs                   4890               118    97.59%         161                 2    98.76%        2271                29    98.72%           0                 0         -
roci-storage/src/metadata/mod.rs                   2665               145    94.56%          88                 7    92.05%        1468                84    94.28%           0                 0         -
roci-storage/src/metadata/snapshot.rs               534                10    98.13%          17                 0   100.00%         258                 1    99.61%           0                 0         -
roci-storage/src/metadata/wal_hmac.rs               198                 1    99.49%          12                 0   100.00%          99                 0   100.00%           0                 0         -
roci-storage/src/publish.rs                         350               112    68.00%          14                 1    92.86%         223                56    74.89%           0                 0         -
roci-storage/src/quota.rs                           362                 4    98.90%          26                 0   100.00%         192                 0   100.00%           0                 0         -
roci-storage/src/routing.rs                         370                24    93.51%          28                 4    85.71%         176                19    89.20%           0                 0         -
roci-storage/src/storage.rs                         170                 9    94.71%          18                 1    94.44%         115                 7    93.91%           0                 0         -
roci-storage/src/upload_body.rs                     226                14    93.81%          21                 2    90.48%         160                 8    95.00%           0                 0         -
roci-telemetry/src/lib.rs                           244                18    92.62%          14                 1    92.86%         149                 1    99.33%           0                 0         -
roci-telemetry/src/metrics.rs                       517                 2    99.61%          40                 0   100.00%         360                 0   100.00%           0                 0         -
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                                             33909              1992    94.13%        1892               104    94.50%       19372               927    95.21%           0                 0         -
```
