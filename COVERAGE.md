# Coverage

Line coverage is enforced at a **95%** floor by the `coverage`
step of the `CI` workflow and the pre-commit hook (lcov line metric), excluding
the thin binary entrypoint `crates/roci-cli/src/main.rs` (a `#[tokio::main]`
shim over the fully-covered library). Any uncovered lines are listed at gate
time for triage; the few that remain are unreachable-in-CI defensive
syscall-error arms in the beneath-root storage path.

Current line coverage: **96.21%** (19387/20150 lines).

Regenerate with `just coverage` (or on every commit via the pre-commit hook).
Inspect region-level gaps with `just coverage-report`.

```
Filename                                        Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
roci-cli/src/auth_tests.rs                          686                 7    98.98%          32                 1    96.88%         336                 1    99.70%           0                 0         -
roci-cli/src/lib.rs                                2319                69    97.02%         155                11    92.90%        1380                30    97.83%           0                 0         -
roci-cli/src/main.rs                                 52                 8    84.62%           8                 1    87.50%          34                 4    88.24%           0                 0         -
roci-cluster/src/lib.rs                               3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-config/src/lib.rs                              982                 6    99.39%          64                 1    98.44%         998                 1    99.90%           0                 0         -
roci-core/src/auth/bearer.rs                        619                 7    98.87%          26                 0   100.00%         320                 1    99.69%           0                 0         -
roci-core/src/auth/cache.rs                          81                 0   100.00%           4                 0   100.00%          60                 0   100.00%           0                 0         -
roci-core/src/auth/htpasswd.rs                      110                 1    99.09%          12                 0   100.00%          59                 0   100.00%           0                 0         -
roci-core/src/auth/identity.rs                      110                 0   100.00%           9                 0   100.00%          56                 0   100.00%           0                 0         -
roci-core/src/auth/ldap.rs                          170                 5    97.06%          11                 0   100.00%         105                 0   100.00%           0                 0         -
roci-core/src/auth/middleware.rs                     47                 0   100.00%           5                 0   100.00%          29                 0   100.00%           0                 0         -
roci-core/src/auth/mod.rs                           436                 5    98.85%          41                 1    97.56%         295                 1    99.66%           0                 0         -
roci-core/src/auth/policy.rs                        411                 0   100.00%          23                 0   100.00%         245                 0   100.00%           0                 0         -
roci-core/src/blobs.rs                               84                 0   100.00%           7                 0   100.00%          67                 0   100.00%           0                 0         -
roci-core/src/conn_close.rs                          64                14    78.12%           6                 2    66.67%          43                10    76.74%           0                 0         -
roci-core/src/error.rs                              318                 5    98.43%          27                 0   100.00%         222                 3    98.65%           0                 0         -
roci-core/src/http_util.rs                          152                 0   100.00%          12                 0   100.00%          80                 0   100.00%           0                 0         -
roci-core/src/lib.rs                                258                 1    99.61%          20                 0   100.00%         160                 1    99.38%           0                 0         -
roci-core/src/listing.rs                            140                 2    98.57%           9                 0   100.00%          87                 0   100.00%           0                 0         -
roci-core/src/manifests.rs                          238                 0   100.00%          28                 0   100.00%         174                 0   100.00%           0                 0         -
roci-core/src/names.rs                              156                 0   100.00%          13                 0   100.00%         111                 0   100.00%           0                 0         -
roci-core/src/ratelimit.rs                          405                 7    98.27%          26                 0   100.00%         266                 6    97.74%           0                 0         -
roci-core/src/routes.rs                             242                 8    96.69%           8                 0   100.00%         111                 0   100.00%           0                 0         -
roci-core/src/uploads.rs                            134                 0   100.00%          19                 0   100.00%         106                 0   100.00%           0                 0         -
roci-ext-scan/src/lib.rs                              3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-search/src/lib.rs                            3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sig/src/lib.rs                               3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sync/src/lib.rs                              3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-storage-s3/src/client.rs                       134                 6    95.52%          11                 1    90.91%         107                 6    94.39%           0                 0         -
roci-storage-s3/src/keys.rs                         117                 2    98.29%          12                 0   100.00%          64                 0   100.00%           0                 0         -
roci-storage-s3/src/lib.rs                          143                 6    95.80%          11                 0   100.00%          82                 0   100.00%           0                 0         -
roci-storage-s3/src/storage_impl.rs                2510               531    78.84%         156                33    78.85%        1348               267    80.19%           0                 0         -
roci-storage-s3/src/tests.rs                       4346                33    99.24%         197                 1    99.49%        2616                 8    99.69%           0                 0         -
roci-storage-s3/src/uploads.rs                      357                42    88.24%          28                 2    92.86%         199                15    92.46%           0                 0         -
roci-storage/src/beneath.rs                         439                49    88.84%          32                 0   100.00%         274                15    94.53%           0                 0         -
roci-storage/src/bufpool.rs                          96                 6    93.75%           9                 1    88.89%          55                 7    87.27%           0                 0         -
roci-storage/src/cache.rs                           304                 0   100.00%          15                 0   100.00%         112                 0   100.00%           0                 0         -
roci-storage/src/dedupe.rs                          125                 0   100.00%          12                 0   100.00%          63                 0   100.00%           0                 0         -
roci-storage/src/digest.rs                          159                 5    96.86%          18                 0   100.00%         111                 1    99.10%           0                 0         -
roci-storage/src/error.rs                            12                 0   100.00%           2                 0   100.00%          10                 0   100.00%           0                 0         -
roci-storage/src/filter.rs                          169                 0   100.00%          12                 0   100.00%          83                 0   100.00%           0                 0         -
roci-storage/src/fs_storage/fast_restart.rs         498                60    87.95%          21                 2    90.48%         266                31    88.35%           0                 0         -
roci-storage/src/fs_storage/gc.rs                   640                72    88.75%          28                 1    96.43%         343                44    87.17%           0                 0         -
roci-storage/src/fs_storage/index.rs                466                59    87.34%          39                 7    82.05%         255                23    90.98%           0                 0         -
roci-storage/src/fs_storage/lifecycle.rs             98                 7    92.86%           6                 0   100.00%          61                 3    95.08%           0                 0         -
roci-storage/src/fs_storage/maintenance.rs           93                29    68.82%          10                 3    70.00%          69                20    71.01%           0                 0         -
roci-storage/src/fs_storage/mod.rs                  304                15    95.07%          22                 0   100.00%         181                 6    96.69%           0                 0         -
roci-storage/src/fs_storage/paths.rs                100                 8    92.00%          12                 0   100.00%          44                 0   100.00%           0                 0         -
roci-storage/src/fs_storage/scrub.rs               1364                47    96.55%          85                 1    98.82%         763                29    96.20%           0                 0         -
roci-storage/src/fs_storage/storage_impl.rs        1680               167    90.06%          71                 1    98.59%         901                71    92.12%           0                 0         -
roci-storage/src/gc.rs                              360                 2    99.44%          38                 0   100.00%         198                 1    99.49%           0                 0         -
roci-storage/src/layout.rs                          585                25    95.73%          46                 0   100.00%         305                12    96.07%           0                 0         -
roci-storage/src/metadata/lmdb.rs                  2362               236    90.01%          98                10    89.80%        1223                95    92.23%           0                 0         -
roci-storage/src/metadata/log.rs                   5447               112    97.94%         180                 1    99.44%        2525                24    99.05%           0                 0         -
roci-storage/src/metadata/mod.rs                   2669               145    94.57%          89                 7    92.13%        1471                84    94.29%           0                 0         -
roci-storage/src/metadata/snapshot.rs               601                10    98.34%          24                 0   100.00%         255                 1    99.61%           0                 0         -
roci-storage/src/metadata/wal_hmac.rs               210                 1    99.52%          13                 0   100.00%         105                 0   100.00%           0                 0         -
roci-storage/src/publish.rs                         358               112    68.72%          15                 1    93.33%         232                56    75.86%           0                 0         -
roci-storage/src/quota.rs                           362                 3    99.17%          26                 0   100.00%         192                 0   100.00%           0                 0         -
roci-storage/src/routing.rs                        1175                 0   100.00%          78                 0   100.00%         559                 0   100.00%           0                 0         -
roci-storage/src/storage.rs                         138                 8    94.20%          15                 1    93.33%          87                 6    93.10%           0                 0         -
roci-storage/src/upload_body.rs                     226                14    93.81%          21                 2    90.48%         160                 8    95.00%           0                 0         -
roci-telemetry/src/lib.rs                           244                18    92.62%          14                 1    92.86%         151                 1    99.34%           0                 0         -
roci-telemetry/src/metrics.rs                       563                 2    99.64%          39                 0   100.00%         369                 1    99.73%           0                 0         -
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                                             37683              1977    94.75%        2075                93    95.52%       21198               893    95.79%           0                 0         -
```
