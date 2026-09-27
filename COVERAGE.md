# Coverage

Line coverage is enforced at a **95%** floor by the `coverage`
step of the `CI` workflow and the pre-commit hook (lcov line metric), excluding
the thin binary entrypoint `crates/roci-cli/src/main.rs` (a `#[tokio::main]`
shim over the fully-covered library). Any uncovered lines are listed at gate
time for triage; the few that remain are unreachable-in-CI defensive
syscall-error arms in the beneath-root storage path.

Current line coverage: **97.48%** (23940/24560 lines).

Regenerate with `just coverage` (or on every commit via the pre-commit hook).
Inspect region-level gaps with `just coverage-report`.

```
Filename                                        Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
roci-cli/src/auth_tests.rs                          686                 7    98.98%          32                 1    96.88%         336                 1    99.70%           0                 0         -
roci-cli/src/lib.rs                                7025               165    97.65%         457                32    93.00%        4024                64    98.41%           0                 0         -
roci-cli/src/main.rs                                 82                12    85.37%          14                 2    85.71%          59                 7    88.14%           0                 0         -
roci-cluster/src/lib.rs                               3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-config/src/lib.rs                             2660                21    99.21%         182                 2    98.90%        2623                 5    99.81%           0                 0         -
roci-core/src/auth/bearer.rs                        619                 7    98.87%          26                 0   100.00%         320                 1    99.69%           0                 0         -
roci-core/src/auth/cache.rs                          81                 0   100.00%           4                 0   100.00%          60                 0   100.00%           0                 0         -
roci-core/src/auth/htpasswd.rs                      110                 1    99.09%          12                 0   100.00%          59                 0   100.00%           0                 0         -
roci-core/src/auth/identity.rs                      110                 0   100.00%           9                 0   100.00%          56                 0   100.00%           0                 0         -
roci-core/src/auth/ldap.rs                          170                 5    97.06%          11                 0   100.00%         105                 0   100.00%           0                 0         -
roci-core/src/auth/middleware.rs                     47                 0   100.00%           5                 0   100.00%          29                 0   100.00%           0                 0         -
roci-core/src/auth/mod.rs                           436                 5    98.85%          41                 1    97.56%         295                 1    99.66%           0                 0         -
roci-core/src/auth/policy.rs                        411                 0   100.00%          23                 0   100.00%         245                 0   100.00%           0                 0         -
roci-core/src/blobs.rs                              168                 0   100.00%          14                 0   100.00%         134                 0   100.00%           0                 0         -
roci-core/src/conn_close.rs                          64                14    78.12%           6                 2    66.67%          43                10    76.74%           0                 0         -
roci-core/src/error.rs                              790                13    98.35%          68                 0   100.00%         537                 6    98.88%           0                 0         -
roci-core/src/http_util.rs                          152                 0   100.00%          12                 0   100.00%          80                 0   100.00%           0                 0         -
roci-core/src/lib.rs                                724                 4    99.45%          57                 0   100.00%         445                 3    99.33%           0                 0         -
roci-core/src/listing.rs                            140                 2    98.57%           9                 0   100.00%          87                 0   100.00%           0                 0         -
roci-core/src/manifests.rs                          527                 1    99.81%          60                 0   100.00%         382                 0   100.00%           0                 0         -
roci-core/src/names.rs                              156                 0   100.00%          13                 0   100.00%         111                 0   100.00%           0                 0         -
roci-core/src/ratelimit.rs                          498                 8    98.39%          33                 0   100.00%         335                 6    98.21%           0                 0         -
roci-core/src/routes.rs                             453                12    97.35%          15                 0   100.00%         207                 0   100.00%           0                 0         -
roci-core/src/uploads.rs                            241                 0   100.00%          35                 0   100.00%         187                 0   100.00%           0                 0         -
roci-ext-scan/src/lib.rs                              3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-search/src/lib.rs                            3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sig/src/lib.rs                               3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-ext-sync/src/lib.rs                              3                 0   100.00%           1                 0   100.00%           3                 0   100.00%           0                 0         -
roci-storage-s3/src/client.rs                       134                 6    95.52%          11                 1    90.91%         107                 6    94.39%           0                 0         -
roci-storage-s3/src/keys.rs                         117                 2    98.29%          12                 0   100.00%          64                 0   100.00%           0                 0         -
roci-storage-s3/src/lib.rs                          146                 6    95.89%          12                 0   100.00%          85                 0   100.00%           0                 0         -
roci-storage-s3/src/storage_impl.rs                4581               996    78.26%         284                62    78.17%        2483               514    79.30%           0                 0         -
roci-storage-s3/src/tests.rs                       4346                33    99.24%         197                 1    99.49%        2616                 8    99.69%           0                 0         -
roci-storage-s3/src/uploads.rs                      608                70    88.49%          47                 3    93.62%         342                27    92.11%           0                 0         -
roci-storage/src/beneath.rs                        1114               114    89.77%          77                 0   100.00%         657                43    93.46%           0                 0         -
roci-storage/src/bufpool.rs                          96                 6    93.75%           9                 1    88.89%          55                 7    87.27%           0                 0         -
roci-storage/src/cache.rs                           304                 0   100.00%          15                 0   100.00%         112                 0   100.00%           0                 0         -
roci-storage/src/dedupe.rs                          189                 0   100.00%          14                 0   100.00%          82                 0   100.00%           0                 0         -
roci-storage/src/digest.rs                          279                 7    97.49%          32                 0   100.00%         184                 1    99.46%           0                 0         -
roci-storage/src/error.rs                            29                 0   100.00%           5                 0   100.00%          25                 0   100.00%           0                 0         -
roci-storage/src/filter.rs                          169                 0   100.00%          12                 0   100.00%          83                 0   100.00%           0                 0         -
roci-storage/src/fs_storage/fast_restart.rs         498                60    87.95%          21                 2    90.48%         266                31    88.35%           0                 0         -
roci-storage/src/fs_storage/gc.rs                  1218               138    88.67%          52                 2    96.15%         646                83    87.15%           0                 0         -
roci-storage/src/fs_storage/index.rs               1926               217    88.73%         144                25    82.64%         988                78    92.11%           0                 0         -
roci-storage/src/fs_storage/lifecycle.rs             98                 7    92.86%           6                 0   100.00%          61                 3    95.08%           0                 0         -
roci-storage/src/fs_storage/maintenance.rs          211                75    64.45%          21                 9    57.14%         149                50    66.44%           0                 0         -
roci-storage/src/fs_storage/mod.rs                 1069                64    94.01%          69                 1    98.55%         582                26    95.53%           0                 0         -
roci-storage/src/fs_storage/paths.rs                100                 8    92.00%          12                 0   100.00%          44                 0   100.00%           0                 0         -
roci-storage/src/fs_storage/scrub.rs               1397                51    96.35%          87                 1    98.85%         776                29    96.26%           0                 0         -
roci-storage/src/fs_storage/storage_impl.rs        4878               555    88.62%         228                10    95.61%        2489               181    92.73%           0                 0         -
roci-storage/src/gc.rs                              755                 7    99.07%          70                 1    98.57%         373                 5    98.66%           0                 0         -
roci-storage/src/layout.rs                          927                28    96.98%          88                 0   100.00%         509                11    97.84%           0                 0         -
roci-storage/src/metadata.rs                       1348                18    98.66%          70                 0   100.00%         663                 1    99.85%           0                 0         -
roci-storage/src/metadata/lmdb.rs                  1929               191    90.10%          89                 9    89.89%        1015                76    92.51%           0                 0         -
roci-storage/src/metadata/log.rs                  10674               209    98.04%         352                 3    99.15%        4898                34    99.31%           0                 0         -
roci-storage/src/metadata/mod.rs                   2536                 7    99.72%          64                 0   100.00%        1323                 7    99.47%           0                 0         -
roci-storage/src/metadata/redb.rs                  1974               137    93.06%          54                 1    98.15%         922                24    97.40%           0                 0         -
roci-storage/src/metadata/snapshot.rs               601                10    98.34%          24                 0   100.00%         255                 1    99.61%           0                 0         -
roci-storage/src/metadata/wal_hmac.rs               210                 1    99.52%          13                 0   100.00%         105                 0   100.00%           0                 0         -
roci-storage/src/publish.rs                        1244               409    67.12%          48                 3    93.75%         746               190    74.53%           0                 0         -
roci-storage/src/quota.rs                           799                11    98.62%          56                 0   100.00%         405                 1    99.75%           0                 0         -
roci-storage/src/routing.rs                        2106                 0   100.00%         110                 0   100.00%         939                 0   100.00%           0                 0         -
roci-storage/src/storage.rs                         288                27    90.62%          34                 3    91.18%         203                26    87.19%           0                 0         -
roci-storage/src/upload_body.rs                     342                18    94.74%          27                 2    92.59%         228                 8    96.49%           0                 0         -
roci-telemetry/src/lib.rs                           950                71    92.53%          54                 4    92.59%         588                 4    99.32%           0                 0         -
roci-telemetry/src/metrics.rs                      1571                33    97.90%         101                 1    99.01%         980                17    98.27%           0                 0         -
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                                             68126              3869    94.32%        3764               185    95.09%       37822              1596    95.78%           0                 0         -
```
