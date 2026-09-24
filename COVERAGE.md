# Coverage

Line coverage is enforced at a **95%** floor by the `coverage`
step of the `CI` workflow and the pre-commit hook (lcov line metric), excluding
the thin binary entrypoint `crates/roci-cli/src/main.rs` (a `#[tokio::main]`
shim over the fully-covered library). Any uncovered lines are listed at gate
time for triage; the few that remain are unreachable-in-CI defensive
syscall-error arms in the beneath-root storage path.

Current line coverage: **96.61%** (14527/15037 lines).

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
roci-core/src/error.rs                              302                 5    98.34%          27                 0   100.00%         211                 3    98.58%           0                 0         -
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
roci-storage-s3/src/lib.rs                          143                 6    95.80%          11                 0   100.00%          82                 0   100.00%           0                 0         -
roci-storage-s3/src/storage_impl.rs                2495               533    78.64%         156                33    78.85%        1340               269    79.93%           0                 0         -
roci-storage-s3/src/tests.rs                       4135                33    99.20%         187                 1    99.47%        2381                 8    99.66%           0                 0         -
roci-storage-s3/src/uploads.rs                      351                44    87.46%          27                 2    92.59%         196                15    92.35%           0                 0         -
roci-storage/src/beneath.rs                         394                31    92.13%          28                 0   100.00%         233                 9    96.14%           0                 0         -
roci-storage/src/cache.rs                           304                 0   100.00%          15                 0   100.00%         112                 0   100.00%           0                 0         -
roci-storage/src/dedupe.rs                          114                 0   100.00%          10                 0   100.00%          54                 0   100.00%           0                 0         -
roci-storage/src/digest.rs                          117                 1    99.15%          15                 0   100.00%          82                 0   100.00%           0                 0         -
roci-storage/src/error.rs                            12                 0   100.00%           2                 0   100.00%          10                 0   100.00%           0                 0         -
roci-storage/src/filter.rs                          169                 0   100.00%          12                 0   100.00%          83                 0   100.00%           0                 0         -
roci-storage/src/fs_storage/gc.rs                   601                67    88.85%          26                 1    96.15%         318                40    87.42%           0                 0         -
roci-storage/src/fs_storage/index.rs                416                54    87.02%          37                 7    81.08%         223                19    91.48%           0                 0         -
roci-storage/src/fs_storage/lifecycle.rs             98                 7    92.86%           6                 0   100.00%          61                 3    95.08%           0                 0         -
roci-storage/src/fs_storage/maintenance.rs           79                21    73.42%           9                 3    66.67%          57                14    75.44%           0                 0         -
roci-storage/src/fs_storage/mod.rs                  285                12    95.79%          21                 0   100.00%         159                 6    96.23%           0                 0         -
roci-storage/src/fs_storage/paths.rs                100                 8    92.00%          12                 0   100.00%          44                 0   100.00%           0                 0         -
roci-storage/src/fs_storage/scrub.rs               1364                47    96.55%          85                 1    98.82%         763                29    96.20%           0                 0         -
roci-storage/src/fs_storage/storage_impl.rs        1227               139    88.67%          52                 2    96.15%         587                48    91.82%           0                 0         -
roci-storage/src/gc.rs                              341                 2    99.41%          35                 0   100.00%         179                 1    99.44%           0                 0         -
roci-storage/src/layout.rs                          585                25    95.73%          46                 0   100.00%         305                12    96.07%           0                 0         -
roci-storage/src/metadata/log.rs                   5301               108    97.96%         173                 1    99.42%        2447                25    98.98%           0                 0         -
roci-storage/src/metadata/mod.rs                   1239                 2    99.84%          30                 0   100.00%         641                 0   100.00%           0                 0         -
roci-storage/src/metadata/redb.rs                  1974               137    93.06%          54                 1    98.15%         922                24    97.40%           0                 0         -
roci-storage/src/metadata/snapshot.rs               601                10    98.34%          24                 0   100.00%         255                 1    99.61%           0                 0         -
roci-storage/src/metadata/wal_hmac.rs               210                 1    99.52%          13                 0   100.00%         105                 0   100.00%           0                 0         -
roci-storage/src/publish.rs                         310               104    66.45%          14                 1    92.86%         190                50    73.68%           0                 0         -
roci-storage/src/quota.rs                           341                 3    99.12%          24                 0   100.00%         177                 0   100.00%           0                 0         -
roci-storage/src/routing.rs                        1166                 0   100.00%          77                 0   100.00%         538                 0   100.00%           0                 0         -
roci-storage/src/storage.rs                         105                 6    94.29%          13                 0   100.00%          73                 2    97.26%           0                 0         -
roci-telemetry/src/lib.rs                           244                18    92.62%          14                 1    92.86%         151                 1    99.34%           0                 0         -
roci-telemetry/src/metrics.rs                       393                 2    99.49%          30                 0   100.00%         253                 0   100.00%           0                 0         -
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                                             29572              1500    94.93%        1584                65    95.90%       15861               607    96.17%           0                 0         -
```
