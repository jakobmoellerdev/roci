{{/*
Render-time guards for insecure or unsupported combinations the schema cannot
express. Included first by statefulset.yaml; scripts/helm-lint.sh asserts
every message.
*/}}
{{- define "roci.validate" -}}
{{- if and (not (include "roci.authConfigured" .)) (not .Values.auth.allowAnonymous) }}
{{- fail "roci: authentication is not configured - set auth.htpasswd.existingSecret or auth.accessControl, or set auth.allowAnonymous=true to run an open registry (anyone reaching the Service can push and delete)" }}
{{- end }}
{{- if .Values.rustfs.enabled }}
{{- if dig "secret" "allowInsecureDefaults" false .Values.rustfs }}
{{- fail "roci: rustfs.secret.allowInsecureDefaults is not permitted - set rustfs.secret.rustfs.access_key/secret_key or rustfs.secret.existingSecret" }}
{{- end }}
{{- if dig "mtls" "enabled" false .Values.rustfs }}
{{- fail "roci: rustfs.mtls.enabled is unsupported - roci's S3 client cannot trust the private RustFS CA; in-cluster S3 traffic is plaintext and confined by NetworkPolicy" }}
{{- end }}
{{- if or (dig "mode" "standalone" "enabled" false .Values.rustfs) (not (dig "mode" "distributed" "enabled" true .Values.rustfs)) }}
{{- fail "roci: S3 mode requires RustFS distributed mode (rustfs.mode.distributed.enabled=true, rustfs.mode.standalone.enabled=false)" }}
{{- end }}
{{- $replicas := int (dig "replicaCount" 4 .Values.rustfs) }}
{{- if lt $replicas 4 }}
{{- fail (printf "roci: rustfs.replicaCount must be >= 4 for a fault-tolerant erasure set (got %d)" $replicas) }}
{{- end }}
{{- if and (dig "secret" "existingSecret" "" .Values.rustfs) (not .Values.s3.accessKeyId) }}
{{- fail "roci: s3.accessKeyId is required when rustfs.secret.existingSecret is set (it must equal the Secret's RUSTFS_ACCESS_KEY)" }}
{{- end }}
{{- end }}
{{- end }}
