{{/*
Chart name.
*/}}
{{- define "roci.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name (release-prefixed, 63-char DNS limit).
*/}}
{{- define "roci.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart name and version for the helm.sh/chart label.
*/}}
{{- define "roci.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "roci.labels" -}}
helm.sh/chart: {{ include "roci.chart" . }}
{{ include "roci.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels; every workload adds app.kubernetes.io/component
(registry, bucket-init, test).
*/}}
{{- define "roci.selectorLabels" -}}
app.kubernetes.io/name: {{ include "roci.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
roci image reference: digest wins over tag; tag defaults to appVersion.
*/}}
{{- define "roci.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- end }}
{{- end }}

{{/*
Image for the bucket-init Job and the helm test pod.
*/}}
{{- define "roci.hooksImage" -}}
{{- printf "%s:%s" .Values.hooks.image.repository .Values.hooks.image.tag }}
{{- end }}

{{/*
"true" when htpasswd (Basic) authentication is configured, else "".
*/}}
{{- define "roci.authHtpasswd" -}}
{{- if .Values.auth.htpasswd.existingSecret }}true{{ end }}
{{- end }}

{{/*
"true" when any authentication/authorization is configured, else "".
*/}}
{{- define "roci.authConfigured" -}}
{{- if or .Values.auth.htpasswd.existingSecret (not (empty .Values.auth.accessControl)) }}true{{ end }}
{{- end }}

{{/*
URL scheme of the registry port.
*/}}
{{- define "roci.scheme" -}}
{{- if .Values.tls.existingSecret }}https{{ else }}http{{ end }}
{{- end }}

{{/*
Mirrors the upstream subchart's "rustfs.fullname". Subchart keys the parent
values.yaml may not set are read with dig and the upstream default: a dotted
path on a missing key would nil-panic.
*/}}
{{- define "roci.rustfsFullname" -}}
{{- $override := dig "fullnameOverride" "" .Values.rustfs }}
{{- if $override }}
{{- $override | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default "rustfs" (dig "nameOverride" "" .Values.rustfs) }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Mirrors the upstream subchart's "rustfs.selectorLabels".
*/}}
{{- define "roci.rustfsSelectorLabels" -}}
app.kubernetes.io/name: {{ default "rustfs" (dig "nameOverride" "" .Values.rustfs) | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Mirrors the upstream subchart's "rustfs.secretName" (RUSTFS_ACCESS_KEY /
RUSTFS_SECRET_KEY).
*/}}
{{- define "roci.rustfsSecretName" -}}
{{- $existing := dig "secret" "existingSecret" "" .Values.rustfs }}
{{- if $existing }}
{{- $existing }}
{{- else }}
{{- printf "%s-secret" (include "roci.rustfsFullname" .) }}
{{- end }}
{{- end }}

{{/*
S3 access key id roci presents to RustFS.
*/}}
{{- define "roci.s3AccessKeyId" -}}
{{- .Values.s3.accessKeyId | default (dig "secret" "rustfs" "access_key" "" .Values.rustfs) }}
{{- end }}

{{/*
RustFS S3 API port.
*/}}
{{- define "roci.rustfsPort" -}}
{{- dig "service" "endpoint" "port" 9000 .Values.rustfs }}
{{- end }}

{{/*
In-cluster RustFS S3 endpoint (upstream Service "<fullname>-svc").
*/}}
{{- define "roci.s3Endpoint" -}}
{{- printf "http://%s-svc.%s.svc.%s:%v" (include "roci.rustfsFullname" .) .Release.Namespace (dig "clusterDomain" "cluster.local" .Values.rustfs) (include "roci.rustfsPort" .) }}
{{- end }}

{{/*
S3 region shared by RustFS, roci and the bucket-init Job.
*/}}
{{- define "roci.s3Region" -}}
{{- dig "config" "rustfs" "region" "us-east-1" .Values.rustfs }}
{{- end }}
