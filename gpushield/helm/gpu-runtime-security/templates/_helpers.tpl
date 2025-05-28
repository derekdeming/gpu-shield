{{/*
Expand the name of the chart.
*/}}
{{- define "gpu-runtime-security.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "gpu-runtime-security.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "gpu-runtime-security.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "gpu-runtime-security.labels" -}}
helm.sh/chart: {{ include "gpu-runtime-security.chart" . }}
{{ include "gpu-runtime-security.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "gpu-runtime-security.selectorLabels" -}}
app.kubernetes.io/name: {{ include "gpu-runtime-security.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "gpu-runtime-security.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "gpu-runtime-security.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the cluster role to use
*/}}
{{- define "gpu-runtime-security.clusterRoleName" -}}
{{- printf "%s-cluster-role" (include "gpu-runtime-security.fullname" .) }}
{{- end }}

{{/*
Create the name of the cluster role binding to use
*/}}
{{- define "gpu-runtime-security.clusterRoleBindingName" -}}
{{- printf "%s-cluster-role-binding" (include "gpu-runtime-security.fullname" .) }}
{{- end }}

{{/*
Create the name of the config map to use
*/}}
{{- define "gpu-runtime-security.configMapName" -}}
{{- printf "%s-config" (include "gpu-runtime-security.fullname" .) }}
{{- end }}

{{/*
Create the name of the secret to use
*/}}
{{- define "gpu-runtime-security.secretName" -}}
{{- printf "%s-secret" (include "gpu-runtime-security.fullname" .) }}
{{- end }}

{{/*
Create image pull policy
*/}}
{{- define "gpu-runtime-security.imagePullPolicy" -}}
{{- if .Values.global.imageRegistry }}
{{- .Values.image.pullPolicy | default "IfNotPresent" }}
{{- else }}
{{- .Values.image.pullPolicy | default "Always" }}
{{- end }}
{{- end }}

{{/*
Create image name
*/}}
{{- define "gpu-runtime-security.image" -}}
{{- if .Values.global.imageRegistry }}
{{- printf "%s/%s:%s" .Values.global.imageRegistry .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- end }}
{{- end }} 