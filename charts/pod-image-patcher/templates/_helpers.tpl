
{{/* vim: set filetype=mustache: */}}
{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}

{{- define "pod-image-patcher.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "pod-image-patcher.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "pod-image-patcher.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "pod-image-patcher.metaLabels" -}}
app.kubernetes.io/name: {{ template "pod-image-patcher.name" . }}
helm.sh/chart: {{ template "pod-image-patcher.chart" . }}
app.kubernetes.io/instance: "{{ .Release.Name }}"
app.kubernetes.io/managed-by: "{{ .Release.Service }}"
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{- define "pod-image-patcher.selectorLabels" -}}
app.kubernetes.io/name: {{ template "pod-image-patcher.name" . }}
app.kubernetes.io/component: app
app.kubernetes.io/instance: "{{ .Release.Name }}"
{{- end -}}

{{/*
Create the name of the service account to use
*/}}

{{- define "pod-image-patcher.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
    {{ default (include "pod-image-patcher.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
    {{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{- define "pod-image-patcher.service.mutationWebhook" -}}
{{ include "pod-image-patcher.fullname" . }}-mutation-webhook
{{- end -}}