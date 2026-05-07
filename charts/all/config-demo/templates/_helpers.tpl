{{/*
Vault HTTPS URL (matches vp-sscsi-spc when externalAddress is empty).
*/}}
{{- define "config-demo.vaultUrl" -}}
{{- $ext := .Values.ocpSecretsStoreCsiVault.vault.externalAddress | default "" | trim }}
{{- if ne $ext "" -}}
{{- $ext -}}
{{- else -}}
{{- printf "https://vault-vault.%s" .Values.global.hubClusterDomain -}}
{{- end -}}
{{- end }}

{{/*
Precheck init container: SS-CSI in use, strict TLS, CA bundle mounted, and not disabled in values.
*/}}
{{- define "config-demo.vaultTlsPrecheckEnabled" -}}
{{- if not .Values.vaultTlsPrecheck.enabled -}}
false
{{- else if not .Values.vaultCaBundle.enabled -}}
false
{{- else if not .Values.ocpSecretsStoreCsiVault.secretProviderClass.enabled -}}
false
{{- else if eq (.Values.ocpSecretsStoreCsiVault.tls.vaultCACertPath | default "" | trim) "" -}}
false
{{- else -}}
{{- $v := .Values.ocpSecretsStoreCsiVault.tls.vaultSkipTLSVerify | toString | trim | lower }}
{{- if or (eq $v "true") (eq $v "1") -}}
false
{{- else -}}
true
{{- end -}}
{{- end -}}
{{- end }}
