# Minimal production-mode config for a self-hosted Vault serving ONLY this
# platform's secrets, on the same host as the app.
#
# Storage is the local filesystem (no separate Consul/etc. cluster needed for
# a single-node deployment). The listener is bound to loopback only — the app
# and Vault run on the same host, so the "network" hop never leaves localhost
# and doesn't need its own TLS; if Vault will ever be reached from another
# host, switch tls_disable to false and set tls_cert_file/tls_key_file.
#
# This is OSS Vault with Shamir secret-sharing seals: after every `vault
# server` (re)start, Vault starts SEALED and an operator must run
# `vault operator unseal` (with enough key shares to meet the threshold set at
# `vault operator init`) before it will serve requests — see the README
# section "Secrets vault (HashiCorp Vault)" for the one-time init + the
# unseal procedure. There is no auto-unseal here (that needs a cloud KMS or
# Vault Enterprise) — plan for someone to run the unseal command after a
# reboot or Vault restart.

storage "file" {
  path = "/opt/ai-troubleshooter/vault/data"
}

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = true
}

api_addr = "http://127.0.0.1:8200"
ui       = true
# Vault normally mlocks memory so secrets can't be swapped to disk, which
# needs CAP_IPC_LOCK (granted below via systemd's AmbientCapabilities). If you
# run the binary somewhere that capability can't be granted, set this to true
# instead — swap should be disabled on the host as a mitigation either way.
disable_mlock = false
