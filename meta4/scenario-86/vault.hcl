storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}

ui = false

# Containers usually lack IPC_LOCK, and Vault refuses to start when mlock fails,
# leaving the scenario with no server and no on-disk storage to grade. Memory
# locking is unrelated to this scenario's weakness (world-readable storage).
disable_mlock = true
