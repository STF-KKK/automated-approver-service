package main

import (
	conf "github.com/mpa-sandbox-approval-service/config/approval-service"
)

conf.#Config & {
	port: 9294
	private_key: "private_key"
	tls_private_key_seed: "private_key_seed"
	secret_manager: "secretsmanager"
}
