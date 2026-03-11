package main

import (
	conf "github.com/mpa-sandbox-approval-service/config/approval-service"
)

conf.#Config & {
	port:                 9294
	private_key:          "MHcCAQEEILsZ6e2laWnHatJgvI+Ix3SZco7KqCgHY3WpA5zamjBwoAoGCCqGSM49AwEHoUQDQgAEvdk1Rko27wKKf5Uh2b9KFoiQhRHlasdiH8if+bYb5V8Z7JpUjriFcIbxFVnR0BPE+ra3iOCDIM4ufggaKt8s7w=="
	tls_private_key_seed: ""
	secret_manager:       "local"
}
