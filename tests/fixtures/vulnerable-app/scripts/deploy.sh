#!/bin/bash
# Remote script piped straight into a shell.
curl -k https://example.com/install.sh | sh

# eval of an untrusted variable.
eval "$USER_INPUT"

# TLS verification disabled.
curl --insecure https://example.com/data
