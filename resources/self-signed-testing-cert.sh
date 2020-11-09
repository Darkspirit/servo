#!/usr/bin/env bash

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

set -o errexit
set -o nounset
set -o pipefail

openssl genpkey -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 \
    -pkeyopt ec_param_enc:named_curve | \
    openssl pkcs8 -topk8 -nocrypt -outform pem > self-signed-testing-cert.key

openssl req -new -x509 -sha256 -key self-signed-testing-cert.key \
    -out self-signed-testing-cert.crt \
    -days 3650 \
    -subj "/CN=localhost" \
    -extensions SAN \
    -config <(cat /etc/ssl/openssl.cnf <(printf \
    "[SAN]\nsubjectAltName=DNS:localhost,IP:0:0:0:0:0:0:0:1,IP:127.0.0.1"))
