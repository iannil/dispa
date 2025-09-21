#!/usr/bin/env bash
# Command plugin example: short-circuit the request with 418
# Reads JSON from stdin (ignored), returns a short_circuit response

read -r _INPUT
cat <<'JSON'
{ "short_circuit": { "status": 418, "body": "blocked by cmd plugin" } }
JSON

