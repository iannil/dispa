#!/usr/bin/env bash
# Simple command plugin example: set response/request headers
# Reads JSON from stdin (ignored), always outputs set_headers with a fixed header

read -r _INPUT
cat <<'JSON'
{ "set_headers": { "x-cmd-plugin": "1" } }
JSON

