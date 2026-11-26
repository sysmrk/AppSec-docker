#!/usr/bin/env bash
# Retired: this legacy entrypoint bypassed the active worker's cache policy.
set -eu
printf '%s\n' 'V4: standalone DB updater retired. The image worker manages staged DB refresh and cache freshness. Stop any old maintenance container before upgrading. No cache was modified.' >&2
exit 2
