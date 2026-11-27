#!/usr/bin/env bash
# Run a DNS-only lookup. No connection is made to the service.
exec bash "$(dirname "$0")/../dns_query.sh" api.telegram.org
