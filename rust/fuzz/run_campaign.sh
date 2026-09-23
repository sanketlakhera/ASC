#!/bin/sh
# One-hour M1.7 campaign for one target. Usage: ./run_campaign.sh <target> [seconds]
# Limits follow the M1 plan: no single allocation above 64 MiB, 10 s per input,
# inputs up to 16 MiB for inflate and tinydex_walk.
set -e
t="$1"; secs="${2:-3600}"
case "$t" in inflate|tinydex_walk) max_len=16777216 ;; *) max_len=65536 ;; esac
# container builds one container-sized copy per logical DEX (Python-faithful), and
# ASan quarantine holds on to them, so its RSS grows over a run without any leak.
case "$t" in container) rss=4096 ;; *) rss=2048 ;; esac
cd "$(dirname "$0")"
mkdir -p "corpus/$t" logs
# caffeinate: a sleeping Mac shows up as a bogus libFuzzer timeout.
exec caffeinate -i cargo +nightly fuzz run -O -a "$t" "corpus/$t" "seeds/$t" -- \
  -max_total_time="$secs" -malloc_limit_mb=64 -rss_limit_mb="$rss" -timeout=10 \
  -max_len="$max_len" -print_final_stats=1 > "logs/campaign_$t.log" 2>&1
