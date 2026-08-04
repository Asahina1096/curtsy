#!/usr/bin/env bash
#
# compare.sh - regression gate between two Curtsy benchmark summary.json files
# (tools/benchmark).
#
# Matches runs between a baseline and a candidate summary by
# (protocol, mode, point, direction) and gates:
#   - throughput (bits_per_second):      fail when candidate is more than
#                                        --max-throughput-regression percent
#                                        below baseline                  [3]
#   - CPU-per-Gbit (cpu_per_gbit):       fail when candidate is more than
#                                        --max-cpu-regression percent
#                                        above baseline                  [5]
#                                        (only when the field is present on
#                                        both sides; otherwise it is
#                                        reported as incomparable)
#   - UDP loss (lost_percent):           fail when candidate exceeds baseline
#                                        by more than --max-loss-increase
#                                        percentage points               [5]
#   - TCP retransmits:                   fail when candidate exceeds baseline
#                                        by more than --max-retransmit-increase
#                                        packets                         [1000]
#
# Runs present on only one side and metrics present on only one side are
# reported as missing/incomparable (warnings by default; pass
# --fail-on-missing to turn missing runs into failures).
#
# Usage: compare.sh <baseline.json> <candidate.json> [options]
#   --max-throughput-regression <pct>   default 3
#   --max-cpu-regression <pct>          default 5
#   --max-loss-increase <pct>           default 5
#   --max-retransmit-increase <n>       default 1000
#   --fail-on-missing                   treat missing runs as failures
#   --json <file>                       write the machine-readable report
#   --text <file>                       write the human-readable report
#                                       (default: stdout)
#   -h, --help
#
# Exit codes: 0 pass, 1 regression detected (fail), 2 usage error,
# 3 cannot compare (invalid summaries or no overlapping runs).

set -eu -o pipefail

TOOL_VERSION="1.0.0"
EXIT_PASS=0
EXIT_FAIL=1
EXIT_USAGE=2
EXIT_CANNOT=3

base_file=""
cand_file=""
bthr=3
cthr=5
lthr=5
rthr=1000
fom=0
json_out=""
text_out=""

usage() {
    cat <<'EOF'
Usage: compare.sh <baseline.json> <candidate.json> [options]

Regression gate between two Curtsy benchmark summary.json files. Runs are
matched by (protocol, mode, point, direction).

Options:
  --max-throughput-regression <pct>  Fail when throughput drops more than this
                                     percent below baseline.            [3]
  --max-cpu-regression <pct>         Fail when CPU-per-Gbit rises more than
                                     this percent above baseline.       [5]
  --max-loss-increase <pct>          Fail when UDP lost_percent rises more
                                     than this many percentage points.  [5]
  --max-retransmit-increase <n>      Fail when TCP retransmits rise more than
                                     this many packets.                 [1000]
  --fail-on-missing                  Treat runs missing on either side as
                                     failures (default: warnings).
  --json <file>                      Write the machine-readable report.
  --text <file>                      Write the human-readable report.
                                     (default: stdout)
  -h, --help                         Print this help and exit.

Exit codes: 0 pass, 1 regression detected, 2 usage error, 3 cannot compare.
EOF
}

# --- argument parsing -------------------------------------------------------
for a in "$@"; do
    case "$a" in
        --help | -h) usage; exit 0 ;;
    esac
done

if [ "$#" -lt 2 ]; then
    usage >&2
    exit "$EXIT_USAGE"
fi

base_file="$1"
cand_file="$2"
shift 2

while [ "$#" -gt 0 ]; do
    case "$1" in
        --help | -h) usage; exit 0 ;;
        --max-throughput-regression) bthr=${2:?missing value for --max-throughput-regression}; shift 2 ;;
        --max-cpu-regression) cthr=${2:?missing value for --max-cpu-regression}; shift 2 ;;
        --max-loss-increase) lthr=${2:?missing value for --max-loss-increase}; shift 2 ;;
        --max-retransmit-increase) rthr=${2:?missing value for --max-retransmit-increase}; shift 2 ;;
        --fail-on-missing) fom=1; shift ;;
        --json) json_out=${2:?missing value for --json}; shift 2 ;;
        --text) text_out=${2:?missing value for --text}; shift 2 ;;
        *) echo "compare: unexpected argument: $1 (see --help)" >&2; exit "$EXIT_USAGE" ;;
    esac
done

is_num() { case "$1" in '' | *[!0-9]*) return 1 ;; *) return 0 ;; esac; }
is_float() { case "$1" in '' | *[!0-9.]*) return 1 ;; *) return 0 ;; esac; }

is_float "$bthr" || { echo "compare: --max-throughput-regression must be a number" >&2; exit "$EXIT_USAGE"; }
is_float "$cthr" || { echo "compare: --max-cpu-regression must be a number" >&2; exit "$EXIT_USAGE"; }
is_float "$lthr" || { echo "compare: --max-loss-increase must be a number" >&2; exit "$EXIT_USAGE"; }
is_num "$rthr" || { echo "compare: --max-retransmit-increase must be an integer" >&2; exit "$EXIT_USAGE"; }

command -v jq >/dev/null 2>&1 || { echo "compare: jq is required" >&2; exit "$EXIT_USAGE"; }

for f in "$base_file" "$cand_file"; do
    [ -f "$f" ] || { echo "compare: file not found: $f" >&2; exit "$EXIT_USAGE"; }
done

# --- the comparison program ------------------------------------------------
# Run key: protocol|mode|point|direction. Numeric metrics fall back to 0 where
# the summary used a fallback; cpu_per_gbit / lost_percent / retransmits are
# absent (null) when not present on a side and are then reported incomparable.
program=$(cat <<'JQ'
def key(o): o.protocol + "|" + o.mode + "|" + o.point + "|" + o.direction;
def num(o; f): if (o[f] == null or o[f] == "") then null else o[f] end;
def pct(a; b): if a > 0 then (b - a) * 100 / a else null end;
def inc(a; b): if a != null and b != null then b - a else null end;

($base[0].runs // []) as $bruns |
($cand[0].runs // []) as $cruns |
($bruns | map({key: key(.), value: .}) | from_entries) as $bm |
($cruns | map({key: key(.), value: .}) | from_entries) as $cm |
(($bm | keys) - ($cm | keys)) as $only_base |
(($cm | keys) - ($bm | keys)) as $only_cand |
(($bm | keys) | map(select($cm[.] != null)) | sort) as $common |
(
  [ $common[] as $k
    | ($bm[$k]) as $b
    | ($cm[$k]) as $c
    | ((num($b; "bits_per_second") // 0) as $bb
      | ((num($c; "bits_per_second") // 0) as $cb
        | (if $bb > 0 then (if $cb > 0 then pct($bb; $cb) else -100.0 end) else null end) as $tc
        | (num($b; "cpu_per_gbit")) as $bcu
        | (num($c; "cpu_per_gbit")) as $ccu
        | (if $bcu != null and $ccu != null and $bcu > 0 then pct($bcu; $ccu) else null end) as $cc
        | (num($b; "lost_percent")) as $bl
        | (num($c; "lost_percent")) as $cl
        | (num($b; "retransmits")) as $br
        | (num($c; "retransmits")) as $cr
        | {
            key: $k,
            protocol: ($b.protocol // $c.protocol // ""),
            baseline_bits: $bb,
            candidate_bits: $cb,
            throughput_change_pct: $tc,
            throughput_status:
              (if $bb <= 0 then "skip"
               elif $cb <= 0 then "fail"
               elif $tc < -$bthr then "fail"
               else "pass" end),
            cpu_change_pct: $cc,
            cpu_status:
              (if $bcu == null or $ccu == null then "skip"
               elif $bcu == 0 and $ccu > 0 then "fail"
               elif $cc > $cthr then "fail"
               else "pass" end),
            loss_increase: inc($bl; $cl),
            loss_status:
              (if $bl == null or $cl == null then "skip"
               elif (($cl - $bl) > $lthr) then "fail"
               else "pass" end),
            retrans_increase: inc($br; $cr),
            retrans_status:
              (if $br == null or $cr == null then "skip"
               elif (($cr - $br) > $rthr) then "fail"
               else "pass" end),
            warnings:
              ( (if $bcu == null and $ccu != null then ["cpu_per_gbit present only on candidate"] else [] end)
            + (if $bcu != null and $ccu == null then ["cpu_per_gbit present only on baseline"] else [] end)
            + (if $bl == null and $cl != null then ["lost_percent present only on candidate"] else [] end)
            + (if $bl != null and $cl == null then ["lost_percent present only on baseline"] else [] end)
            + (if $br == null and $cr != null then ["retransmits present only on candidate"] else [] end)
            + (if $br != null and $cr == null then ["retransmits present only on baseline"] else [] end) )
          } ) ) ]
) as $raw |
( [ $raw[] | . as $r | $r + {
      status:
        ( if [.throughput_status, .cpu_status, .loss_status, .retrans_status] | index("fail") then "fail"
          elif [.throughput_status, .cpu_status, .loss_status, .retrans_status] | index("pass") then "pass"
          else "skip" end ),
      messages:
        ( (if $r.throughput_status == "fail" then
             ["throughput regression " + (($r.throughput_change_pct // -100.0) | tostring) + "% (baseline_bits=" + ($r.baseline_bits | tostring) + " candidate_bits=" + ($r.candidate_bits | tostring) + ", limit < -" + ($bthr | tostring) + "%)"]
           else [] end)
        + (if $r.cpu_status == "fail" then
             ["cpu-per-gbit regression " + (($r.cpu_change_pct // 0) | tostring) + "% (limit > +" + ($cthr | tostring) + "%)"]
           else [] end)
        + (if $r.loss_status == "fail" then
             ["UDP lost_percent increased by " + (($r.loss_increase // 0) | tostring) + " points (limit +" + ($lthr | tostring) + ")"]
           else [] end)
        + (if $r.retrans_status == "fail" then
             ["TCP retransmits increased by " + (($r.retrans_increase // 0) | tostring) + " (limit +" + ($rthr | tostring) + ")"]
           else [] end)
      )
    } ] ) as $results |
{
  tool: "compare",
  version: $ver,
  generated_at: (now | todate),
  baseline: {file: $bfile, session: ($base[0].session // ""), runs: ($bruns | length)},
  candidate: {file: $cfile, session: ($cand[0].session // ""), runs: ($cruns | length)},
  parameters: {max_throughput_regression_pct: $bthr, max_cpu_regression_pct: $cthr,
               max_loss_increase_pct: $lthr, max_retransmit_increase: $rthr,
               fail_on_missing: ($fom == 1)},
  matched: ($results | length),
  missing_in_candidate: ($only_base | map({key: ., protocol: ($bm[.].protocol // "")})),
  missing_in_baseline: ($only_cand | map({key: ., protocol: ($cm[.].protocol // "")})),
  results: $results,
  failures: [ $results[] | select(.status == "fail") | {key: .key, protocol: .protocol, messages: .messages} ],
  warnings:
    ([ $results[].warnings[] ]
     + [ $only_base[] | "run missing in candidate: \(.)" ]
     + [ $only_cand[] | "run missing in baseline: \(.)" ])
    | unique,
  verdict:
    ( if ($results | length) == 0 then "cannot_compare"
      elif ([ $results[].status ] | index("fail")) then "fail"
      elif $fom == 1 and (($only_base | length) > 0 or ($only_cand | length) > 0) then "fail"
      else "pass" end )
}
JQ
)

tmpdir=$(mktemp -d /tmp/curtsy-compare.XXXXXX)
trap 'rm -rf "$tmpdir"' EXIT
report_json="$tmpdir/report.json"
prog_file="$tmpdir/program.jq"
printf '%s\n' "$program" >"$prog_file"

if ! jq -n \
    --slurpfile base "$base_file" \
    --slurpfile cand "$cand_file" \
    --argjson bthr "$bthr" --argjson cthr "$cthr" \
    --argjson lthr "$lthr" --argjson rthr "$rthr" \
    --argjson fom "$fom" \
    --arg ver "$TOOL_VERSION" --arg bfile "$base_file" --arg cfile "$cand_file" \
    -f "$prog_file" >"$report_json"; then
    echo "compare: could not parse $base_file or $cand_file as summary.json" >&2
    exit "$EXIT_CANNOT"
fi

verdict=$(jq -r '.verdict' "$report_json")
matched=$(jq -r '.matched' "$report_json")
nfail=$(jq -r '[.failures[]] | length' "$report_json")
nmiss_c=$(jq -r '.missing_in_candidate | length' "$report_json")
nmiss_b=$(jq -r '.missing_in_baseline | length' "$report_json")

render_text() {
    jq -r '
        "Regression comparison (compare.sh v" + .tool + " )",
        "  baseline:  " + .baseline.file + " (session " + (.baseline.session // "-") + ", runs " + (.baseline.runs | tostring) + ")",
        "  candidate: " + .candidate.file + " (session " + (.candidate.session // "-") + ", runs " + (.candidate.runs | tostring) + ")",
        "  matched: " + (.matched | tostring) +
            "   missing_in_candidate: " + (.missing_in_candidate | length | tostring) +
            "   missing_in_baseline: " + (.missing_in_baseline | length | tostring),
        "  thresholds: throughput < -" + (.parameters.max_throughput_regression_pct | tostring) + "%  cpu-per-gbit > +" +
            (.parameters.max_cpu_regression_pct | tostring) + "%  loss > +" +
            (.parameters.max_loss_increase_pct | tostring) + " pts  retransmits > +" +
            (.parameters.max_retransmit_increase | tostring),
        "",
        "verdict: " + .verdict,
        "",
        ( [ .failures[] | "FAIL  " + .key + "  " + (.messages | join("; ")) ] | join("\n") ),
        ( [ .results[] | select(.status == "pass") |
            "PASS  " + .key + "  bits " + (.baseline_bits | tostring) + " -> " + (.candidate_bits | tostring) +
            "  (" + ((.throughput_change_pct // 0) | tostring) + "%)" ] | join("\n") ),
        ( [ .results[] | select(.status == "skip") |
            "SKIP  " + .key + "  " + (.warnings | join("; ")) ] | join("\n") ),
        ( [ .missing_in_candidate[] | "MISSING-IN-CANDIDATE  " + .key + " (" + .protocol + ")" ] | join("\n") ),
        ( [ .missing_in_baseline[]  | "MISSING-IN-BASELINE   " + .key + " (" + .protocol + ")" ] | join("\n") ),
        ( [ .warnings[] | "WARN  " + . ] | join("\n") )
    ' "$report_json"
}

if [ -n "$json_out" ]; then
    cp "$report_json" "$json_out"
fi
if [ -n "$text_out" ]; then
    render_text >"$text_out"
else
    render_text
fi

echo "compare: verdict=$verdict matched=$matched failures=$nfail missing_in_candidate=$nmiss_c missing_in_baseline=$nmiss_b"

case "$verdict" in
    cannot_compare) exit "$EXIT_CANNOT" ;;
    fail) exit "$EXIT_FAIL" ;;
    *) exit "$EXIT_PASS" ;;
esac
