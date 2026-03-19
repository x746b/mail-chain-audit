#!/usr/bin/env bash
# mail-chain-audit.sh — Generic Email Forwarding Chain Diagnostic & Audit
# Tests DNS, SPF, DKIM, DMARC, rDNS, SMTP, TLS, SRS/ARC, MTA-STS/DANE
# Supports 2-hop (sender→dest) and 3-hop (sender→relay→dest) chains
#
# Usage:
#   ./mail-chain-audit.sh --sender github.com --dest gmail.com [options]
#   ./mail-chain-audit.sh --sender shopify.com --relay harvard.edu --dest gmail.com [options]
#   ./mail-chain-audit.sh --config chain.conf [options]
#
# See mail-chain-audit.md for full documentation.

set -uo pipefail
# Note: -e intentionally omitted — many probes return non-zero on timeout/no-result

VERSION="0.1.0"

# ── Defaults ──────────────────────────────────────────────────────────────────
SENDER_DOMAIN=""
SENDER_EMAIL=""
SENDER_IP=""

RELAY_DOMAIN=""
RELAY_MX_IP=""
RELAY_BACKEND_IP=""
RELAY_RECIPIENT=""

DEST_DOMAIN=""
DEST_RECIPIENT=""

CONFIG_FILE=""
REPORT_HTML=""
REPORT_JSON=""
REPORT_DIR=""
NO_COLOR=0
SKIP_SMTP=0
SKIP_TLS=0
VERBOSE=0

DKIM_SELECTORS=(default selector1 selector2 google s1 s2 k1 k2 dkim
                mail smtp mx mta1 mta2 mandrill everbridge tucaas
                cm protonmail zoho amazonses ses sendgrid mailgun
                postmark sparkpost brevo sendinblue mailchimp mc)
EXTRA_DKIM_SELECTORS=()

SMTP_PORTS=(25 465 587)
SMTP_TIMEOUT=6
DIG_TIMEOUT=3

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
TIMESTAMP_HUMAN=$(date +"%Y-%m-%d %H:%M:%S %Z")

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
    cat <<'USAGE'
mail-chain-audit.sh — Email Forwarding Chain Diagnostic & Audit

USAGE:
  ./mail-chain-audit.sh --sender <domain> --dest <domain> [options]
  ./mail-chain-audit.sh --config <file> [options]

REQUIRED (or use --config):
  --sender <domain>         Sender/origin domain (e.g., github.com)
  --dest <domain>           Final destination domain (e.g., gmail.com)

OPTIONAL — RELAY (3-hop chain):
  --relay <domain>          Intermediate relay/forwarding domain
  --relay-mx-ip <ip>        Relay MX gateway IP (auto-resolved if omitted)
  --relay-backend-ip <ip>   Relay backend/mailbox server IP (if different from MX)
  --relay-recipient <addr>  Relay recipient address (e.g., admin@relay.com)

OPTIONAL — SENDER:
  --sender-email <addr>     Full sender email (default: postmaster@<sender-domain>)
  --sender-ip <ip>          Known sender IP (auto-resolved from MX if omitted)

OPTIONAL — DESTINATION:
  --dest-recipient <addr>   Destination recipient address

OUTPUT:
  --html <file>             Write HTML report
  --json <file>             Write JSON report
  --dir <directory>         Write all reports (auto-named with timestamp)
  --no-color                Disable colored terminal output

TUNING:
  --smtp-timeout <secs>     SMTP probe timeout (default: 6)
  --dns-timeout <secs>      DNS query timeout (default: 3)
  --skip-smtp               Skip SMTP connectivity tests
  --skip-tls                Skip TLS certificate tests
  --dkim-selectors <s1,s2>  Additional DKIM selectors to test (comma-separated)
  -v, --verbose             Show extra diagnostic details

CONFIG FILE:
  --config <file>           Load settings from file (KEY=VALUE format)

EXAMPLES:
  # 2-hop: GitHub notifications → Gmail
  ./mail-chain-audit.sh --sender github.com --dest gmail.com --dir reports/

  # 2-hop: Stripe receipts → Outlook.com
  ./mail-chain-audit.sh --sender stripe.com --dest outlook.com --skip-smtp

  # 3-hop: Shopify alerts → university alumni relay → Gmail
  ./mail-chain-audit.sh \
    --sender shopify.com \
    --relay harvard.edu \
    --dest gmail.com \
    --dir reports/

  # 3-hop: AWS notifications → corporate relay → Microsoft 365
  ./mail-chain-audit.sh \
    --sender amazon.com \
    --relay stanford.edu \
    --relay-recipient admin@stanford.edu \
    --dest microsoft.com \
    --dir reports/

  # Quick DNS-only check (skip slow SMTP/TLS probes)
  ./mail-chain-audit.sh --sender linkedin.com --dest yahoo.com --skip-smtp --skip-tls

  # From config file
  ./mail-chain-audit.sh --config mychain.conf --html report.html

CONFIG FILE FORMAT (mychain.conf):
  SENDER_DOMAIN=github.com
  SENDER_EMAIL=noreply@github.com
  RELAY_DOMAIN=stanford.edu
  RELAY_RECIPIENT=user@stanford.edu
  DEST_DOMAIN=gmail.com
  DEST_RECIPIENT=user@gmail.com
USAGE
    exit 0
}

# ── Argument parsing ──────────────────────────────────────────────────────────
[[ $# -eq 0 ]] && usage

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sender)           SENDER_DOMAIN="$2"; shift 2 ;;
        --sender-email)     SENDER_EMAIL="$2"; shift 2 ;;
        --sender-ip)        SENDER_IP="$2"; shift 2 ;;
        --relay)            RELAY_DOMAIN="$2"; shift 2 ;;
        --relay-mx-ip)      RELAY_MX_IP="$2"; shift 2 ;;
        --relay-backend-ip) RELAY_BACKEND_IP="$2"; shift 2 ;;
        --relay-recipient)  RELAY_RECIPIENT="$2"; shift 2 ;;
        --dest)             DEST_DOMAIN="$2"; shift 2 ;;
        --dest-recipient)   DEST_RECIPIENT="$2"; shift 2 ;;
        --config)           CONFIG_FILE="$2"; shift 2 ;;
        --html)             REPORT_HTML="$2"; shift 2 ;;
        --json)             REPORT_JSON="$2"; shift 2 ;;
        --dir)              REPORT_DIR="$2"; shift 2 ;;
        --no-color)         NO_COLOR=1; shift ;;
        --skip-smtp)        SKIP_SMTP=1; shift ;;
        --skip-tls)         SKIP_TLS=1; shift ;;
        --smtp-timeout)     SMTP_TIMEOUT="$2"; shift 2 ;;
        --dns-timeout)      DIG_TIMEOUT="$2"; shift 2 ;;
        --dkim-selectors)   IFS=',' read -ra EXTRA_DKIM_SELECTORS <<< "$2"; shift 2 ;;
        -v|--verbose)       VERBOSE=1; shift ;;
        -h|--help)          usage ;;
        --version)          echo "mail-chain-audit $VERSION"; exit 0 ;;
        *) echo "Unknown option: $1 (use --help)"; exit 1 ;;
    esac
done

# ── Load config file ─────────────────────────────────────────────────────────
if [[ -n "$CONFIG_FILE" ]]; then
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "Error: config file not found: $CONFIG_FILE" >&2
        exit 1
    fi
    while IFS='=' read -r key value; do
        [[ "$key" =~ ^#.*$ || -z "$key" ]] && continue
        key=$(echo "$key" | xargs)
        value=$(echo "$value" | xargs)
        case "$key" in
            SENDER_DOMAIN)    [[ -z "$SENDER_DOMAIN" ]]    && SENDER_DOMAIN="$value" ;;
            SENDER_EMAIL)     [[ -z "$SENDER_EMAIL" ]]     && SENDER_EMAIL="$value" ;;
            SENDER_IP)        [[ -z "$SENDER_IP" ]]        && SENDER_IP="$value" ;;
            RELAY_DOMAIN)     [[ -z "$RELAY_DOMAIN" ]]     && RELAY_DOMAIN="$value" ;;
            RELAY_MX_IP)      [[ -z "$RELAY_MX_IP" ]]      && RELAY_MX_IP="$value" ;;
            RELAY_BACKEND_IP) [[ -z "$RELAY_BACKEND_IP" ]]  && RELAY_BACKEND_IP="$value" ;;
            RELAY_RECIPIENT)  [[ -z "$RELAY_RECIPIENT" ]]   && RELAY_RECIPIENT="$value" ;;
            DEST_DOMAIN)      [[ -z "$DEST_DOMAIN" ]]      && DEST_DOMAIN="$value" ;;
            DEST_RECIPIENT)   [[ -z "$DEST_RECIPIENT" ]]    && DEST_RECIPIENT="$value" ;;
            DKIM_SELECTORS)   IFS=',' read -ra EXTRA_DKIM_SELECTORS <<< "$value" ;;
        esac
    done < "$CONFIG_FILE"
fi

# ── Validation ────────────────────────────────────────────────────────────────
if [[ -z "$SENDER_DOMAIN" || -z "$DEST_DOMAIN" ]]; then
    echo "Error: --sender and --dest are required (or provide them in --config)" >&2
    exit 1
fi

# Merge extra DKIM selectors
DKIM_SELECTORS+=("${EXTRA_DKIM_SELECTORS[@]}")

# Determine chain mode
HAS_RELAY=0
[[ -n "$RELAY_DOMAIN" ]] && HAS_RELAY=1

# ── Colors ────────────────────────────────────────────────────────────────────
if [[ "$NO_COLOR" -eq 1 ]] || [[ ! -t 1 ]]; then
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; DIM=''; RESET=''
else
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
    BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
fi

pass()  { echo -e "  ${GREEN}[PASS]${RESET} $1"; }
fail()  { echo -e "  ${RED}[FAIL]${RESET} $1"; }
warn()  { echo -e "  ${YELLOW}[WARN]${RESET} $1"; }
info()  { echo -e "  ${CYAN}[INFO]${RESET} $1"; }
header(){ echo -e "\n${BOLD}━━━ $1 ━━━${RESET}"; }
debug() { [[ "$VERBOSE" -eq 1 ]] && echo -e "  ${DIM}[DBG] $1${RESET}"; }

# ── Report output directory ───────────────────────────────────────────────────
if [[ -n "$REPORT_DIR" ]]; then
    mkdir -p "$REPORT_DIR"
    ts=$(date +%Y%m%d_%H%M%S)
    REPORT_HTML="${REPORT_DIR}/mail-chain-audit_${ts}.html"
    REPORT_JSON="${REPORT_DIR}/mail-chain-audit_${ts}.json"
fi

# ── Results collection ────────────────────────────────────────────────────────
declare -a RESULTS=()
declare -a FINDINGS=()
PASS_COUNT=0; FAIL_COUNT=0; WARN_COUNT=0; INFO_COUNT=0

add_result() {
    local section="$1" test_name="$2" status="$3" detail="$4"
    RESULTS+=("$(printf '{"section":"%s","test":"%s","status":"%s","detail":"%s"}' \
        "$section" "$test_name" "$status" "$(echo "$detail" | sed 's/"/\\"/g' | tr '\n' ' ')")")
    case "$status" in
        PASS) ((PASS_COUNT++)) ;;
        FAIL) ((FAIL_COUNT++)); FINDINGS+=("FAIL: [$section] $test_name — $detail") ;;
        WARN) ((WARN_COUNT++)); FINDINGS+=("WARN: [$section] $test_name — $detail") ;;
        INFO) ((INFO_COUNT++)) ;;
    esac
}

# ── Helpers ───────────────────────────────────────────────────────────────────
sdig() { dig +short +time=$DIG_TIMEOUT "$@" 2>/dev/null || echo ""; }

ip_in_cidr() {
    local ip="$1" cidr="$2"
    python3 -c "
import ipaddress, sys
try:
    result = ipaddress.ip_address('$ip') in ipaddress.ip_network('$cidr', strict=False)
    sys.exit(0 if result else 1)
except:
    sys.exit(1)
" 2>/dev/null
}

check_spf_ip() {
    local domain="$1" ip="$2" depth="${3:-0}"
    [[ $depth -gt 10 ]] && return 1  # SPF spec allows max 10 DNS lookups

    local spf_raw spf_record
    spf_raw=$(sdig TXT "$domain" | tr -d '"')
    spf_record=$(echo "$spf_raw" | grep -o 'v=spf1[^"]*' | head -1)
    [[ -z "$spf_record" ]] && return 1

    # ip4: directives
    for cidr in $(echo "$spf_record" | grep -oP 'ip4:\K[^\s]+'); do
        if [[ "$cidr" == */* ]]; then
            ip_in_cidr "$ip" "$cidr" && return 0
        else
            [[ "$ip" == "$cidr" ]] && return 0
        fi
    done

    # ip6: directives
    for cidr in $(echo "$spf_record" | grep -oP 'ip6:\K[^\s]+'); do
        ip_in_cidr "$ip" "$cidr" 2>/dev/null && return 0
    done

    # a: directives (explicit hosts)
    for host in $(echo "$spf_record" | grep -oP 'a:\K[^\s]+'); do
        local resolved
        resolved=$(sdig A "$host")
        for rip in $resolved; do
            [[ "$ip" == "$rip" ]] && return 0
        done
    done

    # bare "a" directive (domain itself)
    if echo "$spf_record" | grep -qP '(\s|^)a(\s|$)'; then
        local self_ips
        self_ips=$(sdig A "$domain")
        for rip in $self_ips; do
            [[ "$ip" == "$rip" ]] && return 0
        done
    fi

    # mx directive
    if echo "$spf_record" | grep -qP '(\s|^)mx(\s|$)'; then
        local mx_hosts
        mx_hosts=$(sdig MX "$domain" | awk '{print $2}')
        for mxh in $mx_hosts; do
            local mxip
            mxip=$(sdig A "$mxh")
            for rip in $mxip; do
                [[ "$ip" == "$rip" ]] && return 0
            done
        done
    fi

    # include: directives (recursive)
    for inc in $(echo "$spf_record" | grep -oP 'include:\K[^\s]+'); do
        check_spf_ip "$inc" "$ip" $((depth+1)) && return 0
    done

    # redirect= directive (replaces entire SPF evaluation with another domain)
    local redirect
    redirect=$(echo "$spf_record" | grep -oP 'redirect=\K[^\s]+')
    if [[ -n "$redirect" ]]; then
        check_spf_ip "$redirect" "$ip" $((depth+1)) && return 0
    fi

    return 1
}

smtp_probe() {
    local host="$1" port="$2" timeout="${3:-$SMTP_TIMEOUT}"
    local result
    result=$(timeout "$timeout" bash -c "
        (echo 'EHLO audit.probe'; sleep 2; echo 'QUIT') | \
        nc -w $((timeout-2)) $host $port 2>&1
    " 2>&1) || true
    echo "$result"
}

resolve_mx_ip() {
    local domain="$1"
    local mx_host
    mx_host=$(sdig MX "$domain" | sort -n | head -1 | awk '{print $2}')
    [[ -z "$mx_host" ]] && return
    # Resolve CNAME if present
    local cname
    cname=$(sdig CNAME "$mx_host")
    if [[ -n "$cname" ]]; then
        sdig A "$cname" | head -1
    else
        sdig A "$mx_host" | head -1
    fi
}

# ── Auto-resolve missing values ──────────────────────────────────────────────
auto_resolve() {
    header "Pre-flight: Auto-resolving missing parameters"

    # Sender email
    if [[ -z "$SENDER_EMAIL" ]]; then
        SENDER_EMAIL="postmaster@${SENDER_DOMAIN}"
        info "Sender email: $SENDER_EMAIL (default)"
    fi

    # Sender IP — only use if explicitly provided
    # NOTE: MX records are for RECEIVING mail, not sending. Auto-resolving
    # sender IP from MX would produce false positives (e.g., Google MX IP
    # won't be in Shopify's SPF even though Shopify sends via Google).
    # The real sender IP comes from mail logs / headers.
    if [[ -z "$SENDER_IP" ]]; then
        SENDER_IP_AUTO=1
        warn "No --sender-ip provided — sender SPF authorization test will be skipped"
        warn "Provide the actual sending IP from mail headers for accurate results"
    else
        SENDER_IP_AUTO=0
        debug "Sender IP provided: $SENDER_IP"
    fi

    # Destination recipient
    if [[ -z "$DEST_RECIPIENT" ]]; then
        DEST_RECIPIENT="postmaster@${DEST_DOMAIN}"
        info "Dest recipient: $DEST_RECIPIENT (default)"
    fi

    if [[ "$HAS_RELAY" -eq 1 ]]; then
        # Relay recipient
        if [[ -z "$RELAY_RECIPIENT" ]]; then
            RELAY_RECIPIENT="postmaster@${RELAY_DOMAIN}"
            info "Relay recipient: $RELAY_RECIPIENT (default)"
        fi

        # Relay MX IP
        if [[ -z "$RELAY_MX_IP" ]]; then
            RELAY_MX_IP=$(resolve_mx_ip "$RELAY_DOMAIN")
            if [[ -n "$RELAY_MX_IP" ]]; then
                info "Relay MX IP auto-resolved: $RELAY_MX_IP"
            else
                warn "Could not auto-resolve relay MX IP"
            fi
        else
            debug "Relay MX IP provided: $RELAY_MX_IP"
        fi

        # Relay backend defaults to MX IP if not specified
        if [[ -z "$RELAY_BACKEND_IP" ]]; then
            RELAY_BACKEND_IP="$RELAY_MX_IP"
            info "Relay backend IP: same as MX ($RELAY_MX_IP)"
        else
            if [[ "$RELAY_BACKEND_IP" != "$RELAY_MX_IP" ]]; then
                info "Relay backend IP ($RELAY_BACKEND_IP) differs from MX IP ($RELAY_MX_IP) — split architecture"
            fi
        fi
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# ██ MAIN
# ══════════════════════════════════════════════════════════════════════════════

# Determine chain mode
if [[ "$HAS_RELAY" -eq 1 ]]; then
    CHAIN_MODE="3-hop (sender → relay → destination)"
else
    CHAIN_MODE="2-hop (sender → destination)"
fi

auto_resolve

# Build chain description (after auto_resolve so emails are populated)
if [[ "$HAS_RELAY" -eq 1 ]]; then
    CHAIN_DESC="$SENDER_EMAIL → ${RELAY_RECIPIENT:-$RELAY_DOMAIN} → ${DEST_RECIPIENT:-$DEST_DOMAIN}"
else
    CHAIN_DESC="${SENDER_EMAIL:-$SENDER_DOMAIN} → ${DEST_RECIPIENT:-$DEST_DOMAIN}"
fi

echo -e "${BOLD} Email Forwarding Chain — Diagnostic Audit ${RESET}"
echo -e "${BOLD} $CHAIN_DESC ${RESET}"
echo -e "${DIM}Mode: $CHAIN_MODE | Timestamp: $TIMESTAMP_HUMAN${RESET}"

# Build list of domains to test and IPs to check rDNS
declare -a ALL_DOMAINS=()
declare -a ALL_IPS=()
declare -a DOMAIN_LABELS=()

ALL_DOMAINS+=("$SENDER_DOMAIN"); DOMAIN_LABELS+=("Sender")
if [[ "$HAS_RELAY" -eq 1 ]]; then
    ALL_DOMAINS+=("$RELAY_DOMAIN"); DOMAIN_LABELS+=("Relay")
fi
ALL_DOMAINS+=("$DEST_DOMAIN"); DOMAIN_LABELS+=("Destination")

[[ -n "$SENDER_IP" && "${SENDER_IP_AUTO:-0}" -eq 0 ]] && ALL_IPS+=("Sender:$SENDER_IP")
if [[ "$HAS_RELAY" -eq 1 ]]; then
    [[ -n "$RELAY_MX_IP" ]] && ALL_IPS+=("Relay MX:$RELAY_MX_IP")
    [[ -n "$RELAY_BACKEND_IP" && "$RELAY_BACKEND_IP" != "$RELAY_MX_IP" ]] && ALL_IPS+=("Relay Backend:$RELAY_BACKEND_IP")
fi

# ── 1. DNS Resolution ────────────────────────────────────────────────────────
header "1. DNS Resolution"

for i in "${!ALL_DOMAINS[@]}"; do
    domain="${ALL_DOMAINS[$i]}"
    label="${DOMAIN_LABELS[$i]}"

    mx=$(sdig MX "$domain")
    if [[ -n "$mx" ]]; then
        pass "$label MX ($domain): $mx"
        add_result "DNS" "$label MX" "PASS" "$mx"
        mx_host=$(echo "$mx" | sort -n | head -1 | awk '{print $2}')

        # CNAME check
        cname=$(sdig CNAME "$mx_host")
        if [[ -n "$cname" ]]; then
            warn "$label MX $mx_host is a CNAME → $cname (RFC 2181 violation)"
            add_result "DNS" "$label MX CNAME" "WARN" "$mx_host CNAMEs to $cname — violates RFC 2181"
        fi

        # Resolve IP
        mx_ip=$(sdig A "$mx_host")
        [[ -z "$mx_ip" && -n "$cname" ]] && mx_ip=$(sdig A "$cname")
        info "$label MX resolves to: $mx_ip"
        add_result "DNS" "$label MX IP" "INFO" "$mx_ip"

        # Redundancy
        mx_count=$(echo "$mx" | grep -c . || true)
        if [[ "$mx_count" -le 1 ]]; then
            warn "$domain has only $mx_count MX record — no redundancy"
            add_result "DNS" "$label MX redundancy" "WARN" "Single MX — no failover"
        else
            pass "$domain has $mx_count MX records"
            add_result "DNS" "$label MX redundancy" "PASS" "$mx_count MX records"
        fi

        # IPv6
        aaaa=$(sdig AAAA "$mx_host")
        if [[ -z "$aaaa" ]]; then
            [[ -n "$cname" ]] && aaaa=$(sdig AAAA "$cname")
        fi
        if [[ -z "$aaaa" ]]; then
            info "$label MX: no AAAA record (no IPv6)"
            add_result "DNS" "$label IPv6" "INFO" "No AAAA record"
        else
            pass "$label MX IPv6: $aaaa"
            add_result "DNS" "$label IPv6" "PASS" "$aaaa"
        fi
    else
        fail "$label: no MX record for $domain"
        add_result "DNS" "$label MX" "FAIL" "No MX record found"
    fi
done

# ── 2. Reverse DNS ───────────────────────────────────────────────────────────
header "2. Reverse DNS (PTR Records)"

for label_ip in "${ALL_IPS[@]}"; do
    label="${label_ip%%:*}"
    ip="${label_ip##*:}"
    rev=$(echo "$ip" | awk -F. '{print $4"."$3"."$2"."$1".in-addr.arpa"}')
    ptr=$(sdig PTR "$rev")
    if [[ -n "$ptr" ]]; then
        pass "$label ($ip) PTR: $ptr"
        add_result "rDNS" "$label PTR" "PASS" "$ptr"
        # FCrDNS
        fwd=$(sdig A "$ptr")
        if echo "$fwd" | grep -q "$ip"; then
            pass "$label FCrDNS: $ptr → $ip (matches)"
            add_result "rDNS" "$label FCrDNS" "PASS" "Forward-confirmed"
        else
            warn "$label FCrDNS mismatch: $ptr → $fwd (expected $ip)"
            add_result "rDNS" "$label FCrDNS" "WARN" "PTR $ptr resolves to $fwd, not $ip"
        fi
    else
        fail "$label ($ip) has NO PTR record — mail penalized/rejected"
        add_result "rDNS" "$label PTR" "FAIL" "No PTR record for $ip"
    fi
done

# ── 3. SPF Records ───────────────────────────────────────────────────────────
header "3. SPF Records"

for i in "${!ALL_DOMAINS[@]}"; do
    domain="${ALL_DOMAINS[$i]}"
    label="${DOMAIN_LABELS[$i]}"
    spf=$(sdig TXT "$domain" | tr -d '"' | grep 'v=spf1' | head -1)
    if [[ -n "$spf" ]]; then
        pass "$label SPF ($domain): $spf"
        add_result "SPF" "$label record" "PASS" "$spf"
        if echo "$spf" | grep -q '\-all'; then
            pass "$label SPF policy: -all (hard fail)"
            add_result "SPF" "$label policy" "PASS" "Hard fail (-all)"
        elif echo "$spf" | grep -q '~all'; then
            warn "$label SPF policy: ~all (soft fail)"
            add_result "SPF" "$label policy" "WARN" "Soft fail (~all)"
        elif echo "$spf" | grep -q '?all'; then
            warn "$label SPF policy: ?all (neutral)"
            add_result "SPF" "$label policy" "WARN" "Neutral (?all)"
        fi
    else
        fail "$label has no SPF record ($domain)"
        add_result "SPF" "$label record" "FAIL" "No SPF record"
    fi
done

# ── 4. SPF Authorization — Forwarding Chain ──────────────────────────────────
header "4. SPF Authorization — Forwarding Chain"

echo -e "  ${DIM}Testing if each hop's IP is authorized by the relevant SPF...${RESET}"

# Sender IP → Sender SPF (baseline — only when IP was explicitly provided)
if [[ -n "$SENDER_IP" && "${SENDER_IP_AUTO:-0}" -eq 0 ]]; then
    if check_spf_ip "$SENDER_DOMAIN" "$SENDER_IP"; then
        pass "Sender IP $SENDER_IP authorized by $SENDER_DOMAIN SPF"
        add_result "SPF Auth" "Sender IP in sender SPF" "PASS" "$SENDER_IP is in $SENDER_DOMAIN SPF"
    else
        fail "Sender IP $SENDER_IP NOT in $SENDER_DOMAIN SPF"
        add_result "SPF Auth" "Sender IP in sender SPF" "FAIL" "$SENDER_IP is NOT in $SENDER_DOMAIN SPF"
    fi
else
    info "Sender IP not provided — skipping sender SPF authorization check (use --sender-ip for this test)"
    add_result "SPF Auth" "Sender IP in sender SPF" "INFO" "Skipped — provide --sender-ip from mail headers for accurate check"
fi

if [[ "$HAS_RELAY" -eq 1 ]]; then
    # The critical test: relay's forwarding IP vs sender's SPF
    fwd_ip="${RELAY_BACKEND_IP:-$RELAY_MX_IP}"
    if [[ -n "$fwd_ip" ]]; then
        if check_spf_ip "$SENDER_DOMAIN" "$fwd_ip"; then
            pass "Forwarding IP $fwd_ip authorized by $SENDER_DOMAIN SPF (unusual)"
            add_result "SPF Auth" "Forward IP in sender SPF" "PASS" "$fwd_ip in $SENDER_DOMAIN SPF"
        else
            fail "Forwarding IP $fwd_ip NOT in $SENDER_DOMAIN SPF — forwarded mail FAILS SPF at destination"
            add_result "SPF Auth" "Forward IP in sender SPF" "FAIL" "$fwd_ip not in $SENDER_DOMAIN SPF — SPF breaks on forward"
        fi

        # Is forwarding IP trusted by destination?
        if check_spf_ip "$DEST_DOMAIN" "$fwd_ip"; then
            pass "Forwarding IP $fwd_ip is in $DEST_DOMAIN SPF (trusted forwarder)"
            add_result "SPF Auth" "Trusted forwarder" "PASS" "$fwd_ip in $DEST_DOMAIN SPF"
        else
            fail "Forwarding IP $fwd_ip NOT in $DEST_DOMAIN SPF — not a trusted forwarder"
            add_result "SPF Auth" "Trusted forwarder" "FAIL" "$fwd_ip not in $DEST_DOMAIN SPF"
        fi
    fi

    # Also check relay MX if it differs from backend
    if [[ -n "$RELAY_MX_IP" && "$RELAY_MX_IP" != "$RELAY_BACKEND_IP" ]]; then
        if check_spf_ip "$DEST_DOMAIN" "$RELAY_MX_IP"; then
            pass "Relay MX $RELAY_MX_IP is in $DEST_DOMAIN SPF"
            add_result "SPF Auth" "Relay MX in dest SPF" "PASS" "$RELAY_MX_IP in $DEST_DOMAIN SPF"
        else
            fail "Relay MX $RELAY_MX_IP NOT in $DEST_DOMAIN SPF"
            add_result "SPF Auth" "Relay MX in dest SPF" "FAIL" "$RELAY_MX_IP not in $DEST_DOMAIN SPF"
        fi
    fi
else
    # 2-hop: just check sender IP vs destination SPF (only with explicit IP)
    if [[ -n "$SENDER_IP" && "${SENDER_IP_AUTO:-0}" -eq 0 ]]; then
        if check_spf_ip "$DEST_DOMAIN" "$SENDER_IP"; then
            info "Sender IP $SENDER_IP is in $DEST_DOMAIN SPF"
            add_result "SPF Auth" "Sender in dest SPF" "INFO" "$SENDER_IP in $DEST_DOMAIN SPF"
        else
            info "Sender IP $SENDER_IP not in $DEST_DOMAIN SPF (expected — sender uses own domain's SPF)"
            add_result "SPF Auth" "Sender in dest SPF" "INFO" "Not in dest SPF (normal for direct delivery)"
        fi
    fi
fi

# ── 5. DKIM Discovery ────────────────────────────────────────────────────────
header "5. DKIM Selector Discovery"

for i in "${!ALL_DOMAINS[@]}"; do
    domain="${ALL_DOMAINS[$i]}"
    label="${DOMAIN_LABELS[$i]}"
    found=0
    for sel in "${DKIM_SELECTORS[@]}"; do
        dkim=$(sdig TXT "${sel}._domainkey.${domain}")
        if [[ -n "$dkim" ]]; then
            ((found++))
            dkim_cname=$(sdig CNAME "${sel}._domainkey.${domain}")
            if [[ -n "$dkim_cname" ]]; then
                pass "$label DKIM: ${sel}._domainkey.${domain} → CNAME $dkim_cname"
                add_result "DKIM" "$label selector '$sel'" "PASS" "Delegated via CNAME to $dkim_cname"
            else
                key_len=""
                if echo "$dkim" | tr -d '"' | grep -qP 'p=[A-Za-z0-9+/=]+'; then
                    pubkey=$(echo "$dkim" | tr -d '"' | grep -oP 'p=\K[A-Za-z0-9+/=]+')
                    key_bytes=$(echo "$pubkey" | base64 -d 2>/dev/null | wc -c)
                    key_bits=$((key_bytes * 8))
                    key_len=" (${key_bits}-bit)"
                    if [[ $key_bits -lt 1024 ]]; then
                        warn "$label DKIM '$sel': ${key_bits}-bit key (minimum 1024 recommended)"
                        add_result "DKIM" "$label key strength '$sel'" "WARN" "${key_bits}-bit — weak"
                    fi
                fi
                pass "$label DKIM: ${sel}._domainkey.${domain}${key_len}"
                add_result "DKIM" "$label selector '$sel'" "PASS" "Found${key_len}"
            fi
        fi
    done
    if [[ $found -eq 0 ]]; then
        warn "$label: no DKIM selectors found (tested ${#DKIM_SELECTORS[@]} selectors)"
        add_result "DKIM" "$label discovery" "WARN" "No selectors found"
    fi
done

# ── 6. DMARC Records ─────────────────────────────────────────────────────────
header "6. DMARC Records"

for i in "${!ALL_DOMAINS[@]}"; do
    domain="${ALL_DOMAINS[$i]}"
    label="${DOMAIN_LABELS[$i]}"
    dmarc=$(sdig TXT "_dmarc.${domain}" | tr -d '"')
    if [[ -n "$dmarc" ]]; then
        info "$label DMARC (_dmarc.${domain}): $dmarc"
        add_result "DMARC" "$label record" "INFO" "$dmarc"

        policy=$(echo "$dmarc" | grep -oP '(?<![a-z])p=\K[^;]+' | head -1 | tr -d ' ')
        case "$policy" in
            reject)
                pass "$label DMARC policy: reject (maximum enforcement)"
                add_result "DMARC" "$label policy" "PASS" "reject" ;;
            quarantine)
                warn "$label DMARC policy: quarantine (medium — failing mail goes to spam)"
                add_result "DMARC" "$label policy" "WARN" "quarantine — not reject" ;;
            none)
                fail "$label DMARC policy: none (monitoring only)"
                add_result "DMARC" "$label policy" "FAIL" "none — no enforcement" ;;
        esac

        aspf=$(echo "$dmarc" | grep -oP 'aspf=\K[^;]+' | tr -d ' ')
        adkim=$(echo "$dmarc" | grep -oP 'adkim=\K[^;]+' | tr -d ' ')
        [[ -n "$aspf" ]] && info "$label SPF alignment: ${aspf} ($([ "$aspf" = "s" ] && echo strict || echo relaxed))"
        [[ -n "$adkim" ]] && info "$label DKIM alignment: ${adkim} ($([ "$adkim" = "s" ] && echo strict || echo relaxed))"

        sp=$(echo "$dmarc" | grep -oP 'sp=\K[^;]+' | tr -d ' ')
        [[ -n "$sp" ]] && info "$label subdomain policy: $sp"

        rua=$(echo "$dmarc" | grep -oP 'rua=\K[^;]+' | tr -d ' ')
        ruf=$(echo "$dmarc" | grep -oP 'ruf=\K[^;]+' | tr -d ' ')
        [[ -n "$rua" ]] && info "$label aggregate reports → $rua"
        [[ -n "$ruf" ]] && info "$label forensic reports → $ruf"
        [[ -z "$ruf" ]] && warn "$label: no forensic (ruf) reporting"
    else
        fail "$label has no DMARC record (_dmarc.${domain})"
        add_result "DMARC" "$label record" "FAIL" "No DMARC record"
    fi
done

# ── 7. Forwarding Impact Simulation (only for 3-hop) ─────────────────────────
FORWARD_BROKEN=0  # Track whether forwarding chain has actual failures

if [[ "$HAS_RELAY" -eq 1 ]]; then
    header "7. DMARC Forwarding Impact Simulation"

    fwd_ip="${RELAY_BACKEND_IP:-$RELAY_MX_IP}"
    echo -e "  ${DIM}Simulating what happens when mail from $SENDER_DOMAIN is forwarded by $fwd_ip to $DEST_DOMAIN...${RESET}"

    sender_dmarc=$(sdig TXT "_dmarc.${SENDER_DOMAIN}" | tr -d '"')
    sender_policy=$(echo "$sender_dmarc" | grep -oP '(?<![a-z])p=\K[^;]+' | head -1 | tr -d ' ')
    sender_aspf=$(echo "$sender_dmarc" | grep -oP 'aspf=\K[^;]+' | tr -d ' ')
    sender_adkim=$(echo "$sender_dmarc" | grep -oP 'adkim=\K[^;]+' | tr -d ' ')

    info "Sender DMARC: p=${sender_policy:-none} aspf=${sender_aspf:-r} adkim=${sender_adkim:-r}"
    add_result "Forward Sim" "Sender DMARC" "INFO" "p=${sender_policy:-none} aspf=${sender_aspf:-r} adkim=${sender_adkim:-r}"

    # SPF at destination
    fwd_spf_pass=0
    if [[ -n "$fwd_ip" ]]; then
        if check_spf_ip "$SENDER_DOMAIN" "$fwd_ip"; then
            pass "SPF alignment would PASS (relay IP in sender SPF)"
            add_result "Forward Sim" "SPF at destination" "PASS" "Relay IP authorized"
            fwd_spf_pass=1
        else
            fail "SPF alignment FAILS — $fwd_ip not in $SENDER_DOMAIN SPF"
            add_result "Forward Sim" "SPF at destination" "FAIL" "$fwd_ip not in $SENDER_DOMAIN SPF"
            FORWARD_BROKEN=1
        fi
    fi

    # DKIM
    warn "DKIM survival: UNKNOWN — forwarding servers commonly modify headers which breaks DKIM"
    add_result "Forward Sim" "DKIM survival" "WARN" "Cannot verify without actual forwarded headers"

    # DMARC verdict — only FAIL if SPF failed (we can't know DKIM status)
    dest_dmarc=$(sdig TXT "_dmarc.${DEST_DOMAIN}" | tr -d '"')
    dest_policy=$(echo "$dest_dmarc" | grep -oP '(?<![a-z])p=\K[^;]+' | head -1 | tr -d ' ')

    if [[ "$fwd_spf_pass" -eq 1 ]]; then
        pass "DMARC may PASS if DKIM signature survives forwarding"
        add_result "Forward Sim" "DMARC verdict" "PASS" "SPF passes — DMARC can pass even if DKIM breaks"
    else
        fail "DMARC verdict at $DEST_DOMAIN: FAIL → sender policy '${sender_policy:-none}', dest policy '${dest_policy:-none}'"
        add_result "Forward Sim" "DMARC verdict" "FAIL" "SPF fails and DKIM likely fails → policies apply"
        FORWARD_BROKEN=1
    fi

    case "${sender_policy:-none}" in
        reject)
            if [[ "$fwd_spf_pass" -eq 0 ]]; then
                fail "CRITICAL: Sender has p=reject — forwarded mail REJECTED outright"
                add_result "Forward Sim" "Impact" "FAIL" "p=reject means mail dropped"
                FORWARD_BROKEN=1
            fi ;;
        quarantine)
            if [[ "$fwd_spf_pass" -eq 0 ]]; then
                warn "Sender has p=quarantine — forwarded mail goes to SPAM"
                add_result "Forward Sim" "Impact" "WARN" "Mail quarantined at destination"
                FORWARD_BROKEN=1
            fi ;;
        none)
            info "Sender has p=none — mail delivered but DMARC reports generated"
            add_result "Forward Sim" "Impact" "INFO" "No enforcement, monitoring only" ;;
    esac
fi

# ── 8. Forwarding Mitigations (SRS / ARC) ────────────────────────────────────
if [[ "$HAS_RELAY" -eq 1 ]]; then
    header "8. Forwarding Mitigation Checks (SRS / ARC)"

    srs_record=$(sdig TXT "_srs.$RELAY_DOMAIN")
    if [[ -n "$srs_record" ]]; then
        pass "SRS record for $RELAY_DOMAIN: $srs_record"
        add_result "Mitigations" "SRS" "PASS" "$srs_record"
    else
        fail "No SRS record for $RELAY_DOMAIN — envelope-from not rewritten on forward"
        add_result "Mitigations" "SRS" "FAIL" "No _srs.$RELAY_DOMAIN — forwarding breaks SPF without SRS"
    fi

    info "ARC sealing: must be configured on the forwarding server — cannot verify via DNS"
    add_result "Mitigations" "ARC" "INFO" "ARC must be configured on forwarding server"

    # Detect if destination is M365
    dest_mx_check=$(sdig MX "$DEST_DOMAIN" | grep -i "protection.outlook.com" || true)
    if [[ -n "$dest_mx_check" ]]; then
        info "Destination uses Microsoft 365 — supports ARC validation for trusted sealers"
        warn "Verify in M365 admin: Is $RELAY_DOMAIN configured as a trusted ARC sealer?"
        add_result "Mitigations" "M365 ARC sealer" "WARN" "Check M365 Exchange Online admin"
    fi
fi

# ── 9. SMTP Connectivity ─────────────────────────────────────────────────────
if [[ "$SKIP_SMTP" -eq 0 ]]; then
    header "9. SMTP Connectivity"

    # Build list of IPs to probe
    declare -a SMTP_TARGETS=()
    if [[ "$HAS_RELAY" -eq 1 ]]; then
        [[ -n "$RELAY_MX_IP" ]] && SMTP_TARGETS+=("Relay MX:$RELAY_MX_IP")
        [[ -n "$RELAY_BACKEND_IP" && "$RELAY_BACKEND_IP" != "$RELAY_MX_IP" ]] && SMTP_TARGETS+=("Relay Backend:$RELAY_BACKEND_IP")
    fi

    for label_ip in "${SMTP_TARGETS[@]}"; do
        label="${label_ip%%:*}"
        ip="${label_ip##*:}"
        for port in "${SMTP_PORTS[@]}"; do
            echo -e "  ${DIM}Testing $label ($ip) port $port...${RESET}"
            banner=$(smtp_probe "$ip" "$port")
            if echo "$banner" | grep -qiE "^(220|250)"; then
                smtp_host=$(echo "$banner" | grep -m1 "^220" | head -1)
                pass "$label port $port OPEN: $smtp_host"
                add_result "SMTP" "$label port $port" "PASS" "$smtp_host"
                if echo "$banner" | grep -qi "STARTTLS"; then
                    pass "$label port $port supports STARTTLS"
                    add_result "SMTP" "$label STARTTLS" "PASS" "STARTTLS advertised"
                else
                    warn "$label port $port: no STARTTLS"
                    add_result "SMTP" "$label STARTTLS" "WARN" "No STARTTLS"
                fi
            elif echo "$banner" | grep -qi "timed out\|refused\|unreachable"; then
                fail "$label port $port UNREACHABLE"
                add_result "SMTP" "$label port $port" "FAIL" "Connection timed out or refused"
            else
                warn "$label port $port — unexpected: $(echo "$banner" | head -1)"
                add_result "SMTP" "$label port $port" "WARN" "Unexpected response"
            fi
        done
    done

    # Destination MX
    dest_mx_host=$(sdig MX "$DEST_DOMAIN" | sort -n | head -1 | awk '{print $2}')
    if [[ -n "$dest_mx_host" ]]; then
        echo -e "  ${DIM}Testing destination MX ($dest_mx_host)...${RESET}"
        first_dest_ip=$(sdig A "$dest_mx_host" | head -1)
        if [[ -n "$first_dest_ip" ]]; then
            banner=$(smtp_probe "$first_dest_ip" 25)
            if echo "$banner" | grep -qiE "^(220|250)"; then
                pass "Destination MX ($first_dest_ip) port 25 OPEN"
                add_result "SMTP" "Dest MX port 25" "PASS" "Reachable"
            else
                fail "Destination MX ($first_dest_ip) port 25 unreachable"
                add_result "SMTP" "Dest MX port 25" "FAIL" "Unreachable from this host"
            fi
        fi
    fi
else
    header "9. SMTP Connectivity — SKIPPED"
    info "SMTP tests skipped (--skip-smtp)"
fi

# ── 10. TLS Certificate Check ────────────────────────────────────────────────
if [[ "$SKIP_TLS" -eq 0 && "$SKIP_SMTP" -eq 0 ]]; then
    header "10. TLS Certificate Check"

    declare -a TLS_TARGETS=()
    if [[ "$HAS_RELAY" -eq 1 ]]; then
        [[ -n "$RELAY_MX_IP" ]] && TLS_TARGETS+=("Relay MX:$RELAY_MX_IP:25")
        [[ -n "$RELAY_BACKEND_IP" && "$RELAY_BACKEND_IP" != "$RELAY_MX_IP" ]] && TLS_TARGETS+=("Relay Backend:$RELAY_BACKEND_IP:25")
    fi

    for label_ip_port in "${TLS_TARGETS[@]}"; do
        label="${label_ip_port%%:*}"
        rest="${label_ip_port#*:}"
        ip="${rest%%:*}"
        port="${rest##*:}"

        cert_info=$(timeout $SMTP_TIMEOUT bash -c "
            echo | openssl s_client -starttls smtp -connect $ip:$port -servername $ip 2>/dev/null | \
            openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null
        " 2>/dev/null) || true

        if [[ -n "$cert_info" ]]; then
            subject=$(echo "$cert_info" | grep "subject=" | head -1)
            issuer=$(echo "$cert_info" | grep "issuer=" | head -1)
            not_after=$(echo "$cert_info" | grep "notAfter=" | head -1)
            pass "$label TLS cert: $subject"
            info "$label issuer: $issuer"
            info "$label expiry: $not_after"
            add_result "TLS" "$label certificate" "PASS" "$subject | $issuer | $not_after"
        else
            warn "$label: could not retrieve TLS certificate"
            add_result "TLS" "$label certificate" "WARN" "Port unreachable or no STARTTLS"
        fi
    done
else
    header "10. TLS Certificate Check — SKIPPED"
    info "TLS tests skipped (--skip-tls)"
fi

# ── 11. MTA-STS & DANE ───────────────────────────────────────────────────────
header "11. MTA-STS & DANE (Transport Security)"

# Only check relay and destination (sender's transport security is their concern)
declare -a TRANSPORT_DOMAINS=()
declare -a TRANSPORT_LABELS=()
if [[ "$HAS_RELAY" -eq 1 ]]; then
    TRANSPORT_DOMAINS+=("$RELAY_DOMAIN"); TRANSPORT_LABELS+=("Relay")
fi
TRANSPORT_DOMAINS+=("$DEST_DOMAIN"); TRANSPORT_LABELS+=("Destination")

for i in "${!TRANSPORT_DOMAINS[@]}"; do
    domain="${TRANSPORT_DOMAINS[$i]}"
    label="${TRANSPORT_LABELS[$i]}"

    mtasts=$(sdig TXT "_mta-sts.${domain}")
    if [[ -n "$mtasts" ]]; then
        pass "$label MTA-STS: $mtasts"
        add_result "Transport" "$label MTA-STS" "PASS" "$mtasts"
    else
        info "$label: no MTA-STS (_mta-sts.${domain})"
        add_result "Transport" "$label MTA-STS" "INFO" "Not configured"
    fi

    tlsrpt=$(sdig TXT "_smtp._tls.${domain}")
    if [[ -n "$tlsrpt" ]]; then
        pass "$label TLS-RPT: $tlsrpt"
        add_result "Transport" "$label TLS-RPT" "PASS" "$tlsrpt"
    else
        info "$label: no TLS-RPT (_smtp._tls.${domain})"
        add_result "Transport" "$label TLS-RPT" "INFO" "Not configured"
    fi

    mx_host=$(sdig MX "$domain" | sort -n | head -1 | awk '{print $2}')
    if [[ -n "$mx_host" ]]; then
        tlsa=$(sdig TLSA "_25._tcp.${mx_host}")
        if [[ -n "$tlsa" ]]; then
            pass "$label DANE/TLSA for $mx_host"
            add_result "Transport" "$label DANE" "PASS" "$tlsa"
        else
            info "$label: no DANE/TLSA for _25._tcp.${mx_host}"
            add_result "Transport" "$label DANE" "INFO" "Not configured"
        fi
    fi
done

# ══════════════════════════════════════════════════════════════════════════════
# ██ SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
header "SUMMARY"

echo -e "  ${GREEN}PASS: $PASS_COUNT${RESET}  ${RED}FAIL: $FAIL_COUNT${RESET}  ${YELLOW}WARN: $WARN_COUNT${RESET}  ${CYAN}INFO: $INFO_COUNT${RESET}"
echo ""

if [[ ${#FINDINGS[@]} -gt 0 ]]; then
    echo -e "${BOLD}Critical Findings:${RESET}"
    for f in "${FINDINGS[@]}"; do
        if [[ "$f" == FAIL:* ]]; then
            echo -e "  ${RED}●${RESET} ${f#FAIL: }"
        else
            echo -e "  ${YELLOW}●${RESET} ${f#WARN: }"
        fi
    done
fi

if [[ "$HAS_RELAY" -eq 1 && "$FORWARD_BROKEN" -eq 1 ]]; then
    fwd_ip="${RELAY_BACKEND_IP:-$RELAY_MX_IP}"
    echo ""
    echo -e "${BOLD}Root Cause Analysis:${RESET}"
    echo -e "  When ${RED}$fwd_ip${RESET} ($RELAY_DOMAIN) forwards mail from $SENDER_DOMAIN to $DEST_DOMAIN:"
    echo -e "    1. SPF fails — $fwd_ip is not in $SENDER_DOMAIN's SPF"
    echo -e "    2. DKIM likely fails — headers modified during forwarding"
    echo -e "    3. DMARC fails — neither SPF nor DKIM pass with alignment"
    echo -e "    4. Result: mail quarantined or rejected per DMARC policy"
    echo ""
    echo -e "${BOLD}Recommended Fixes:${RESET}"
    echo -e "  ${GREEN}1.${RESET} Configure SRS on the relay ($fwd_ip) to rewrite envelope-from"
    echo -e "  ${GREEN}2.${RESET} Add ARC signing on the relay and trust it at the destination"
    echo -e "  ${GREEN}3.${RESET} Set PTR record for $fwd_ip"
    echo -e "  ${GREEN}4.${RESET} Or: replace forwarding with IMAP/POP fetch from $DEST_RECIPIENT"
elif [[ "$HAS_RELAY" -eq 1 && "$FORWARD_BROKEN" -eq 0 ]]; then
    echo ""
    echo -e "${BOLD}Forwarding chain:${RESET} ${GREEN}No authentication breakage detected.${RESET}"
    echo -e "  SPF passes through the relay — DMARC should survive forwarding."
fi

# ══════════════════════════════════════════════════════════════════════════════
# ██ JSON EXPORT
# ══════════════════════════════════════════════════════════════════════════════
if [[ -n "$REPORT_JSON" ]]; then
    {
        cat <<EOF
{
  "version": "$VERSION",
  "timestamp": "$TIMESTAMP",
  "mode": "$CHAIN_MODE",
  "chain": {
    "sender_domain": "$SENDER_DOMAIN",
    "sender_email": "$SENDER_EMAIL",
    "sender_ip": "${SENDER_IP:-not provided}",
EOF
        if [[ "$HAS_RELAY" -eq 1 ]]; then
            cat <<EOF
    "relay_domain": "$RELAY_DOMAIN",
    "relay_mx_ip": "${RELAY_MX_IP:-}",
    "relay_backend_ip": "${RELAY_BACKEND_IP:-}",
    "relay_recipient": "$RELAY_RECIPIENT",
EOF
        fi
        cat <<EOF
    "dest_domain": "$DEST_DOMAIN",
    "dest_recipient": "$DEST_RECIPIENT"
  },
  "summary": {
    "pass": $PASS_COUNT,
    "fail": $FAIL_COUNT,
    "warn": $WARN_COUNT,
    "info": $INFO_COUNT
  },
  "results": [
EOF
        for i in "${!RESULTS[@]}"; do
            if [[ $i -lt $((${#RESULTS[@]}-1)) ]]; then
                echo "    ${RESULTS[$i]},"
            else
                echo "    ${RESULTS[$i]}"
            fi
        done
        echo "  ]"
        echo "}"
    } > "$REPORT_JSON"
    echo -e "\n${DIM}JSON report: $REPORT_JSON${RESET}"
fi

# ══════════════════════════════════════════════════════════════════════════════
# ██ HTML EXPORT
# ══════════════════════════════════════════════════════════════════════════════
if [[ -n "$REPORT_HTML" ]]; then
    cat > "$REPORT_HTML" <<'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Email Chain Audit Report</title>
<style>
:root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #e6edf3;
        --green: #3fb950; --red: #f85149; --yellow: #d29922; --blue: #58a6ff;
        --dim: #8b949e; }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; line-height: 1.6; padding: 2rem; max-width: 1200px; margin: 0 auto; }
h1 { text-align: center; margin-bottom: 0.5rem; font-size: 1.5rem; }
.subtitle { text-align: center; color: var(--dim); margin-bottom: 2rem; font-size: 0.9rem; }
.chain { display: flex; align-items: center; justify-content: center; gap: 0.5rem; margin-bottom: 2rem; flex-wrap: wrap; }
.chain-node { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 0.5rem 1rem; font-family: monospace; font-size: 0.85rem; }
.chain-arrow { color: var(--dim); font-size: 1.2rem; }
.chain-break { color: var(--red); font-weight: bold; }
.summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }
.summary-card { background: var(--card); border-radius: 8px; padding: 1rem; text-align: center; border: 1px solid var(--border); }
.summary-card .count { font-size: 2rem; font-weight: bold; }
.summary-card.pass .count { color: var(--green); }
.summary-card.fail .count { color: var(--red); }
.summary-card.warn .count { color: var(--yellow); }
.summary-card.info .count { color: var(--blue); }
.section { background: var(--card); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }
.section-header { padding: 0.75rem 1rem; font-weight: 600; border-bottom: 1px solid var(--border); }
.section-body { padding: 0; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th { text-align: left; padding: 0.5rem 1rem; border-bottom: 1px solid var(--border); color: var(--dim); font-weight: 500; }
td { padding: 0.5rem 1rem; border-bottom: 1px solid var(--border); }
tr:last-child td { border-bottom: none; }
.status { font-weight: 600; font-size: 0.8rem; padding: 2px 8px; border-radius: 4px; }
.status-PASS { background: #0f2d1a; color: var(--green); }
.status-FAIL { background: #2d0f0f; color: var(--red); }
.status-WARN { background: #2d2200; color: var(--yellow); }
.status-INFO { background: #0f1d2d; color: var(--blue); }
.findings { background: #1a0000; border: 1px solid #3d1010; border-radius: 8px; padding: 1rem; margin-bottom: 2rem; }
.findings h3 { color: var(--red); margin-bottom: 0.5rem; }
.findings li { margin: 0.25rem 0 0.25rem 1.5rem; font-size: 0.9rem; }
.fix-list { background: #001a0f; border: 1px solid #103d20; border-radius: 8px; padding: 1rem; margin-bottom: 2rem; }
.fix-list h3 { color: var(--green); margin-bottom: 0.5rem; }
.fix-list li { margin: 0.25rem 0 0.25rem 1.5rem; font-size: 0.9rem; }
.detail { font-family: monospace; font-size: 0.8rem; color: var(--dim); word-break: break-all; }
</style>
</head>
<body>
<h1>Email Forwarding Chain — Audit Report</h1>
HTMLEOF

    # Dynamic header
    html_sender_detail=""
    if [[ -n "$SENDER_IP" && "${SENDER_IP_AUTO:-0}" -eq 0 ]]; then
        html_sender_detail="$SENDER_IP"
    else
        html_sender_detail="$SENDER_DOMAIN"
    fi

    # Determine destination MX description
    html_dest_mx=$(sdig MX "$DEST_DOMAIN" | sort -n | head -1 | awk '{print $2}' | sed 's/\.$//')
    [[ -z "$html_dest_mx" ]] && html_dest_mx="$DEST_DOMAIN"

    cat >> "$REPORT_HTML" <<EOF
<p class="subtitle">Generated: $TIMESTAMP_HUMAN | Mode: $CHAIN_MODE</p>
<div class="chain">
  <div class="chain-node">$SENDER_EMAIL<br><small>$html_sender_detail</small></div>
  <div class="chain-arrow">→</div>
EOF

    if [[ "$HAS_RELAY" -eq 1 ]]; then
        html_relay_detail=""
        if [[ -n "$RELAY_BACKEND_IP" && "$RELAY_BACKEND_IP" != "$RELAY_MX_IP" ]]; then
            html_relay_detail="MX: ${RELAY_MX_IP:-?} | Backend: $RELAY_BACKEND_IP"
        else
            html_relay_detail="MX: ${RELAY_MX_IP:-?}"
        fi
        if [[ "$FORWARD_BROKEN" -eq 1 ]]; then
            html_fwd_arrow='<div class="chain-arrow chain-break">✗→</div>'
        else
            html_fwd_arrow='<div class="chain-arrow">→</div>'
        fi
        cat >> "$REPORT_HTML" <<EOF
  <div class="chain-node">$RELAY_RECIPIENT<br><small>$html_relay_detail</small></div>
  $html_fwd_arrow
EOF
    fi

    cat >> "$REPORT_HTML" <<EOF
  <div class="chain-node">$DEST_RECIPIENT<br><small>$html_dest_mx</small></div>
</div>
<div class="summary">
  <div class="summary-card pass"><div class="count">$PASS_COUNT</div>PASS</div>
  <div class="summary-card fail"><div class="count">$FAIL_COUNT</div>FAIL</div>
  <div class="summary-card warn"><div class="count">$WARN_COUNT</div>WARN</div>
  <div class="summary-card info"><div class="count">$INFO_COUNT</div>INFO</div>
</div>
EOF

    # Findings
    if [[ ${#FINDINGS[@]} -gt 0 ]]; then
        echo '<div class="findings"><h3>Critical Findings</h3><ul>' >> "$REPORT_HTML"
        for f in "${FINDINGS[@]}"; do
            escaped=$(echo "$f" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
            echo "<li>$escaped</li>" >> "$REPORT_HTML"
        done
        echo '</ul></div>' >> "$REPORT_HTML"
    fi

    # Fixes (only for relay mode with detected breakage)
    if [[ "$HAS_RELAY" -eq 1 && "$FORWARD_BROKEN" -eq 1 ]]; then
        cat >> "$REPORT_HTML" <<'EOF'
<div class="fix-list"><h3>Recommended Fixes</h3><ul>
<li><strong>SRS (Sender Rewriting Scheme)</strong> — Configure on the relay to rewrite envelope-from, fixing SPF at the destination</li>
<li><strong>ARC (Authenticated Received Chain)</strong> — Add ARC signing on the relay and configure destination to trust it</li>
<li><strong>PTR Record</strong> — Set reverse DNS for relay IPs to prevent delivery penalties</li>
<li><strong>Replace forwarding</strong> — Use IMAP/POP fetch instead of SMTP forwarding</li>
</ul></div>
EOF
    fi

    # Results table
    prev_section=""
    for r in "${RESULTS[@]}"; do
        section=$(echo "$r" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['section'])" 2>/dev/null || echo "")
        test_name=$(echo "$r" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['test'])" 2>/dev/null || echo "")
        status=$(echo "$r" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['status'])" 2>/dev/null || echo "")
        detail=$(echo "$r" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['detail'])" 2>/dev/null || echo "")

        if [[ "$section" != "$prev_section" ]]; then
            [[ -n "$prev_section" ]] && echo '</table></div></div>' >> "$REPORT_HTML"
            cat >> "$REPORT_HTML" <<EOF
<div class="section">
<div class="section-header">$section</div>
<div class="section-body"><table>
<tr><th>Test</th><th>Status</th><th>Detail</th></tr>
EOF
            prev_section="$section"
        fi

        escaped_detail=$(echo "$detail" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
        escaped_test=$(echo "$test_name" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
        cat >> "$REPORT_HTML" <<EOF
<tr><td>$escaped_test</td><td><span class="status status-$status">$status</span></td><td class="detail">$escaped_detail</td></tr>
EOF
    done
    [[ -n "$prev_section" ]] && echo '</table></div></div>' >> "$REPORT_HTML"

    echo '</body></html>' >> "$REPORT_HTML"
    echo -e "${DIM}HTML report: $REPORT_HTML${RESET}"
fi

echo -e "\n${DIM}Audit complete.${RESET}"
