#!/usr/bin/env bash
# check-php2shell.sh - find every PHP runtime on a Linux host and tell you
# whether it is vulnerable to php2shell (CVE-2026-109618 / CVE-2026-109619).
#
# Read-only. Does not change anything. Run as root for full coverage.
#
# Usage:
#   sudo bash check-php2shell.sh            # full report
#   sudo bash check-php2shell.sh --hunt     # also look for signs of compromise
#   sudo bash check-php2shell.sh --hunt --since 2026-06-01   # look further back
#   sudo bash check-php2shell.sh --summary  # one line, for running across many servers
#
# Exit codes: 0 = nothing vulnerable found, 1 = vulnerable PHP found,
#             2 = nothing vulnerable but some items need manual review.

set -u
export LC_ALL=C

CVES="CVE-2026-109618|CVE-2026-109619"
LEAK_DATE="2026-10-20"
HUNT=0
SUMMARY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --hunt) HUNT=1 ;;
    --summary) SUMMARY=1 ;;
    --since) shift; LEAK_DATE="${1:?--since needs a date like 2026-06-01}" ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
  shift
done

VULN=0
REVIEW=0
OK=0

if [ -t 1 ] && [ "$SUMMARY" -eq 0 ]; then
  RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLD=$'\e[1m'; RST=$'\e[0m'
else
  RED=; GRN=; YEL=; BLD=; RST=
fi

say() { [ "$SUMMARY" -eq 1 ] || printf '%s\n' "$*"; }
hdr() { say ""; say "${BLD}== $* ==${RST}"; }

run() { if command -v timeout >/dev/null 2>&1; then timeout 10 "$@"; else "$@"; fi; }

# Prints the first upstream PHP version (x.y.z) found in its input.
extract_version() { grep -oE 'PHP[ /v]*[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+'; }

# Lowest patch release that contains the fix, per branch. Empty = no upstream fix.
fixed_patch() {
  case "$1" in
    8.5) echo 12 ;;
    8.4) echo 27 ;;
    8.3) echo 36 ;;
    8.2) echo 35 ;;
    *) echo "" ;;
  esac
}

# Package that owns a file, or empty.
owner_pkg() {
  local f="$1"
  if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -S "$f" 2>/dev/null | head -n1 | cut -d: -f1
  elif command -v rpm >/dev/null 2>&1; then
    rpm -qf "$f" 2>/dev/null | grep -v 'not owned' | head -n1
  fi
}

# Does the package changelog mention the CVEs? (distros backport fixes
# without changing the upstream version number shown by `php -v`).
pkg_has_fix() {
  local pkg="$1"
  [ -n "$pkg" ] || return 1
  if command -v dpkg-query >/dev/null 2>&1; then
    local base="${pkg%%:*}"
    local cl
    for cl in /usr/share/doc/"$base"/changelog.Debian.gz /usr/share/doc/"$base"/changelog.gz; do
      [ -f "$cl" ] && zgrep -qE "$CVES" "$cl" 2>/dev/null && return 0
    done
    return 1
  elif command -v rpm >/dev/null 2>&1; then
    rpm -q --changelog "$pkg" 2>/dev/null | grep -qE "$CVES"
  else
    return 1
  fi
}

# verdict <version> <package> -> sets VERDICT and REASON
verdict() {
  local v="$1" pkg="$2" maj min pat need
  IFS=. read -r maj min pat <<<"$v"
  need=$(fixed_patch "$maj.$min")
  if pkg_has_fix "$pkg"; then
    VERDICT=PATCHED; REASON="package $pkg changelog lists the fix (distro backport)"
    return
  fi
  if [ -n "$need" ]; then
    if [ "$pat" -ge "$need" ]; then
      VERDICT=PATCHED; REASON="$maj.$min.$need or later"
    else
      VERDICT=VULNERABLE; REASON="upgrade to $maj.$min.$need or later"
    fi
  elif [ "$maj" -gt 8 ] || { [ "$maj" -eq 8 ] && [ "$min" -ge 6 ]; }; then
    VERDICT=REVIEW; REASON="branch $maj.$min not covered by the advisory, check php.net"
  else
    VERDICT=VULNERABLE
    REASON="PHP $maj.$min is end-of-life, no official fix. Upgrade to 8.2+ or get a vendor backport"
  fi
}

report() {
  local what="$1" v="$2" pkg="$3"
  verdict "$v" "$pkg"
  case "$VERDICT" in
    PATCHED) OK=$((OK+1)); say "  ${GRN}[PATCHED]${RST}    $what  PHP $v  ($REASON)" ;;
    VULNERABLE) VULN=$((VULN+1)); say "  ${RED}[VULNERABLE]${RST} $what  PHP $v  ($REASON)" ;;
    *) REVIEW=$((REVIEW+1)); say "  ${YEL}[REVIEW]${RST}     $what  PHP $v  ($REASON)" ;;
  esac
  [ -n "$pkg" ] && say "               package: $pkg"
}

# ---------------------------------------------------------------- host binaries
hdr "PHP binaries on this host"

declare -A SEEN=()
CANDIDATES=()
for c in php php-fpm php-cgi lsphp frankenphp; do
  p=$(command -v "$c" 2>/dev/null) && CANDIDATES+=("$p")
done
SEARCH_DIRS=(/usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /usr/local/php* /usr/local/lsws /opt /bin /sbin)
while IFS= read -r -d '' f; do CANDIDATES+=("$f"); done < <(
  find "${SEARCH_DIRS[@]}" -xdev -maxdepth 6 -type f \
    \( -name 'php' -o -name 'php[0-9]*' -o -name 'php-fpm*' -o -name 'php-cgi*' \
       -o -name 'lsphp*' -o -name 'frankenphp' \) \
    ! -name '*.*.ini' ! -name '*.conf' ! -name '*.service' ! -name '*-config*' ! -name 'phpize*' \
    -perm -u+x -print0 2>/dev/null
)

FOUND_BIN=0
for f in "${CANDIDATES[@]}"; do
  real=$(readlink -f "$f" 2>/dev/null || echo "$f")
  [ -n "${SEEN[$real]:-}" ] && continue
  SEEN[$real]=1
  if [ "$(basename "$real")" = frankenphp ]; then
    out=$(run "$real" version 2>&1)
  else
    out=$(run "$real" -n -v 2>&1)
  fi
  v=$(printf '%s' "$out" | extract_version)
  [ -n "$v" ] || continue
  FOUND_BIN=1
  report "$real" "$v" "$(owner_pkg "$real")"
done
[ "$FOUND_BIN" -eq 1 ] || say "  no PHP binaries found"

# ---------------------------------------------------------- apache mod_php
hdr "Apache mod_php modules"
FOUND_MOD=0
while IFS= read -r -d '' so; do
  FOUND_MOD=1
  pkg=$(owner_pkg "$so")
  v=$(grep -aoE 'PHP/[0-9]+\.[0-9]+\.[0-9]+' "$so" 2>/dev/null | head -n1 | cut -d/ -f2)
  if [ -n "$v" ]; then
    report "$so" "$v" "$pkg"
  else
    REVIEW=$((REVIEW+1))
    say "  ${YEL}[REVIEW]${RST}     $so  (could not read version; compare with the PHP binary from the same package${pkg:+ $pkg})"
  fi
done < <(find /usr/lib /usr/lib64 /usr/local /opt /etc/httpd /etc/apache2 -xdev -maxdepth 6 \
          -type f \( -name 'libphp*.so' -o -name 'mod_php*.so' \) -print0 2>/dev/null)
[ "$FOUND_MOD" -eq 1 ] || say "  none found"

# ------------------------------------------------------------ containers
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  hdr "Running Docker containers"
  ids=$(docker ps -q 2>/dev/null)
  if [ -z "$ids" ]; then say "  no running containers"; fi
  for id in $ids; do
    name=$(docker inspect -f '{{.Name}}' "$id" 2>/dev/null | sed 's#^/##')
    image=$(docker inspect -f '{{.Config.Image}}' "$id" 2>/dev/null)
    out=$(run docker exec "$id" sh -c 'php -n -v 2>/dev/null || php-fpm -n -v 2>/dev/null || frankenphp version 2>/dev/null' 2>/dev/null)
    v=$(printf '%s' "$out" | extract_version)
    if [ -n "$v" ]; then
      report "container $name ($image)" "$v" ""
    fi
  done
  say "  note: stopped containers and images are not checked. Rebuild images on a patched base image."
fi

# ------------------------------------------------------------ exposure
hdr "Is PHP serving web requests right now?"
WEB=$(ps -eo comm= 2>/dev/null | grep -E '^(php-fpm|php-cgi|lsphp|frankenphp)' | sort | uniq -c)
if command -v apachectl >/dev/null 2>&1 || command -v apache2ctl >/dev/null 2>&1; then
  actl=$(command -v apache2ctl || command -v apachectl)
  if pgrep -x 'apache2|httpd' >/dev/null 2>&1 && "$actl" -M 2>/dev/null | grep -qi php; then
    WEB="${WEB:+$WEB$'\n'}      apache (running, mod_php loaded)"
  fi
fi
if [ -n "$(printf '%s' "$WEB" | tr -d '[:space:]')" ]; then
  say "  yes, these PHP web processes are running:"
  say "$WEB"
  say "  Any vulnerable version above that serves web traffic is remotely exploitable without login."
else
  say "  no PHP web processes found (CLI-only PHP is far less exposed, but still update it)"
fi

STALE=""
for exe in /proc/[0-9]*/exe; do
  t=$(readlink "$exe" 2>/dev/null) || continue
  case "$t" in
    *php*" (deleted)"|*lsphp*" (deleted)"|*httpd*" (deleted)"|*apache2*" (deleted)") STALE="$STALE ${exe#/proc/}" ;;
  esac
done
if [ -n "$STALE" ]; then
  REVIEW=$((REVIEW+1))
  say "  ${YEL}PHP/Apache processes still running a deleted (replaced) binary, restart them:${RST}"
  say "    pids:$(printf '%s' "$STALE" | sed 's#/exe##g')"
fi

# ------------------------------------------------------------ interim mitigation
hdr "Interim mitigation status (not a fix)"
php_cli=$(command -v php 2>/dev/null)
if [ -n "$php_cli" ]; then
  up=$(run "$php_cli" -r 'echo ini_get("session.upload_progress.enabled") ? "On" : "Off";' 2>/dev/null)
  say "  session.upload_progress.enabled (CLI ini) = ${up:-unknown}"
fi
say "  Community advice is session.upload_progress.enabled = Off in php.ini for every SAPI."
say "  The PHP team says ini settings will not fully protect you. Patching is the only fix."

# ------------------------------------------------------------ compromise hunt
if [ "$HUNT" -eq 1 ]; then
  hdr "Signs of compromise (leads to investigate, not proof)"

  say "  Shells or tools whose parent is a PHP or web server process:"
  hits=$(ps -eo pid=,ppid=,user=,comm=,args= 2>/dev/null | awk '
    { pid=$1; ppid=$2; comm[pid]=$4; line[pid]=$0; parent[pid]=ppid }
    END {
      for (p in line) {
        c = comm[p]; pc = comm[parent[p]]
        if (pc ~ /^(php|php-fpm|php-cgi|lsphp|frankenphp|httpd|apache2|nginx|litespeed)/ &&
            c ~ /^(sh|bash|dash|zsh|python[0-9.]*|perl|ruby|curl|wget|nc|ncat|socat|busybox)$/)
          print "    " line[p]
      }
    }')
  if [ -n "$hits" ]; then say "${RED}$hits${RST}"; REVIEW=$((REVIEW+1)); else say "    none"; fi

  say "  PHP files changed since $LEAK_DATE in web roots and temp dirs (first 50):"
  roots=()
  for d in /var/www /srv /usr/share/nginx /home/*/public_html /home/*/domains /var/www/vhosts /tmp /var/tmp /dev/shm; do
    [ -d "$d" ] && roots+=("$d")
  done
  if [ "${#roots[@]}" -gt 0 ]; then
    files=$(find "${roots[@]}" -xdev -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' \) \
      -newermt "$LEAK_DATE" ! -path '*/vendor/*' ! -path '*/node_modules/*' ! -path '*/cache/*' \
      2>/dev/null | head -n 50)
    if [ -n "$files" ]; then say "$(printf '%s\n' "$files" | sed 's/^/    /')"; else say "    none"; fi
    tmpphp=$(find /tmp /var/tmp /dev/shm -xdev -type f \( -name '*.php' -o -name '*.phtml' \) 2>/dev/null | head -n 20)
    if [ -n "$tmpphp" ]; then
      REVIEW=$((REVIEW+1))
      say "  ${YEL}PHP files in temp dirs (unusual, check these):${RST}"
      say "$(printf '%s\n' "$tmpphp" | sed 's/^/    /')"
    fi
  fi

  say "  Cron files changed since $LEAK_DATE:"
  cron=$(find /etc/cron* /var/spool/cron -xdev -type f -newermt "$LEAK_DATE" 2>/dev/null)
  if [ -n "$cron" ]; then say "$(printf '%s\n' "$cron" | sed 's/^/    /')"; else say "    none"; fi

  say "  Account, SSH key and persistence files changed since $LEAK_DATE:"
  acct=$(find /etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d /root/.ssh /home/*/.ssh /var/www/.ssh \
    /etc/systemd/system /etc/ld.so.preload /etc/rc.local /etc/profile.d \
    -xdev ! -type d -newermt "$LEAK_DATE" 2>/dev/null)
  if [ -n "$acct" ]; then say "$(printf '%s\n' "$acct" | sed 's/^/    /')"; else say "    none"; fi
  if [ -s /etc/ld.so.preload ]; then
    REVIEW=$((REVIEW+1))
    say "  ${RED}/etc/ld.so.preload is not empty (common rootkit trick):${RST}"
    say "$(sed 's/^/    /' /etc/ld.so.preload)"
  fi

  # Timestamps can be faked, so also scan file contents in web roots.
  say "  Webshell-like code in web roots, any age (first 30, expect some false positives):"
  if [ "${#roots[@]}" -gt 0 ]; then
    shells=$(find "${roots[@]}" -xdev -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' -o -name '*.inc' \) \
      -size -2M ! -path '*/vendor/*' ! -path '*/node_modules/*' -print0 2>/dev/null |
      xargs -0 -r grep -lE \
        'eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_(POST|GET|REQUEST|COOKIE|SERVER))|(system|shell_exec|passthru|exec|popen|proc_open|assert)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)|preg_replace\s*\(\s*["'"'"'].*/e["'"'"']|\$_(POST|GET|REQUEST|COOKIE)\s*\[[^]]+\]\s*\(' \
        2>/dev/null | head -n 30)
    if [ -n "$shells" ]; then
      REVIEW=$((REVIEW+1))
      say "${RED}$(printf '%s\n' "$shells" | sed 's/^/    /')${RST}"
    else
      say "    none"
    fi
  fi

  say "  Processes running as the web user (should only be PHP/web server workers):"
  webusers=$(ps -eo user=,comm= 2>/dev/null | awk '$2 ~ /^(php-fpm|php-cgi|lsphp|httpd|apache2|nginx|litespeed)/ && $1 != "root" {print $1}' | sort -u)
  odd=""
  for u in $webusers; do
    odd="$odd$(ps -u "$u" -o pid=,user=,etime=,comm=,args= 2>/dev/null |
      awk '$4 !~ /^(php|php-fpm|php-cgi|lsphp|frankenphp|httpd|apache2|nginx|litespeed|lshttpd)/')"
  done
  if [ -n "$odd" ]; then REVIEW=$((REVIEW+1)); say "${RED}$(printf '%s\n' "$odd" | sed 's/^ */    /')${RST}"; else say "    none"; fi

  say "  Outbound connections owned by PHP, web server or shell processes:"
  if command -v ss >/dev/null 2>&1; then
    conns=$(ss -tnpH state established 2>/dev/null | awk '
      $0 ~ /"(php[^"]*|lsphp[^"]*|httpd|apache2|sh|bash|dash|python[0-9.]*|perl|nc|ncat|socat)"/ {
        split($3, l, ":"); lp = l[length(l)]
        if (lp != 80 && lp != 443 && lp != 8080 && lp != 8443 && lp != 9000) print "    " $0 }' |
      grep -vE ' (127\.[0-9.]+|\[::1\]|\[::ffff:127\.[0-9.]+\]):[0-9]+ ' | head -n 30)
    say "${conns:-    none}"
    say "    (PHP talking to your DB, Redis or APIs is normal; unknown IPs on odd ports are not)"
  else
    say "    ss not available"
  fi

  say "  PHP/web server crash and memory errors since $LEAK_DATE (exploit attempts often crash workers):"
  logs=$(find /var/log /var/www/vhosts/system /usr/local/lsws/logs /home/*/logs -xdev -type f \
    \( -name '*error*log*' -o -name '*fpm*.log*' -o -name 'syslog*' -o -name 'messages*' -o -name 'kern.log*' \) \
    -newermt "$LEAK_DATE" 2>/dev/null)
  crash_re='Allowed memory size of [0-9]+ bytes exhausted|Out of memory|exited on signal (11|6|7)|Segmentation fault|child pid [0-9]+ exit signal|segfault at .* in (php|libphp|httpd|apache2|lsphp)'
  ncrash=0
  for lf in $logs; do
    c=$(zgrep -cE "$crash_re" "$lf" 2>/dev/null | tail -n1)
    [ "${c:-0}" -gt 0 ] && { say "    $c  $lf"; ncrash=$((ncrash+c)); }
  done
  if command -v journalctl >/dev/null 2>&1; then
    c=$(journalctl -q --since "$LEAK_DATE" --no-pager 2>/dev/null | grep -cE "$crash_re")
    [ "${c:-0}" -gt 0 ] && { say "    $c  journald"; ncrash=$((ncrash+c)); }
  fi
  [ "$ncrash" -gt 0 ] || say "    none"
  say "    (a sudden spike since $LEAK_DATE matters more than the absolute number)"

  say "  Top client IPs with HTTP 500 on POST requests in current access logs:"
  alogs=$(find /var/log /var/www/vhosts/system /usr/local/lsws/logs /home/*/logs -xdev -type f \
    -name '*access*log' -newermt "$LEAK_DATE" 2>/dev/null)
  if [ -n "$alogs" ]; then
    top=$(cat $alogs 2>/dev/null | awk '$6 ~ /POST/ && $9 == 500 {print $1}' | sort | uniq -c | sort -rn | head -n 10)
    say "${top:-    none}"
  else
    say "    no access logs found"
  fi
fi

# ------------------------------------------------------------ result
HOST=$(hostname 2>/dev/null || echo unknown)
if [ "$VULN" -gt 0 ]; then
  RESULT="VULNERABLE"; CODE=1
elif [ "$REVIEW" -gt 0 ]; then
  RESULT="REVIEW"; CODE=2
else
  RESULT="OK"; CODE=0
fi

if [ "$SUMMARY" -eq 1 ]; then
  printf '%s %s vulnerable=%d review=%d patched=%d\n' "$HOST" "$RESULT" "$VULN" "$REVIEW" "$OK"
else
  hdr "Result for $HOST"
  case "$RESULT" in
    VULNERABLE) say "  ${RED}${BLD}VULNERABLE${RST}: $VULN vulnerable PHP install(s). Patch now: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, or your distro's fixed package. Restart php-fpm/apache afterwards." ;;
    REVIEW) say "  ${YEL}${BLD}REVIEW${RST}: nothing clearly vulnerable, but $REVIEW item(s) need a manual look." ;;
    OK) say "  ${GRN}${BLD}OK${RST}: all $OK PHP install(s) found are patched." ;;
  esac
  say "  Remember to restart PHP after upgrading. A patched package with an old running process is still vulnerable."
fi
exit "$CODE"
