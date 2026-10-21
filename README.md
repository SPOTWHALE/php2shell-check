<p align="center">
  <img src="assets/icon.svg" width="96" height="96" alt="php2shell-check">
</p>

<h1 align="center">php2shell-check</h1>

<p align="center">
  Find out in seconds whether your servers are vulnerable to, or already compromised through,<br>
  CVE-2026-109618 and CVE-2026-109619.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/CVE--2026--109618-critical-b60205" alt="CVE-2026-109618 critical">
  <img src="https://img.shields.io/badge/CVE--2026--109619-critical-b60205" alt="CVE-2026-109619 critical">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows-4f5b93" alt="Linux and Windows">
  <img src="https://img.shields.io/badge/license-MIT-2b3050" alt="MIT license">
</p>

**php2shell** is a pair of critical bugs in PHP itself that let anyone run code on your server without logging in. They leaked on 20 October 2026 and fixes shipped on 21 October 2026. The scripts here are read-only.

## Quick start

**Linux** (run as root):

```bash
curl -fsSLO https://raw.githubusercontent.com/SPOTWHALE/php2shell-check/main/check-php2shell.sh
sudo bash check-php2shell.sh --hunt
```

**Windows** (XAMPP, WAMP, Laragon, IIS), from an elevated PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\check-php2shell.ps1
```

| Command | What it does |
|---|---|
| `sudo bash check-php2shell.sh` | Am I vulnerable? |
| `sudo bash check-php2shell.sh --hunt` | Am I vulnerable, and was I already hacked? |
| `sudo bash check-php2shell.sh --hunt --since 2026-06-01` | Same, looking further back in time |
| `sudo bash check-php2shell.sh --summary` | One-line result, for many servers |

Exit code: `0` all clear, `1` vulnerable, `2` needs a manual look.

## Am I vulnerable?

Yes, if **any** PHP that serves web traffic (php-fpm, Apache mod_php, php-cgi, LiteSpeed, FrankenPHP, Docker) is older than:

| Branch | Fixed in |
|---|---|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |
| 8.1 and older | No fix. End-of-life: upgrade or take it off the internet |

> [!IMPORTANT]
> The bug is in the PHP runtime, not your code. `composer audit`, plugin scanners and code reviews will not find it. Only the PHP version matters.

> [!NOTE]
> Debian, Ubuntu and RHEL often patch PHP without changing the version shown by `php -v`. The script checks the package changelog, so trust its result over the raw version number.

## Fix it

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install --only-upgrade 'php*'
sudo systemctl restart 'php*-fpm' apache2

# RHEL / Alma / Rocky
sudo dnf upgrade 'php*'
sudo systemctl restart php-fpm httpd
```

> [!WARNING]
> Restart php-fpm and Apache after upgrading. Until you do, they keep running the old, vulnerable binary.

<details>
<summary><b>Docker, control panels, and if you can't patch today</b></summary>

- **Docker:** pull the new `php:` image tag, rebuild and redeploy. Old images stay vulnerable.
- **cPanel, Plesk, DirectAdmin:** apply the panel's PHP updates. Plesk has [an advisory](https://support.plesk.com/hc/en-us/articles/44397729587351-Vulnerability-CVE-2026-109618-and-CVE-2026-109619-Remote-code-execution-in-PHP-shipped-with-Plesk).
- **Can't patch today:** set `session.upload_progress.enabled = Off` in the php.ini of every SAPI and put the site behind a WAF (Cloudflare has rules, including on the free plan). This reduces exposure but is **not** a fix.

</details>

## Was I already hacked?

Run with `--hunt`. There are no official indicators of compromise yet, so it looks for what an attacker does after getting in: shells started by PHP, webshells, unknown processes and outbound connections, new cron jobs, users or SSH keys, and crash spikes in the logs. Everything it prints is a lead, not proof.

**If it finds something:**

1. Don't delete it yet. Snapshot the disk and copy the logs first.
2. Isolate the server, patch PHP, and restart php-fpm and Apache.
3. Rotate every secret the web user could read: database passwords, `.env` and API keys, SMTP, cloud keys, `APP_KEY`. Do this on any exposed vulnerable server, even if nothing turned up, because CVE-2026-109619 can leak memory.
4. If the attacker reached root, or you can't explain what you found, rebuild from a clean image.

<details>
<summary><b>Everything <code>--hunt</code> checks, and why</b></summary>

| What it looks for | Why it matters |
|---|---|
| `sh`, `bash`, `python`, `perl`, `curl`, `wget`, `nc` started by php-fpm, php-cgi, Apache or lsphp | PHP almost never needs a shell. Strongest live signal. |
| Processes running as the web user that are not PHP or web server workers | Backdoors, miners and reverse shells run as the web user. |
| Webshell code in web roots at **any** age: `eval($_POST[...])`, `eval(base64_decode(...))`, `system($_GET[...])` | Attackers fake file dates, so contents are checked, not just timestamps. |
| PHP files changed since the date, and PHP files in `/tmp`, `/var/tmp`, `/dev/shm` | Files nobody deployed. |
| Changed cron, `/etc/passwd`, `/etc/shadow`, sudoers, SSH keys, systemd units, `/etc/ld.so.preload` | Ways to keep access after you patch. |
| Outbound connections from PHP, web server or shell processes | Reverse shells and data theft. |
| Spikes of `Allowed memory size ... exhausted`, `exited on signal 11`, `Segmentation fault` | Both bugs are memory bugs, and attack attempts crash workers. |
| Client IPs with many POST requests ending in HTTP 500 | Attack attempts and scanners. |

</details>

<details>
<summary><b>Manual checks the script can't do</b></summary>

- Compare the live web root with git or your last clean deploy: `git status`, `git diff`, or `rsync -rcn --delete clean/ live/`.
- WordPress: `wp core verify-checksums` and `wp plugin verify-checksums --all`, and look for unknown admin users.
- Look for new admin accounts in your application's database.
- Check your WAF or Cloudflare dashboard for blocked attempts.

</details>

## More

<details>
<summary><b>Check many servers at once</b></summary>

```bash
# hosts.txt: one host per line
while read -r h; do
  ssh -n "$h" 'sudo bash -s -- --summary' < check-php2shell.sh
done < hosts.txt

# or with Ansible
ansible all -b -m script -a "check-php2shell.sh --summary"
```

Output, one line per host:

```
web01 VULNERABLE vulnerable=2 review=0 patched=0
web02 OK vulnerable=0 review=0 patched=3
```

</details>

<details>
<summary><b>What the Linux script scans</b></summary>

- Every `php`, `php-fpm*`, `php-cgi*`, `lsphp*` and `frankenphp` binary, including control panel installs (`/opt/plesk/php`, `/opt/cpanel/ea-php*`, `/opt/remi`, `/usr/local/php*`, `/usr/local/lsws`)
- Apache `libphp*.so` and `mod_php*.so` modules
- Running Docker containers
- Whether PHP is serving web traffic right now
- Distro backports, via the package changelog
- Processes still running a replaced binary (need a restart)
- The interim `session.upload_progress.enabled` setting

**Limits:** it checks versions, it does not exploit anything. It cannot see stopped containers, images, other machines, or PHP compiled into unusual software. If a result looks wrong, check the official PHP advisory and your vendor's advisory.

</details>

<details>
<summary><b>Sources</b></summary>

- [Tenable: php2shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)
- [Huntress: php2shell rapid response](https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities)
- [Help Net Security](https://www.helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619/)
- [UK NCSC](https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php)
- [Check Point: what we know about php2shell](https://blog.checkpoint.com/security/php2shell-what-we-know-about-the-leaked-critical-php-vulnerabilities-cve-2026-109618-cve-2026-109619)
- [Aikido: critical vulnerabilities in PHP](https://www.aikido.dev/blog/critical-vulnerabilities-in-php-php2shell)
- [CybelAngel: what we know about php2shell](https://cybelangel.com/blog/critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619/)
- [Plesk advisory](https://support.plesk.com/hc/en-us/articles/44397729587351-Vulnerability-CVE-2026-109618-and-CVE-2026-109619-Remote-code-execution-in-PHP-shipped-with-Plesk)

</details>

## License

[MIT](LICENSE)
