# alpine-openssh-musl-password-bypass-audit

Non-exploitive exposure audit for the **Alpine Linux OpenSSH/musl password
authentication bypass** (Alpine security advisory, November 2026): musl's
`crypt()` returns `*` as an error indicator for passwords longer than 256
bytes, which can collide with the `*` password-field marker used for
passwordless accounts on hosts running `sshd` without PAM. An attacker who
knows an eligible account name and can reach `sshd` can authenticate with
an overlong password (257-1024 bytes), without knowing any real password.

This repo does **not** contain a working exploit or any code that attempts
such a login. It contains:

1. `alpine_openssh_musl_password_bypass_audit.sh` — connects to each host
   with credentials you already manage (SSH key or account you control)
   and checks, read-only, whether the conditions for this bug are
   present, and whether the host's installed version is already patched.
   It never sends a crafted or overlong password.
2. `REMEDIATION.md` — the fix, in order, including incident-response
   steps if you suspect a host was already exploited.

## Who this is for

Teams and MSPs auditing their own fleet, or a fleet they are contracted
to assess, for this exposure class before patching. You need legitimate
SSH access to every host you scan. This tool assumes you already have
that access; it does not get you access.

## What the audit checks

A host is flagged `EXPOSED` only when all four hold:

1. `sshd` is linked against musl (not glibc)
2. Effective `UsePAM` is `no`, read via `sshd -T` (the effective
   configuration, which correctly resolves `Match` blocks and unset
   defaults, rather than a raw grep of `sshd_config`)
3. Effective `PasswordAuthentication` is `yes`, same method
4. `/etc/shadow` has at least one account with `*`/`!`/`!!` as its hash
   **and** at least one other account with a `$5$`/`$6$` (sha256/sha512
   crypt) hash

It also reports the installed Alpine release so you can cross-check it
against the known-fixed branches: **3.21.10, 3.22.8, 3.23.8, 3.24.4**
(with backports to 3.16.x). Patch status is not inferred automatically
from the version string alone, since Alpine backports fixes into point
releases; always cross-check against the current advisory.

If any condition can't be verified (e.g. no sudo to run `sshd -T` or read
`/etc/shadow`), the host is flagged `NEEDS-SUDO` rather than guessing.

## Usage

```sh
chmod +x alpine_openssh_musl_password_bypass_audit.sh
./alpine_openssh_musl_password_bypass_audit.sh hosts.txt [ssh_user] [ssh_key_path]
```

`hosts.txt`: one hostname or IP per line. Blank lines and lines starting
with `#` are ignored.

Requires key-based (or otherwise pre-authenticated) SSH access to every
host listed. For the `sshd -T` and `/etc/shadow` checks, the SSH user
needs passwordless sudo (`sudo -n`); hosts without it are flagged
`NEEDS-SUDO` rather than silently skipped.

### Example

```
$ cat hosts.txt
10.0.1.10
10.0.1.11
web01.internal.example.com

$ ./alpine_openssh_musl_password_bypass_audit.sh hosts.txt ops ~/.ssh/ops_key

HOST                         ALPINE    VERSION    MUSL_SSHD          PAM            PWAUTH    VERDICT
--------------------------------------------------------------------------------------------------------------
10.0.1.10                    yes       3.20.3     yes                UsePAM=no      yes       EXPOSED
10.0.1.11                    yes       3.21.10    yes                UsePAM=yes     yes       LOW-RISK
web01.internal.example.com   no        not-alpine no                 UsePAM=yes     no        LOW-RISK
```

## Remediation

See [REMEDIATION.md](./REMEDIATION.md): patch first, disable password
auth as an interim mitigation if you can't patch immediately, enable PAM
as a second layer, clean up malformed shadow hashes, and check logs for
signs of prior exploitation before re-running the audit to confirm
`LOW-RISK`.

## Scope and limitations

- This checks exposure; it does not verify end-to-end exploitability and
  never performs a live login attempt of any kind.
- `ldd`-less or statically-linked `sshd` builds may report
  `static-unknown` for musl linkage; verify manually with `apk info musl`
  or `file` on those hosts.
- The VERSION column reports the installed release; cross-reference it
  against the current Alpine security advisory rather than assuming any
  version comparison here is authoritative.
- Only run this against hosts you own or are explicitly authorized to
  assess.

## Related reading

- [How to Audit and Fix the Alpine OpenSSH Password Bypass](https://dev.to/jamilxt/how-to-audit-and-fix-the-alpine-openssh-password-bypass-5hih) — the original writeup this tool was built against; worth reading for the full advisory context and log-forensics detail.

## License

MIT. See [LICENSE](./LICENSE).
