# Remediation Runbook: Alpine OpenSSH/musl Password Bypass

## What this is

A class of sshd configurations on musl-based Linux (default on Alpine) where musl's `crypt()` returns `*` as an error indicator for passwords longer than 256 bytes. On a host running sshd without PAM, with password authentication enabled, this collides with the `*` password-field marker used for passwordless accounts: an attacker who knows the account name can authenticate with an overlong password (257-1024 bytes), with no correct password needed.

Published Alpine advisory, dated November 5, 2026. Fixed in stable releases 3.21.10, 3.22.8, 3.23.8, 3.24.4, with backports to 3.16.x.

This runbook remediates hosts flagged `EXPOSED` or `PARTIAL-RISK` by `alpine_openssh_musl_password_bypass_audit.sh`.

## 1. Patch first

```sh
apk update
apk upgrade -U -a
```

Then restart sshd, since the upgraded package does not replace an already-running daemon:

```sh
rc-service sshd restart
```

Confirm the installed release is at or above the fixed version for your branch:

```sh
cat /etc/alpine-release
apk info openssh-server
apk info musl
```

Compare against the current advisory, not just the version string: Alpine backports fixes into point releases, so a package can carry a fix without the upstream version number changing.

## 2. If you can't patch immediately: disable password auth

```
PasswordAuthentication no
```

in `/etc/ssh/sshd_config`. Validate before restarting:

```sh
sshd -t
```

Then restart and confirm the effective configuration picked it up:

```sh
rc-service sshd restart
sshd -T | grep -i passwordauthentication
```

**Before you do this**, open a second, separate SSH session using a key and confirm it logs in successfully. Do not close your current session until that's confirmed. If no working key-based session exists for an account you need, set one up first.

## 3. Enable PAM as a second layer

PAM enforces its own password-length and hash-validation checks that this bug skips.

```sh
apk add linux-pam
```

In `/etc/ssh/sshd_config`:

```
UsePAM yes
```

Validate and restart the same way as step 2, then confirm:

```sh
sshd -T | grep -i usepam
```

## 4. `PermitRootLogin prohibit-password` is not sufficient on its own

This setting blocks password login for the root account specifically, but does nothing for any other account with a `*`/`!` hash, including accounts with `doas` (or `sudo`) privileges that could grant an attacker root anyway. Audit all accounts, not just root.

## 5. Clean up `/etc/shadow` hash fields

Find accounts with a malformed/placeholder hash:

```sh
awk -F: '$2=="*" || $2=="!" || $2=="!!" {print $1}' /etc/shadow
```

For each:

- Service or system accounts that should never log in interactively: lock explicitly and remove shell access, rather than relying on `*` alone.

  ```sh
  passwd -l <account>
  usermod -s /sbin/nologin <account>
  ```

- Real users who need password access: set an actual password now.

  ```sh
  passwd <account>
  ```

## 6. Re-run the audit

```sh
./alpine_openssh_musl_password_bypass_audit.sh hosts.txt
```

A remediated host should read `LOW-RISK`, with the VERSION column at or above the fixed release for its branch. If musl linkage shows `static-unknown`, verify manually (`apk info musl`, or `file` on the sshd binary).

## 7. If you suspect this was already exploited

Treat the host as a potential incident before doing anything else on it:

- Preserve current logs and system state (snapshot/copy before you restart services or patch, if feasible).
- Search `/var/log/messages` (or the relevant syslog target) for unexpected `Accepted password for` entries on accounts that should not have password access:

  ```sh
  grep "Accepted password for" /var/log/messages
  ```

- Review `doas` (or `sudo`) activity logs for unexpected privilege escalation.
- Check for recently created user accounts and modified `authorized_keys` files:

  ```sh
  find /home /root -name authorized_keys -newer /etc/alpine-release 2>/dev/null
  ```

- Look for unexpected running processes or persistence mechanisms (cron jobs, init scripts, new services).
- If any of the above is positive, isolate the host from the network, rotate all credentials and SSH keys from a clean, separate system, and investigate further before returning it to service.

## Prevention

- Pin `musl`, `openssh-server` (and `linux-pam` if used) version checks into your base image build / CI pipeline so a future image build doesn't silently regress to an unpatched version.
- Bake steps 2 to 5 into your baseline hardening playbook (Ansible/Salt/etc.) for new host provisioning.
- Re-run the audit script on a schedule (e.g. monthly, or on every new host), not as a one-time check.
