# Lab-X Exercise Outcomes

Environment build: [README.md](README.md).

This file records what was practiced on the lab VMs, what showed up, and what to fix or alert on. It is not a command-by-command attack playbook. Work was done on hosts you own on `lab-x-network` only.

---

## Timeline: first scan through persistence

All of this ran from `lab-x-kali` (`10.0.0.50`) against the lab NAT network. Designated lab secrets used on purpose: `root@corp-svr` / `november`, and domain `Administrator` / `@Deeboodah1!`.

1. **First service map (ports 1-1000).** A TCP service scan of the lab subnet showed eight live addresses. The DC (`10.0.0.5`) advertised DNS, Kerberos, LDAP, and SMB for `corp.lab-x-dc.com`. `corp-svr` (`10.0.0.8`) showed only SSH in that range. `lab-x-sec-mon` (`10.0.0.10`) showed HTTPS with `osd-name: sec-mon`. `lab-x-ubu-client` (`10.0.0.101`) showed SSH and Postfix. Kali itself showed SSH and Apache.

2. **Weak SSH on the mail host.** Port 22 on `10.0.0.8` was open. The lab `root` password was a dictionary word set for this exercise. After it was recovered, an SSH session as `root@corp-svr` worked.

3. **Local listen ports on `corp-svr`.** `netstat` showed MailHog on `1025/tcp` (SMTP) and `8025/tcp` (web UI), bound on all interfaces. Those ports were outside the first scan range, so they only appeared after local access.

4. **MailHog as an internal mail path.** The UI at `http://10.0.0.8:8025` and `/home/mailhog/test_message.py` showed mail already going to `janed@ubu-client`.

5. **Phishing site on Kali.** Apache was started with `sudo service apache2 start`. The fake verify-password page was served at `http://10.0.0.50`. Lab files: [index.html](https://github.com/21bitt/SOC-Lab/blob/main/index.html) and [process.php](https://github.com/21bitt/SOC-Lab/blob/main/process.php). Submitted values were written to `creds.log`.

6. **Lure to Jane Doe.** A MailHog message to `janed@linux-client` claimed to be HR/security and linked to `http://10.0.0.50`. From the Ubuntu client the link was opened on purpose. The test username and password then appeared in `creds.log`.

7. **Second scan (all TCP ports).** A later scan of ports 1-65535 found WinRM `5985/5986` on `lab-x-win-client` (`10.0.0.100`) and WinRM plus RDP `3389` on the DC (`10.0.0.5`), along with the rest of the AD port set (`3268`, `3269`, and so on).

8. **WinRM to the Windows workstation.** NetExec was used against WinRM on `10.0.0.100` with the designated lab Administrator account. After that login worked, Evil-WinRM opened a remote shell. `hostname` returned `lab-x-win-client`.

9. **Find the DC from the workstation.** `nltest /dsgetdc:` from a `johnd.CORP` prompt returned `WIN-23NL888TQBS.corp.lab-x-dc.com` at `10.0.0.5`, forest `corp.lab-x-dc.com`, PDC/GC/KDC flags set.

10. **RDP to the DC.** The same Administrator lab account and domain `corp.lab-x-dc.com` were used to open a FreeRDP desktop on `10.0.0.5`.

11. **Mock file copy.** `secrets.txt` under `C:\Users\Administrator\Documents\ProductionFiles` was copied to Kali as `/home/kali/exfil.txt`.

12. **Study account.** `lab-x-user` was created, added to local Administrators and Domain Admins, and checked with `net user lab-x-user /domain`.

13. **Scheduled task.** Task `PersistenceTask` was set to run daily at 12:00 and pointed at a PowerShell file under the Administrator AppData Windows folder. Task Scheduler Library showed the task. Lab note: [scheduled task example](https://github.com/21bitt/SOC-Lab/blob/main/scheduled%20task%20example).

14. **Callback check.** Kali listened on TCP 4444. The script was started from the DC session. The listener showed a connect from `10.0.0.5` and the line `Connected to reverse shell!` Lab note: [reverse.ps1 example](https://github.com/21bitt/SOC-Lab/blob/main/reverse.ps1%20example).

15. **No cleanup.** Logs and artifacts were left so Wazuh and Windows Security logs can be reviewed.

The sections below repeat the same work with tables and defense notes.

---

## Exercise 1: Recon and internal phishing

### What was practiced

1. Map live hosts and services on the lab `/24`.
2. Show how a weak SSH password on `corp-svr` leads to local access.
3. Show how MailHog can carry a phishing lure to `janed`, and how a fake login page can capture a submitted password.

### What showed up

From Kali (`10.0.0.50`), a TCP service scan of ports 1 through 1000 (Nmap 7.99, 21 Oct 2026) found eight addresses.

| IP | Likely host | Notable open ports | What it showed |
| :--- | :--- | :--- | :--- |
| `10.0.0.1` | NAT gateway | 135/tcp (MSRPC), 445/tcp | Windows-style RPC and SMB on the virtual router path |
| `10.0.0.2` | VirtualBox NIC | none in 1-1000 | Host up, no services in the scanned range |
| `10.0.0.5` | `lab-x-dc` / `CORP` | 53, 88, 135, 139, 389, 445, 464, 593, 636 | AD DC for `corp.lab-x-dc.com`. NetBIOS name `WIN-23NL888TQBS` |
| `10.0.0.8` | `corp-svr` | 22/tcp OpenSSH 8.9p1 Ubuntu | SSH only in this port range. MailHog ports were outside 1-1000 |
| `10.0.0.10` | `lab-x-sec-mon` | 443/tcp HTTPS | TLS site redirects to `/app/login`. Header `osd-name: sec-mon` |
| `10.0.0.101` | `lab-x-ubu-client` | 22/tcp OpenSSH 8.9p1, 25/tcp Postfix | SSH plus local SMTP. Nmap hostname `ubu-client` |
| `10.0.0.7` | extra Debian/Kali-like host | 22/tcp OpenSSH 10.3p1, 80/tcp Apache 2.4.68 | Second web/SSH listener on the NAT net |
| `10.0.0.50` | `lab-x-kali` | 22/tcp OpenSSH 10.3p1, 80/tcp Apache 2.4.68 | Tester VM |

The `root` account on `corp-svr` was given the dictionary password `november` on purpose. After that password was found, login as `root@corp-svr` succeeded. Root SSH with a password was allowed, and there was no lockout that stopped repeated guesses in time.

On `corp-svr`, `netstat -tuln` showed MailHog on all interfaces:

| Port | Service in this lab |
| :--- | :--- |
| `1025/tcp` | MailHog SMTP |
| `8025/tcp` | MailHog web UI and API |

The UI at `http://10.0.0.8:8025` showed mail to `janed@ubu-client`. The send script `/home/mailhog/test_message.py` posts through `localhost:1025`.

Apache on Kali was started with `sudo service apache2 start` and served `http://10.0.0.50`. Campaign files already in the public repo:

- [index.html](https://github.com/21bitt/SOC-Lab/blob/main/index.html)
- [process.php](https://github.com/21bitt/SOC-Lab/blob/main/process.php)

A MailHog message to `janed@linux-client` claimed to be HR/security and linked to `http://10.0.0.50`. From the Jane Doe VM the link was opened on purpose. The submitted test username and password appeared in `creds.log` on Kali.

### Defenses

- Disable root SSH passwords. Use keys and `PermitRootLogin prohibit-password` or `no`.
- Do not reuse `november` outside this lab.
- Do not bind MailHog SMTP/UI to `0.0.0.0` on a shared LAN.
- Treat ports 8025 and 1025 as sensitive. They did not show up in a 1-1000 scan.
- Treat unexpected "verify your password" mail with a raw IP link as phishing.
- Detection: Wazuh Linux `auth.log` for failed SSH; web or DNS logs for visits to `10.0.0.50`; mail logs for spoofed From headers.

---

## Exercise 2: Lateral movement, exfil, and persistence

### What was practiced

Find admin remote-management ports, reach `lab-x-win-client`, reach the DC, copy a mock file, then leave a study account and a scheduled task. Logs were left on purpose. Password retrieval is skipped in this write-up. The lab Administrator password (`@Deeboodah1!`) was set for this environment only.

### What showed up

A later TCP scan of ports 1 through 65535 on `10.0.0.0/24` showed ports the 1-1000 scan missed.

| Host | Ports | Meaning in this lab |
| :--- | :--- | :--- |
| `10.0.0.100` (`lab-x-win-client`) | 5985/tcp, 5986/tcp | WinRM (HTTP and HTTPS) |
| `10.0.0.5` (`lab-x-dc`) | 5985/tcp, 3389/tcp, plus AD ports | WinRM and RDP on the DC |

DC ports from that scan: `53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 3389, 5985`.

WinRM on `10.0.0.100` accepted the designated lab Administrator account. A remote shell on that host returned hostname `lab-x-win-client`.

From a `johnd.CORP` prompt, `nltest /dsgetdc:` returned:

| Field | Value |
| :--- | :--- |
| DC | `\\WIN-23NL888TQBS.corp.lab-x-dc.com` |
| Address | `\\10.0.0.5` |
| Dom Guid | `89f68fc9-92a1-47de-b5a8-65560af66826` |
| Dom Name / Forest | `corp.lab-x-dc.com` |
| Site | Default-First-Site-Name |
| Flags | PDC, GC, DS, LDAP, KDC, timeserv, writable DNS DC |

An RDP session to `10.0.0.5` as `Administrator` in `corp.lab-x-dc.com` opened a desktop on the DC.

Mock file `C:\Users\Administrator\Documents\ProductionFiles\secrets.txt` was copied to Kali as `/home/kali/exfil.txt`.

Study persistence left in place:

- Account `lab-x-user` added to local Administrators and Domain Admins (checked with `net user lab-x-user /domain`)
- Scheduled task `PersistenceTask`, daily at 12:00, pointed at a PowerShell file under Administrator AppData. See [scheduled task example](https://github.com/21bitt/SOC-Lab/blob/main/scheduled%20task%20example)
- A connect from `10.0.0.5` to Kali TCP 4444 with the line `Connected to reverse shell!` See [reverse.ps1 example](https://github.com/21bitt/SOC-Lab/blob/main/reverse.ps1%20example)

No log wiping was done so Wazuh and Windows logs can be reviewed.

### Defenses

- Do not expose WinRM (5985/5986) or RDP (3389) to the whole LAN without network controls and strong auth.
- Do not use Domain Admin as a daily login on `lab-x-win-client`. Use tiered admin.
- Alert on WinRM and RDP logons from `10.0.0.50`.
- Alert on new members of Domain Admins (`lab-x-user`).
- Alert on new scheduled tasks and PowerShell with execution-policy bypass.
- Outbound TCP from the DC to a client on port 4444 is a useful Wazuh or firewall finding.
- Treat `Documents\ProductionFiles` on the DC as a high-value path in FIM.
