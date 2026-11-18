   # Kerbo-S lab setup

   Built by Ben Grider on Nov 5, 2026. Follows the KDC Lab Setup Guide (Ben's Sprint 2 Guide, Phase 1), adapted from VirtualBox to Proxmox.

   ## VM
   - Proxmox VM: kerbo-kdc (2 CPU, 4 GB RAM, 32 GB disk on local-zfs)
   - OS: Ubuntu Server 26.04 LTS (amd64), updated to 26.04.1
   - Network: Proxmox bridge vmbr0 on the home LAN (DHCP), SSH on port 22
   - Snapshot: clean-baseline (Proxmox snapshot)

   ## Kerberos
   - Realm: KERBO.LAB
   - KDC and admin server: kdc.kerbo.lab (10.27.27.32 in /etc/hosts)
   - Packages: krb5-kdc, krb5-admin-server, krb5-user
   - Principals: alice (user), ben/admin (admin), plus built-ins
   - Policy: standard (minlength 12, maxlife 90 days)
   - ACL: */admin@KERBO.LAB *

   ## kdc.conf defaults (clean baseline)
   - max_life: 10h 0m 0s
   - max_renewable_life: 7d 0h 0m 0s
   - supported_enctypes: not set (commented out), so MIT's default applies: aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal

   ## Commands used
   Run on the VM as kerbo.

   ```
   sudo apt update && sudo apt upgrade -y
   sudo hostnamectl set-hostname kdc.kerbo.lab
   # /etc/hosts: 10.27.27.32 kdc.kerbo.lab kdc
   sudo apt install -y krb5-kdc krb5-admin-server krb5-user   # realm KERBO.LAB, servers kdc.kerbo.lab
   sudo krb5_newrealm                                         # runs kdb5_util create
   # /etc/krb5kdc/kadm5.acl: */admin@KERBO.LAB *
   sudo kadmin.local
     addpol -minlength 12 -maxlife "90 days" standard
     addprinc -policy standard alice
     addprinc -policy standard ben/admin
   sudo systemctl restart krb5-kdc krb5-admin-server
   sudo systemctl enable krb5-kdc krb5-admin-server
   kinit alice && klist                                       # TC-ENV-01
   kinit ben/admin && kadmin -p ben/admin -q "listprincs" && kdestroy
   ```

   ## Credentials
   Stored on private chat

   ## Tests
   - TC-ENV-01: Pass on Nov 5, 2026, evidence in docs/evidence/TC-ENV-01.png
   ## Live collector (Sprint 3, S3-04)
   The collector runs on the KDC with the Python standard library only; nothing needs installing. It runs only read-only list and get commands (allow-listed), copies the config files, includes and ACL, reads 30 days of the KDC journal, and writes a snapshot folder with hashes.json last.

   From a PC with the repo (git pull first):

   ```
   scp -r src kerbo@kdc.kerbo.lab:~/kerbo-s/
   ```

   On the KDC:

   ```
   sudo PYTHONPATH=~/kerbo-s/src python3 -m kerbo_s.collectors.live --out ~/snapshots/clean
   ```

   - The output folder must be new or empty. Use a new name for each run.
   - Files belong to the user who ran sudo, so they can be copied back: `scp -r kerbo@kdc.kerbo.lab:~/snapshots/clean .`
   - `commands.log` lists every command run (TC-COL-06). `collection_errors.txt` exists only if something could not be read.
   - Exit code 2 and "Cannot reach the KDC" means kadmin.local could not run (for example, not run with sudo).
   - Check the folder from the repo on a PC: `python -m kerbo_s.cli audit --snapshot clean` (exit 4 means a file changed after capture).
