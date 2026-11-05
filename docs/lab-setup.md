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