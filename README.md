# Firewall template

Firewall script. Includes:

- Reset rules, counters and redirections
- Support for IPv6 rules
- `DROP` as default policy
- Enabled local traffic
- Enables by default HTTP/HTTPS, SSH, Ping, DNS, SMTP, Git and FTP
- Enables logging
- Uses iptables-save to persist rules
