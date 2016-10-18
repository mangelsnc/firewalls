#!/bin/bash

IPTABLES=/sbin/iptables;
IPTABLES_SAVE=/sbin/iptables-save
IP6TABLES_SAVE=/sbin/ip6tables-save

echo "[FIREWALL] Flush current settings..."
$IPTABLES -F;
$IPTABLES -X;
$IPTABLES -Z;
$IPTABLES -t nat -F;

echo "[FIREWALL] Apply default policy DROP...";
$IPTABLES -P INPUT DROP;
$IPTABLES -P OUTPUT DROP;
$IPTABLES -P FORWARD DROP;

echo "[FIREWALL] Allow localhost to connect to everything...";
$IPTABLES -A INPUT -i lo -j ACCEPT
$IPTABLES -A OUTPUT -o lo -j ACCEPT

echo "[FIREWALL] Allow connections to webserver...";
$IPTABLES -A INPUT -i eth0 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -o eth0 -p tcp --sport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -o eth0 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES -A INPUT -i eth0 -p tcp --sport 80 -m state --state NEW,ESTABLISHED -j ACCEPT

$IPTABLES -A INPUT -i eth0 -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -o eth0 -p tcp --sport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -o eth0 -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES -A INPUT -i eth0 -p tcp --sport 443 -m state --state NEW,ESTABLISHED -j ACCEPT

echo "[FIREWALL] Allow connections to SSH...";
$IPTABLES -A INPUT -i eth0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -o eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -o eth0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES -A INPUT -i eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

echo "[FIREWALL] Allow ping"
$IPTABLES -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
$IPTABLES -A OUTPUT -p icmp -m icmp --icmp-type 0 -j ACCEPT

echo "[FIREWALL] Allow DNS resolutions"
$IPTABLES -A INPUT -p udp --sport 53 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT

echo "[FIREWALL] Allow SMTP to Mandrillapp"
$IPTABLES -A OUTPUT -p tcp --dport 587 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES -A INPUT -p tcp --sport 587 -m state --state ESTABLISHED -j ACCEPT

echo "[FIREWALL] Allow GIT protocol"
$IPTABLES -A INPUT -p tcp --sport 9418 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 9418 -m state --state NEW,ESTABLISHED -j ACCEPT

echo "[FIREWALL] Enable FTP outgoing"
$IPTABLES -A INPUT -p tcp --sport 21 -m state --state ESTABLISHED -j ACCEPT
$IPTABLES -A INPUT -p tcp --sport 20 -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -A INPUT -p tcp --sport 1024: --dport 1024: -m state --state ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 21 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 20 -m state --state ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --sport 1024: --dport 1024: -m state --state ESTABLISHED,RELATED,NEW -j ACCEPT

echo "[FIREWALL] Enable logging"
$IPTABLES -N LOGGING
$IPTABLES -A OUTPUT -j LOGGING
$IPTABLES -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4

$IPTABLES_SAVE > /etc/iptables/rules.v4
$IP6TABLES_SAVE > /etc/iptables/rules.v6

