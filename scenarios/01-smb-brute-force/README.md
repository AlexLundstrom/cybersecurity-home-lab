# Scenario 01: SMB brute force

In the scenario, from attacker Kali, I scanned the target with Nmap and found SMB open. I then used NetExec to confirm the target details. I then used brute-force to a local account svc_backup with a wordlist consisting of passwords. I got in on the last attempt and read a file from its share `Backup` with `smbclient`. After that, a detector reads the security log and finds the attack by seeing the failed logons, the successful logon, and the access of the share `Backup`.

|           |                                                                                                             |
| --------- | ----------------------------------------------------------------------------------------------------------- |
| Attacker  | Kali, `192.168.56.10`                                                                                       |
| Target    | Windows 11 `WIN11-TARGET`, `192.168.56.20`, built with [Setup-Target.ps1](../../lab/setup/Setup-Target.ps1) |
| Weakness  | local account `svc_backup` with a seasonal password, readable share `Backup`                                |
| Detection | [detect/detect_bruteforce.py](detect/detect_bruteforce.py)                                                  |
| Evidence  | [evidence/](evidence/): Security log and packet capture from the run                                        |

## MITRE ATT&CK

I mapped the attack using the public framework [MITRE ATT&CK](https://attack.mitre.org/) to label the techniques, and 
learn standards used in cybersecurity fields.

Here are the techniques used for this scenario:

| Phase  | Technique                                                                          |
| ------ | ---------------------------------------------------------------------------------- |
| Recon  | T1046 Network Service Discovery, T1135 Network Share Discovery                     |
| Attack | T1110.001 Brute Force: Password Guessing, T1078.003 Valid Accounts: Local Accounts |
| Attack | T1039 Data from Network Shared Drive                                               |


## Recon

In the attacker VM, I scanned every TCP port with the command:
`sudo nmap -sS -sV -p- --min-rate 1000 192.168.56.20 -oN recon-nmap.txt`
I found 4 ports which were open, and they were 135, 49668, 445, and 7680. Other ports were not shown because of the firewall rule I had in the target VM. 

I then ran the command:
`nxc smb 192.168.56.20`
This revealed the target's operating system, pc name, and that the SMB signing was on. 

## Attack

I used the wordlist [attack/wordlist.txt](attack/wordlist.txt). It has eight passwords with the right one being last. 
The wordlist found the right password that was Syksy2026! on the last try. Wireshark shows that Windows answered each failed attempt as STATUS_LOGON_FAILURE. The attempts were about 2000 ms apart from each other which matches the SMB delay that was put in previous session. 

Here are the 7 failed attempts. Kali appears as 192.168.56.101 because it was still on its DHCP address when I ran the attack.
![The 7 failed attempts](evidence/wireshark_failed_logins.png)

After the password worked, I listed the share `Backup` and read `network-passwords.txt` from it with `smbclient`. 

## Detect

After running the detector against the Security log, it gives me three findings:

`Scenario 01 Detection: 3 finding(s) in ../evidence/Security.evtx`
`(785 records read, 0 skipped, times in UTC)`

`[CRITICAL] 192.168.56.101  brute force -> logon -> share access`
  `2026-11-24 13:34:03Z  first failed network logon (4625)`
  `2026-11-24 13:34:14Z  7 failed logons in a row, accounts tried: svc_backup`
  `2026-11-24 13:34:16Z  successful network logon as svc_backup (4624, type 3)`
  `2026-11-24 13:34:16Z  share opened: \\*\IPC$ (5140)`
  `2026-11-24 13:34:16Z  file accessed: svcctl (5145)`
  `2026-11-24 13:34:40Z  file accessed: srvsvc (5145)`
  `2026-11-24 13:34:40Z  share opened: \\*\ADMIN$ (5140)`
  `2026-11-24 13:34:40Z  share opened: \\*\Backup (5140)`
  `2026-11-24 13:34:40Z  file accessed: lYQswbeHVT (5145)`
  `2026-11-24 13:34:40Z  file accessed: KYnhjzCvHX.txt (5145)`                                               
  `2026-11-24 13:34:40Z  share opened: \\*\C$ (5140)`                                                                
  `2026-11-24 13:35:11Z  file accessed: network-passwords.txt (5145)`                                  

`[CRITICAL] 192.168.56.101  brute force -> logon -> share access`
  `2026-11-24 13:41:40Z  first failed network logon (4625)`
  `2026-11-24 13:41:47Z  7 failed logons in a row, accounts tried: svc_backup`
  `2026-11-24 13:41:48Z  successful network logon as svc_backup (4624, type 3)`
  `2026-11-24 13:41:48Z  share opened: \\*\IPC$ (5140)`
  `2026-11-24 13:41:48Z  file accessed: svcctl (5145)`

`[CRITICAL] 192.168.56.10  brute force -> logon -> share access`
  `2026-11-25 16:40:28Z  first failed network logon (4625)`
  `2026-11-25 16:40:39Z  7 failed logons in a row, accounts tried: svc_backup`
  `2026-11-25 16:40:41Z  successful network logon as svc_backup (4624, type 3)`
  `2026-11-25 16:40:41Z  share opened: \\*\IPC$ (5140)`
  `2026-11-25 16:40:41Z  file accessed: svcctl (5145)`

Each finding is the same topic. The findings are all about failed logons at the account `svc_backup`, then a successful logon, and the attacker reading from the share. 

The first two findings are from an attempt where the attacker IP was .101. 
My first attempt at detection came back with 0 findings out of 96 records, which didn't match what I had done. I found that the reason for that was restoring the target VM to an earlier snapshot after running the attack. That erased the security log. 

After running the attack again and exporting the security log, I got the findings above and confirmed that the detector works correctly.

## What I learnt from this
I learnt setting up and running a home lab. I built the lab using VirtualBox with two different operating systems on an isolated network. I set up the network, accounts, files and the snapshots. I also worked on both Linux and Windows command lines. 

I learnt the basics of penetration testing and red teaming. I ran the attack from Kali by scanning the target with Nmap, enumerating SMB with NetExec, brute-forcing an account with a list, and reading a file in the account after getting in. 

I learnt monitoring by reading the security logs in the Windows VM, and learning event IDs and logon types by being able to tell the attack apart from normal operation. I also used Wireshark by reading the traffic and finding the login tries by using filters. 

I learnt to write a simple detector using Python, to detect an attack chain from the security logs. 


## Sources used in the scenario
https://www.blackhillsinfosec.com/getting-started-with-netexec/

https://www.netexec.wiki/smb-protocol/password-spraying

https://attack.mitre.org/

https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625