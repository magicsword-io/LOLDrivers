+++

description = ""
title = "gftkyj64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# gftkyj64.sys ![:inline](/images/twitter_verified.png) 


### Description

SentinelOne has observed prominent threat actors abusing legitimately signed Microsoft drivers in active intrusions into telecommunication, BPO, MSSP, and financial services businesses.
Investigations into these intrusions led to the discovery of POORTRY and STONESTOP malware, part of a small toolkit designed to terminate AV and EDR processes.
We first reported our discovery to Microsoft’s Security Response Center (MSRC) in October 2022 and received an official case number (75361). Today, MSRC released an associated advisory under ADV220005.
This research is being released alongside Mandiant, a SentinelOne technology and incident response partner. 

- **Created**: 2023-03-04
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create gftkyj64.sys binPath=C:\windows\temp\gftkyj64.sys type=kernel
sc.exe start gftkyj64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.sentinelone.com/labs/driving-through-defenses-targeted-attacks-leverage-signed-malicious-microsoft-drivers/">https://www.sentinelone.com/labs/driving-through-defenses-targeted-attacks-leverage-signed-malicious-microsoft-drivers/</a></li>
<li><a href=""></a></li>
<br>

### Known Vulnerable Samples

| Filename | gftkyj64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/04a88f5974caa621cee18f34300fc08a">04a88f5974caa621cee18f34300fc08a</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/a804ebec7e341b4d98d9e94f6e4860a55ea1638d">a804ebec7e341b4d98d9e94f6e4860a55ea1638d</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/9b1b15a3aacb0e786a608726c3abfc94968915cedcbd239ddf903c4a54bfcf0c">9b1b15a3aacb0e786a608726c3abfc94968915cedcbd239ddf903c4a54bfcf0c</a> |
| Signature | 北京东方海达网络科技有限责任公司, Sectigo Public Code Signing CA R36, Sectigo Public Code Signing Root R46, Sectigo (AAA)   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/gftkyj64.sys.yml)

*last_updated:* 2023-04-04








{{< /column >}}
{{< /block >}}
