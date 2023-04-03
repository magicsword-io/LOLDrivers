+++

description = ""
title = "LcTkA.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# LcTkA.sys ![:inline](/images/twitter_verified.png) 


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
sc.exe create LcTkA.sys binPath=C:\windows\temp\LcTkA.sys type=kernel
sc.exe start LcTkA.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.sentinelone.com/labs/driving-through-defenses-targeted-attacks-leverage-signed-malicious-microsoft-drivers/">https://www.sentinelone.com/labs/driving-through-defenses-targeted-attacks-leverage-signed-malicious-microsoft-drivers/</a></li>
<br>

### Known Vulnerable Samples

| Filename | LcTkA.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/909f3fc221acbe999483c87d9ead024a">909f3fc221acbe999483c87d9ead024a</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/b2f955b3e6107f831ebe67997f8586d4fe9f3e98">b2f955b3e6107f831ebe67997f8586d4fe9f3e98</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/c8f9e1ad7b8cce62fba349a00bc168c849d42cfb2ca5b2c6cc4b51d054e0c497">c8f9e1ad7b8cce62fba349a00bc168c849d42cfb2ca5b2c6cc4b51d054e0c497</a> |
| Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/lctka.sys.yml)

*last_updated:* 2023-04-03








{{< /column >}}
{{< /block >}}
