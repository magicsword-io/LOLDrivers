+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "MsIo32.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# MsIo32.sys ![:inline](/images/twitter_verified.png) 


### Description

The MsIo64.sys and MsIo32.sys drivers in Patriot Viper RGB before 1.1 allow local users (including low integrity processes) to read and write to arbitrary memory locations, and consequently gain NT AUTHORITY\SYSTEM privileges, by mapping \Device\PhysicalMemory into the calling process via ZwOpenSection and ZwMapViewOfSection.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create MsIo32.sys binPath=C:\windows\temp\MsIo32.sys type=kernel
sc.exe start MsIo32.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<li><a href="https://www.activecyber.us/activelabs/viper-rgb-driver-local-privilege-escalation-cve-2019-18845">https://www.activecyber.us/activelabs/viper-rgb-driver-local-privilege-escalation-cve-2019-18845</a></li>
<li><a href="http://blog.rewolf.pl/blog/?p=1630">http://blog.rewolf.pl/blog/?p=1630</a></li>
<br>

### Known Vulnerable Samples

| Filename | MsIo32.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/d9e7e5bcc5b01915dbcef7762a7fc329">d9e7e5bcc5b01915dbcef7762a7fc329</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/e6305dddd06490d7f87e3b06d09e9d4c1c643af0">e6305dddd06490d7f87e3b06d09e9d4c1c643af0</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/525d9b51a80ca0cd4c5889a96f857e73f3a80da1ffbae59851e0f51bdfb0b6cd">525d9b51a80ca0cd4c5889a96f857e73f3a80da1ffbae59851e0f51bdfb0b6cd</a> |
| Publisher |  |
| Signature | MICSYS Technology Co., Ltd., Symantec Class 3 Extended Validation Code Signing CA - G2, VeriSign   |
| Date |  |
| Company |  |
| Description |  |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/msio32.sys.yml)

*last_updated:* 2023-03-29








{{< /column >}}
{{< /block >}}
