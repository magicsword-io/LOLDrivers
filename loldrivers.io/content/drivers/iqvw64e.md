+++

description = ""
title = "iqvw64e.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# iqvw64e.sys ![:inline](/images/twitter_verified.png) 


### Description

(1) IQVW32.sys before 1.3.1.0 and (2) IQVW64.sys before 1.3.1.0 in the Intel Ethernet diagnostics driver for Windows allows local users to cause a denial of service or possibly execute arbitrary code with kernel privileges via a crafted (a) 0x80862013, (b) 0x8086200B, (c) 0x8086200F, or (d) 0x80862007 IOCTL call.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create iqvw64e.sys binPath=C:\windows\temp\iqvw64e.sys type=kernel
sc.exe start iqvw64e.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.crowdstrike.com/blog/scattered-spider-attempts-to-avoid-detection-with-bring-your-own-vulnerable-driver-tactic/">https://www.crowdstrike.com/blog/scattered-spider-attempts-to-avoid-detection-with-bring-your-own-vulnerable-driver-tactic/</a></li>
<li><a href="https://expel.com/blog/well-that-escalated-quickly-how-a-red-team-went-from-domain-user-to-kernel-memory/">https://expel.com/blog/well-that-escalated-quickly-how-a-red-team-went-from-domain-user-to-kernel-memory/</a></li>
<li><a href="https://github.com/Exploitables/CVE-2015-2291">https://github.com/Exploitables/CVE-2015-2291</a></li>
<li><a href="https://github.com/Tare05/Intel-CVE-2015-2291">https://github.com/Tare05/Intel-CVE-2015-2291</a></li>
<li><a href="https://github.com/TheCruZ/kdmapper">https://github.com/TheCruZ/kdmapper</a></li>
<br>

### Known Vulnerable Samples

| Filename | iqvw64e.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/1898ceda3247213c084f43637ef163b3">1898ceda3247213c084f43637ef163b3</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/d04e5db5b6c848a29732bfd52029001f23c3da75">d04e5db5b6c848a29732bfd52029001f23c3da75</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b">4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b</a> |
| Publisher |  |
| Signature | Intel Corporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Date |  |
| Company | Intel |
| Description | Intel(R) Network Adapter Diagnostic Driver |
| Product | Intel(R) iQVW64.SYS |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename | iQVW64.SYS |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/iqvw64e.sys.yml)

*last_updated:* 2023-03-30








{{< /column >}}
{{< /block >}}
