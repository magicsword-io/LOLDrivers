+++

description = ""
title = "POORTRY1.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# POORTRY1.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver categorized as POORTRY by Mandiant.

- **Created**: 2023-03-04
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create POORTRY1.sys binPath=C:\windows\temp\POORTRY1.sys type=kernel
sc.exe start POORTRY1.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware">https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware</a></li>
<br>

### Known Vulnerable Samples

| Filename | POORTRY1.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/acac842a46f3501fe407b1db1b247a0b">acac842a46f3501fe407b1db1b247a0b</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/31fac347aa26e92db4d8c9e1ba37a7c7a2234f08">31fac347aa26e92db4d8c9e1ba37a7c7a2234f08</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/575e58b62afab094c20c296604dc3b7dd2e1a50f5978d8ee24b7dca028e97316">575e58b62afab094c20c296604dc3b7dd2e1a50f5978d8ee24b7dca028e97316</a> |
| Publisher |  |
| Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |
| Date |  |
| Company |  |
| Description |  |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/poortry1.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
