+++

description = ""
title = "POORTRY2.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# POORTRY2.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver categorized as POORTRY by Mandiant.

- **Created**: 2023-03-04
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create POORTRY2.sys binPath=C:\windows\temp\POORTRY2.sys type=kernel
sc.exe start POORTRY2.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware">https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware</a></li>
<br>

### Known Vulnerable Samples

| Filename | POORTRY2.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/b164daf106566f444dfb280d743bc2f7">b164daf106566f444dfb280d743bc2f7</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/7e836dadc2e149a0b758c7e22c989cbfcce18684">7e836dadc2e149a0b758c7e22c989cbfcce18684</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/9bb09752cf3a464455422909edef518ac18fe63cf5e1e8d9d6c2e68db62e0c87">9bb09752cf3a464455422909edef518ac18fe63cf5e1e8d9d6c2e68db62e0c87</a> |
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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/poortry2.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
