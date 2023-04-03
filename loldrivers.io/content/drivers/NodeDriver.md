+++

description = ""
title = "NodeDriver.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# NodeDriver.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver categorized as POORTRY by Mandiant.

- **Created**: 2023-03-02
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create NodeDriver.sys binPath=C:\windows\temp\NodeDriver.sys type=kernel
sc.exe start NodeDriver.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware">https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware</a></li>
<br>

### Known Vulnerable Samples

| Filename | NodeDriver.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/ee6b1a79cb6641aa44c762ee90786fe0">ee6b1a79cb6641aa44c762ee90786fe0</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/3ef30c95e40a854cc4ded94fc503d0c3dc3e620e">3ef30c95e40a854cc4ded94fc503d0c3dc3e620e</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/05b146a48a69dd62a02759487e769bd30d39f16374bc76c86453b4ae59e7ffa4">05b146a48a69dd62a02759487e769bd30d39f16374bc76c86453b4ae59e7ffa4</a> |
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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/nodedriver.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
