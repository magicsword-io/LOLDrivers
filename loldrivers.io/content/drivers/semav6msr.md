+++

description = ""
title = "semav6msr.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# semav6msr.sys ![:inline](/images/twitter_verified.png) 


### Description

semav6msr.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create semav6msr.sys binPath=C:\windows\temp\semav6msr.sys type=kernel
sc.exe start semav6msr.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<li><a href="https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md">https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Filename | semav6msr.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/07f83829e7429e60298440cd1e601a6a">07f83829e7429e60298440cd1e601a6a</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/643383938d5e0d4fd30d302af3e9293a4798e392">643383938d5e0d4fd30d302af3e9293a4798e392</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/9f1229cd8dd9092c27a01f5d56e3c0d59c2bb9f0139abf042e56f343637fda33">9f1229cd8dd9092c27a01f5d56e3c0d59c2bb9f0139abf042e56f343637fda33</a> |
| Signature | Intel(R) Code Signing External, Intel External Basic Issuing CA 3B, Intel External Basic Policy CA, Sectigo (AddTrust)   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/semav6msr.yaml)

*last_updated:* 2023-04-10








{{< /column >}}
{{< /block >}}
