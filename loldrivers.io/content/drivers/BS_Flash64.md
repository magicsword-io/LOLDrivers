+++

description = ""
title = "BS_Flash64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# BS_Flash64.sys ![:inline](/images/twitter_verified.png) 


### Description

BS_Flash64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create BS_Flash64.sys binPath=C:\windows\temp\BS_Flash64.sys type=kernel
sc.exe start BS_Flash64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<li><a href="https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md">https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Filename | BS_Flash64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/f5051c756035ef5de9c4c48bacb0612b">f5051c756035ef5de9c4c48bacb0612b</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/e83458c4a6383223759cd8024e60c17be4e7c85f">e83458c4a6383223759cd8024e60c17be4e7c85f</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/86a8e0aa29a5b52c84921188cc1f0eca9a7904dcfe09544602933d8377720219">86a8e0aa29a5b52c84921188cc1f0eca9a7904dcfe09544602933d8377720219</a> |
| Signature | BIOSTAR MICROTECH INT&#39;L CORP, VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bs_flash64.yaml)

*last_updated:* 2023-04-05








{{< /column >}}
{{< /block >}}
