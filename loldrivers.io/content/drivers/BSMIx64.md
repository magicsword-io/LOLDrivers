+++

description = ""
title = "BSMIx64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# BSMIx64.sys ![:inline](/images/twitter_verified.png) 


### Description

BSMIx64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create BSMIx64.sys binPath=C:\windows\temp\BSMIx64.sys type=kernel
sc.exe start BSMIx64.sys
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

| Filename | BSMIx64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/444f538daa9f7b340cfd43974ed43690">444f538daa9f7b340cfd43974ed43690</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/c6bd965300f07012d1b651a9b8776028c45b149a">c6bd965300f07012d1b651a9b8776028c45b149a</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/552f70374715e70c4ade591d65177be2539ec60f751223680dfaccb9e0be0ed9">552f70374715e70c4ade591d65177be2539ec60f751223680dfaccb9e0be0ed9</a> |
| Signature | BIOSTAR MICROTECH INT&#39;L CORP, VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bsmix64.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
