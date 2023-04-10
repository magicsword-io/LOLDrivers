+++

description = ""
title = "fidpcidrv64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# fidpcidrv64.sys ![:inline](/images/twitter_verified.png) 


### Description

fidpcidrv64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create fidpcidrv64.sys binPath=C:\windows\temp\fidpcidrv64.sys type=kernel
sc.exe start fidpcidrv64.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<li><a href="https://github.com/elastic/protections-artifacts/search?q=VulnDriver">https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Filename | fidpcidrv64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/2fed983ec44d1e7cffb0d516407746f2">2fed983ec44d1e7cffb0d516407746f2</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/eb93d2f564fea9b3dc350f386b45de2cd9a3e001">eb93d2f564fea9b3dc350f386b45de2cd9a3e001</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/3ac5e01689a3d745e60925bc7faca8d4306ae693e803b5e19c94906dc30add46">3ac5e01689a3d745e60925bc7faca8d4306ae693e803b5e19c94906dc30add46</a> |
| Signature | Intel(R) Processor Identification Utility, Intel External Basic Issuing CA 3A, Intel External Basic Policy CA, GeoTrust   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/fidpcidrv64.yaml)

*last_updated:* 2023-04-10








{{< /column >}}
{{< /block >}}
