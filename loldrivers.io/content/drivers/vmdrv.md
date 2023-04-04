+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "vmdrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# vmdrv.sys ![:inline](/images/twitter_verified.png) 


### Description

vmdrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create vmdrv.sys binPath=C:\windows\temp\vmdrv.sys type=kernel
sc.exe start vmdrv.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Filename | vmdrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/d5db81974ffda566fa821400419f59be">d5db81974ffda566fa821400419f59be</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/4c18754dca481f107f0923fb8ef5e149d128525d">4c18754dca481f107f0923fb8ef5e149d128525d</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/32cccc4f249499061c0afa18f534c825d01034a1f6815f5506bf4c4ff55d1351">32cccc4f249499061c0afa18f534c825d01034a1f6815f5506bf4c4ff55d1351</a> |
| Signature | Voicemod Sociedad Limitada, DigiCert Global G3 Code Signing ECC SHA384 2021 CA1, DigiCert Global Root G3   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/vmdrv.sys.yml)

*last_updated:* 2023-04-04








{{< /column >}}
{{< /block >}}
