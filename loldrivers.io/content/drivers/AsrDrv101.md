+++

description = ""
title = "AsrDrv101.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrDrv101.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrDrv101.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create AsrDrv101.sys binPath=C:\windows\temp\AsrDrv101.sys type=kernel &amp;&amp; sc.exe start AsrDrv101.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<li><a href="https://github.com/namazso/physmem_drivers">https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | AsrDrv101.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/1a234f4643f5658bab07bfa611282267">1a234f4643f5658bab07bfa611282267</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/57511ef5ff8162a9d793071b5bf7ebe8371759de">57511ef5ff8162a9d793071b5bf7ebe8371759de</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/f40435488389b4fb3b945ca21a8325a51e1b5f80f045ab019748d0ec66056a8b">f40435488389b4fb3b945ca21a8325a51e1b5f80f045ab019748d0ec66056a8b</a> |
| Publisher | ASROCK Incorporation || Signature | ASROCK Incorporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Company | ASRock Incorporation || Description | ASRock IO Driver || Product | ASRock IO Driver || OriginalFilename | AsrDrv.sys |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrdrv101.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
