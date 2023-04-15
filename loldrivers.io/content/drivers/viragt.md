+++

description = ""
title = "viragt.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# viragt.sys ![:inline](/images/twitter_verified.png) 


### Description

viragt.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create viragt.sys binPath=C:\windows\temp\viragt.sys type=kernel &amp;&amp; sc.exe start viragt.sys
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

| Filename | viragt.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/e79c91c27df3eaf82fb7bd1280172517">e79c91c27df3eaf82fb7bd1280172517</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/cb22723faa5ae2809476e5c5e9b9a597b26cab9b">cb22723faa5ae2809476e5c5e9b9a597b26cab9b</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/e05eeb2b8c18ad2cb2d1038c043d770a0d51b96b748bc34be3e7fc6f3790ce53">e05eeb2b8c18ad2cb2d1038c043d770a0d51b96b748bc34be3e7fc6f3790ce53</a> |
| Signature | TG Soft S.a.s. Di Tonello Gianfranco e C., VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Company | TG Soft S.a.s. || Description | VirIT Agent System || Product | VirIT Agent System || OriginalFilename | viragt.sys |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/viragt.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
