+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "zamguard64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# zamguard64.sys ![:inline](/images/twitter_verified.png) 


### Description

zamguard64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create zamguard64.sys binPath=C:\windows\temp\zamguard64.sys type=kernel
sc.exe start zamguard64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Filename | zamguard64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/"></a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/543991ca8d1c65113dff039b85ae3f9a87f503daec30f46929fd454bc57e5a91">543991ca8d1c65113dff039b85ae3f9a87f503daec30f46929fd454bc57e5a91</a> |
| Publisher |  |
| Signature |  |
| Date |  |
| Company |  |
| Description |  |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/zamguard64.sys.yml)

*last_updated:* 2023-03-21








{{< /column >}}
{{< /block >}}
