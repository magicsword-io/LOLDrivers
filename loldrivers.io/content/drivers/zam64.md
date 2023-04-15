+++

description = ""
title = "zam64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# zam64.sys ![:inline](/images/twitter_verified.png) 


### Description

zam64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create zam64.sys binPath=C:\windows\temp\zam64.sys type=kernel &amp;&amp; sc.exe start zam64.sys
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

| Filename | zam64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/21e13f2cb269defeae5e1d09887d47bb">21e13f2cb269defeae5e1d09887d47bb</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/16d7ecf09fc98798a6170e4cef2745e0bee3f5c7">16d7ecf09fc98798a6170e4cef2745e0bee3f5c7</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/543991ca8d1c65113dff039b85ae3f9a87f503daec30f46929fd454bc57e5a91">543991ca8d1c65113dff039b85ae3f9a87f503daec30f46929fd454bc57e5a91</a> |
| Signature | Zemana Ltd., DigiCert High Assurance Code Signing CA-1, DigiCert   || Company | Zemana Ltd. || Description | ZAM || Product | ZAM |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/zam64.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
