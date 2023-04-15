+++

description = ""
title = "GLCKIO2.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# GLCKIO2.sys ![:inline](/images/twitter_verified.png) 


### Description

GLCKIO2.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create GLCKIO2.sys binPath=C:\windows\temp\GLCKIO2.sys type=kernel &amp;&amp; sc.exe start GLCKIO2.sys
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

| Filename | GLCKIO2.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/e700a820f117f65e813b216fccbf78c9">e700a820f117f65e813b216fccbf78c9</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/2dfcb799b3c42ecb0472e27c19b24ac7532775ce">2dfcb799b3c42ecb0472e27c19b24ac7532775ce</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/3a5ec83fe670e5e23aef3afa0a7241053f5b6be5e6ca01766d6b5f9177183c25">3a5ec83fe670e5e23aef3afa0a7241053f5b6be5e6ca01766d6b5f9177183c25</a> |
| Publisher | ASUSTeK Computer Inc. || Signature | ASUSTeK Computer Inc., DigiCert SHA2 High Assurance Code Signing CA, DigiCert   || Filename | GLCKIO2.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/d253c19194a18030296ae62a10821640">d253c19194a18030296ae62a10821640</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/cc51be79ae56bc97211f6b73cc905c3492da8f9d">cc51be79ae56bc97211f6b73cc905c3492da8f9d</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/61a1bdddd3c512e681818debb5bee94db701768fc25e674fcad46592a3259bd0">61a1bdddd3c512e681818debb5bee94db701768fc25e674fcad46592a3259bd0</a> |
| Publisher | ASUSTeK Computer Inc. || Signature | ASUSTeK Computer Inc., DigiCert SHA2 High Assurance Code Signing CA, DigiCert   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/glckio2.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
