+++

description = ""
title = "inpoutx64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# inpoutx64.sys ![:inline](/images/twitter_verified.png) 


### Description

inpoutx64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create inpoutx64.sys binPath=C:\windows\temp\inpoutx64.sys type=kernel
sc.exe start inpoutx64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<li><a href="https://github.com/namazso/physmem_drivers">https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | inpoutx64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/4d487f77be4471900d6ccbc47242cc25">4d487f77be4471900d6ccbc47242cc25</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/cc0e0440adc058615e31e8a52372abadf658e6b1">cc0e0440adc058615e31e8a52372abadf658e6b1</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/2d83ccb1ad9839c9f5b3f10b1f856177df1594c66cbbc7661677d4b462ebf44d">2d83ccb1ad9839c9f5b3f10b1f856177df1594c66cbbc7661677d4b462ebf44d</a> |
| Signature | RISINTECH INC., VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Filename | inpoutx64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/5ca1922ed5ee2b533b5f3dd9be20fd9a">5ca1922ed5ee2b533b5f3dd9be20fd9a</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/5520ac25d81550a255dc16a0bb89d4b275f6f809">5520ac25d81550a255dc16a0bb89d4b275f6f809</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/f581decc2888ef27ee1ea85ea23bbb5fb2fe6a554266ff5a1476acd1d29d53af">f581decc2888ef27ee1ea85ea23bbb5fb2fe6a554266ff5a1476acd1d29d53af</a> |
| Signature | RISINTECH INC., VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Filename | inpoutx64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/9321a61a25c7961d9f36852ecaa86f55">9321a61a25c7961d9f36852ecaa86f55</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/6afc6b04cf73dd461e4a4956365f25c1f1162387">6afc6b04cf73dd461e4a4956365f25c1f1162387</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/f8965fdce668692c3785afa3559159f9a18287bc0d53abb21902895a8ecf221b">f8965fdce668692c3785afa3559159f9a18287bc0d53abb21902895a8ecf221b</a> |
| Signature | Red Fox UK Limited, VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/inpoutx64.sys.yml)

*last_updated:* 2023-04-04








{{< /column >}}
{{< /block >}}
