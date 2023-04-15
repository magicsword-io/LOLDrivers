+++

description = ""
title = "blacklotus_driver.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# blacklotus_driver.sys ![:inline](/images/twitter_verified.png) 


### Description

The first in-the-wild UEFI bootkit bypassing UEFI Secure Boot on fully updated UEFI systems is now a reality. Once the persistence is configured, the BlackLotus bootkit is executed on every system start. The bootkits goal is to deploy a kernel driver and a final user-mode component.

- **Created**: 2023-04-05
- **Author**: Michael Haag
- **Acknowledgement**: Martin Smolár, ESET | [](https://twitter.com/)

### Commands

```
sc.exe create blacklotus_driver.sys binPath=C:\windows\temp\blacklotus_driver.sys type=kernel &amp;&amp; sc.exe start blacklotus_driver.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/">https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/</a></li>
<br>

### Known Vulnerable Samples

| Filename | 0x3440_blacklotus_v2_driver.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/4ad8fd9e83d7200bd7f8d0d4a9abfb11">4ad8fd9e83d7200bd7f8d0d4a9abfb11</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/17fa047c1f979b180644906fe9265f21af5b0509">17fa047c1f979b180644906fe9265f21af5b0509</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/749b0e8c8c8b7dda8c2063c708047cfe95afa0a4d86886b31a12f3018396e67c">749b0e8c8c8b7dda8c2063c708047cfe95afa0a4d86886b31a12f3018396e67c</a> |
| Signature | -   || Filename | 0x3040_blacklotus_beta_driver.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/a42249a046182aaaf3a7a7db98bfa69d">a42249a046182aaaf3a7a7db98bfa69d</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/1f3799fed3cf43254fe30dcdfdb8dc02d82e662b">1f3799fed3cf43254fe30dcdfdb8dc02d82e662b</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/f8236fc01d4efaa48f032e301be2ebba4036b2cd945982a29046eca03944d2ae">f8236fc01d4efaa48f032e301be2ebba4036b2cd945982a29046eca03944d2ae</a> |
| Signature | -   || Filename | 0x3040_blacklotus_beta_driver.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/a42249a046182aaaf3a7a7db98bfa69d">a42249a046182aaaf3a7a7db98bfa69d</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/1f3799fed3cf43254fe30dcdfdb8dc02d82e662b">1f3799fed3cf43254fe30dcdfdb8dc02d82e662b</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/f8236fc01d4efaa48f032e301be2ebba4036b2cd945982a29046eca03944d2ae">f8236fc01d4efaa48f032e301be2ebba4036b2cd945982a29046eca03944d2ae</a> |
| Signature | -   || Filename | blacklotus_beta_driver.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/4B882748FAF2C6C360884C6812DD5BCBCE75EBFF">4B882748FAF2C6C360884C6812DD5BCBCE75EBFF</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| Signature | -   || Filename | blacklotus_beta_driver_2.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/91F832F46E4C38ECC9335460D46F6F71352CFFED">91F832F46E4C38ECC9335460D46F6F71352CFFED</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| Signature | -   || Filename | blacklotus_beta_driver_3.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/994DC79255AEB662A672A1814280DE73D405617A">994DC79255AEB662A672A1814280DE73D405617A</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| Signature | -   || Filename | blacklotus_beta_driver_4.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/FFF4F28287677CAABC60C8AB36786C370226588D">FFF4F28287677CAABC60C8AB36786C370226588D</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/-">-</a> |
| Signature | -   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/blacklotus_driver.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
