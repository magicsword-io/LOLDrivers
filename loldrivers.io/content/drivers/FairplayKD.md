+++

description = ""
title = "FairplayKD.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# FairplayKD.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

FairplayKD.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create FairplayKD.sys binPath=C:\windows\temp\FairplayKD.sys type=kernel &amp;&amp; sc.exe start FairplayKD.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.unknowncheats.me/forum/anti-cheat-bypass/334557-vulnerable-driver-megathread.html">https://www.unknowncheats.me/forum/anti-cheat-bypass/334557-vulnerable-driver-megathread.html</a></li>
<li><a href="https://www.unknowncheats.me/forum/anti-cheat-bypass/244386-mta-fairplaykd-driver-reversed-exploited-rpm.html">https://www.unknowncheats.me/forum/anti-cheat-bypass/244386-mta-fairplaykd-driver-reversed-exploited-rpm.html</a></li>
<li><a href=""></a></li>
<br>

### Known Vulnerable Samples

| Filename | FairplayKD.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/4e90cd77509738d30d3181a4d0880bfa">4e90cd77509738d30d3181a4d0880bfa</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/b4dcdbd97f38b24d729b986f84a9cdb3fc34d59f">b4dcdbd97f38b24d729b986f84a9cdb3fc34d59f</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/9f4ce6ab5e8d44f355426d9a6ab79833709f39b300733b5b251a0766e895e0e5">9f4ce6ab5e8d44f355426d9a6ab79833709f39b300733b5b251a0766e895e0e5</a> |
| Signature | Hans Roes, Thawte Code Signing CA - G2, thawte   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/fairplaykd.yaml)

*last_updated:* 2023-04-10








{{< /column >}}
{{< /block >}}
