+++

description = ""
title = "msrhook.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# msrhook.sys ![:inline](/images/twitter_verified.png) 


### Description

msrhook.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create msrhook.sys binPath=C:\windows\temp\msrhook.sys type=kernel &amp;&amp; sc.exe start msrhook.sys
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

| Filename | msrhook.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/c49a1956a6a25ffc25ad97d6762b0989">c49a1956a6a25ffc25ad97d6762b0989</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/89909fa481ff67d7449ee90d24c167b17b0612f1">89909fa481ff67d7449ee90d24c167b17b0612f1</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/6de84caa2ca18673e01b91af58220c60aecd5cccf269725ec3c7f226b2167492">6de84caa2ca18673e01b91af58220c60aecd5cccf269725ec3c7f226b2167492</a> |
| Signature | ID TECH, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/msrhook.yaml)

*last_updated:* 2023-04-14








{{< /column >}}
{{< /block >}}
