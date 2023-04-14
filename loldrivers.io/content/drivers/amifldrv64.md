+++

description = ""
title = "amifldrv64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# amifldrv64.sys ![:inline](/images/twitter_verified.png) 


### Description

amifldrv64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create amifldrv64.sys binPath=C:\windows\temp\amifldrv64.sys type=kernel &amp;&amp; sc.exe start amifldrv64.sys
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

| Filename | amifldrv64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/6ab7b8ef0c44e7d2d5909fdb58d37fa5">6ab7b8ef0c44e7d2d5909fdb58d37fa5</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/bb962c9a8dda93e94fef504c4159de881e4706fe">bb962c9a8dda93e94fef504c4159de881e4706fe</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/42579a759f3f95f20a2c51d5ac2047a2662a2675b3fb9f46c1ed7f23393a0f00">42579a759f3f95f20a2c51d5ac2047a2662a2675b3fb9f46c1ed7f23393a0f00</a> |
| Publisher | &#34;American Megatrends, Inc.&#34; || Signature | American Megatrends, Inc., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/amifldrv64.yaml)

*last_updated:* 2023-04-14








{{< /column >}}
{{< /block >}}
