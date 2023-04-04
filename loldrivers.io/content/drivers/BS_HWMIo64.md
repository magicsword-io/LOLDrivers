+++

description = "https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"
title = "BS_HWMIo64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# BS_HWMIo64.sys ![:inline](/images/twitter_verified.png) 


### Description

BS_HWMIo64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create BS_HWMIo64.sys binPath=C:\windows\temp\BS_HWMIo64.sys type=kernel
sc.exe start BS_HWMIo64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Filename | BS_HWMIo64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/338a98e1c27bc76f09331fcd7ae413a5">338a98e1c27bc76f09331fcd7ae413a5</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/9c24dd75e4074041dbe03bf21f050c77d748b8e9">9c24dd75e4074041dbe03bf21f050c77d748b8e9</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/60c6f4f34c7319cb3f9ca682e59d92711a05a2688badbae4891b1303cd384813">60c6f4f34c7319cb3f9ca682e59d92711a05a2688badbae4891b1303cd384813</a> |
| Signature | BIOSTAR MICROTECH INT&#39;L CORP, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bs_hwmio64.sys.yml)

*last_updated:* 2023-04-04








{{< /column >}}
{{< /block >}}
