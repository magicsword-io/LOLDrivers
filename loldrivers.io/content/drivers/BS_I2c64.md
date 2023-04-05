+++

description = ""
title = "BS_I2c64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# BS_I2c64.sys ![:inline](/images/twitter_verified.png) 


### Description

BS_I2c64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create BS_I2c64.sys binPath=C:\windows\temp\BS_I2c64.sys type=kernel
sc.exe start BS_I2c64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<li><a href="https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md">https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Filename | BS_I2c64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/83601bbe5563d92c1fdb4e960d84dc77">83601bbe5563d92c1fdb4e960d84dc77</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/dc55217b6043d819eadebd423ff07704ee103231">dc55217b6043d819eadebd423ff07704ee103231</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/55fee54c0d0d873724864dc0b2a10b38b7f40300ee9cae4d9baaf8a202c4049a">55fee54c0d0d873724864dc0b2a10b38b7f40300ee9cae4d9baaf8a202c4049a</a> |
| Signature | BIOSTAR MICROTECH INT&#39;L CORP, VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bs_i2c64.sys.yml)

*last_updated:* 2023-04-04








{{< /column >}}
{{< /block >}}
