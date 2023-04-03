+++

description = "https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"
title = "phymem64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# phymem64.sys ![:inline](/images/twitter_verified.png) 


### Description

phymem64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create phymem64.sys binPath=C:\windows\temp\phymem64.sys type=kernel
sc.exe start phymem64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Filename | phymem64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/2c54859a67306e20bfdc8887b537de72">2c54859a67306e20bfdc8887b537de72</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/d7f7594ff084201c0d9fa2f4ef1626635b67bce5">d7f7594ff084201c0d9fa2f4ef1626635b67bce5</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/1963d5a0e512b72353953aadbe694f73a9a576f0241a988378fa40bf574eda52">1963d5a0e512b72353953aadbe694f73a9a576f0241a988378fa40bf574eda52</a> |
| Publisher |  |
| Signature | Super Micro Computer, Inc., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Date |  |
| Company |  |
| Description |  |
| Product |  |
| ProductVersion |  |
| FileVersion |  |
| MachineType |  |
| OriginalFilename |  |



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/phymem64.sys.yml)

*last_updated:* 2023-04-02








{{< /column >}}
{{< /block >}}
