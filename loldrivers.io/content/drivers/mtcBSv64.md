+++

description = "https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"
title = "mtcBSv64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# mtcBSv64.sys ![:inline](/images/twitter_verified.png) 



### Description


mtcBSv64.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create mtcBSv64.sys binPath=C:\windows\temp\mtcBSv64.sys type=kernel
sc.exe start mtcBSv64.sys
```

### Resources
<br>


<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/c9cf1d627078f63a36bbde364cd0d5f2be1714124d186c06db5bcdf549a109f8">c9cf1d627078f63a36bbde364cd0d5f2be1714124d186c06db5bcdf549a109f8</a></li>



- binary: 
- Verified: 
- Date: 
- Publisher: 
- Company: 
- Description: 
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/mtcbsv64.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
