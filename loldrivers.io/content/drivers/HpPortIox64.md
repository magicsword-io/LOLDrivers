+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "HpPortIox64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# HpPortIox64.sys ![:inline](/images/twitter_verified.png) 



### Description


HpPortIox64.sys is a vulnerable driver and more information will be added as found.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc.exe create HpPortIox64.sys binPath=C:\windows\temp\HpPortIox64.sys type=kernel
sc.exe start HpPortIox64.sys
```

### Resources
<br>


<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>


<br>


### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/c5050a2017490fff7aa53c73755982b339ddb0fd7cef2cde32c81bc9834331c5">c5050a2017490fff7aa53c73755982b339ddb0fd7cef2cde32c81bc9834331c5</a></li>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/hpportiox64.sys.yml)

*last_updated:* 2023-03-07


{{< /column >}}
{{< /block >}}
