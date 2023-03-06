+++

description = "https://eclypsium.com/2019/11/12/mother-of-all-drivers/"
title = "VideoNovaServerControllerService.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}




# VideoNovaServerControllerService.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}




### Description


CapCom.sys is a vulnerable driver that has been abused over the years.


- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

```
sc create CapCom binpath = c:\temp\capcom.sys type=kernel start=auto displayname=&#34;CapCom vulnerable Driver&#34;
```

### Resources
<br>


<li><a href=" https://eclypsium.com/2019/11/12/mother-of-all-drivers/"> https://eclypsium.com/2019/11/12/mother-of-all-drivers/</a></li>


<br>


### Binary Metadata
<br>



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/videonovaservercontrollerservice.sys.yml)

*last_updated:* 2023-03-06


{{< /column >}}
{{< /block >}}
