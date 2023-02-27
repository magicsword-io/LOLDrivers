+++
description = "https://eclypsium.com/2019/11/12/mother-of-all-drivers/"
title = "VideoNovaServerControllerService.sys"
weight = 10
+++

# VideoNovaServerControllerService.sys

#### Description

CapCom.sys is a vulnerable driver that has been abused over the years.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc create CapCom binpath = c:\temp\capcom.sys type=kernel start=auto displayname="CapCom vulnerable Driver"
```

#### Resources


<li><a href=" https://eclypsium.com/2019/11/12/mother-of-all-drivers/"> https://eclypsium.com/2019/11/12/mother-of-all-drivers/</a></li>





#### Binary Metadata

- Known Hashes: [](https://www.virustotal.com/gui/file/) 
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