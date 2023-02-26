+++
description = "https://eclypsium.com/2019/11/12/mother-of-all-drivers/"
title = "OpenHardwareMonitorLib.sys"
weight = 10
+++

# OpenHardwareMonitorLib.sys

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


* [https://eclypsium.com/2019/11/12/mother-of-all-drivers/](https://eclypsium.com/2019/11/12/mother-of-all-drivers/)



#### Binary Metadata

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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/openhardwaremonitorlib.sys.yml)