+++
description = "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/driver_load/driver_load_vuln_drivers_names.yml"
title = "gmer.sys"
weight = 10
+++

# gmer.sys

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


* [https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/driver_load/driver_load_vuln_drivers_names.yml](https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/driver_load/driver_load_vuln_drivers_names.yml)



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

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/gmer.sys.yml)