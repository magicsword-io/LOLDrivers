+++
description = "https://github.com/namazso/physmem_drivers"
title = "ADV64DRV.sys"
weight = 10
+++

# ADV64DRV.sys

#### Description

CapCom.sys is a vulnerable driver that has been abused over the years.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc create ADV64DRV.sys binpath = c:\temp\ADV64DRV.sys.sys type=kernel start=auto displayname="ADV64DRV.sys vulnerable Driver"
```

#### Resources


<li><a href="{&#39; https://github.com/namazso/physmem_drivers&#39;}">{&#39; https://github.com/namazso/physmem_drivers&#39;}</a></li>





#### Binary Metadata

- Known Hashes: [04A85E359525D662338CAE86C1E59B1D7AA9BD12B920E8067503723DC1E03162](https://www.virustotal.com/gui/file/04A85E359525D662338CAE86C1E59B1D7AA9BD12B920E8067503723DC1E03162) 
- binary: 
- Verified: TRUE
- Date: 44896
- Publisher: Microsoft Corp
- Company: Microsoft Corp
- Description: Software Driver
- Product: NA
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/adv64drv.sys.yml)