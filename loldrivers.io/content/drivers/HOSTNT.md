+++

description = "https://github.com/namazso/physmem_drivers"
title = "HOSTNT.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# HOSTNT.sys

#### Description

HOSTNT.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

#### Command

```
sc.exe create HOSTNT binPath= C:\windows\temp\HOSTNT.sys type= kernel
sc.exe start HOSTNT.sys
```

#### Resources
<br>


<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/07B6D69BAFCFD767F1B63A490A8843C3BB1F8E1BBEA56176109B5743C8F7D357">07B6D69BAFCFD767F1B63A490A8843C3BB1F8E1BBEA56176109B5743C8F7D357</a></li>



- binary: 
- Verified: 
- Date: 
- Publisher: &#34;SafeNet, Inc.&#34;
- Company: 
- Description: Hostnt 64-bit driver
- Product: 
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: 

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/hostnt.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
