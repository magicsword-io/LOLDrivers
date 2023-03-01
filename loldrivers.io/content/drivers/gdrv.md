+++

description = "https://github.com/namazso/physmem_drivers"
title = "gdrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# gdrv.sys

#### Description

gdrv.sys is vulnerable to multiple CVEs: CVE-2018-19320, CVE-2018-19322, CVE-2018-19323, CVE-2018-19321. Read/Write Physical memory, read/write to/from IO ports, exposes ring0 memcpy-like functionality,  read and write Machine Specific Registers (MSRs).

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**: MattNotMax | [@mattnotmax](https://twitter.com/@mattnotmax)

#### Command

```
sc.exe create gdrv binPath= C:\windows\temp\gdrv.sys type= kernel
sc.exe start gdrv.sys
```

#### Resources
<br>


<li><a href=" https://github.com/hoangprod/DanSpecial"> https://github.com/hoangprod/DanSpecial</a></li>

<li><a href="https://github.com/namazso/physmem_drivers">https://github.com/namazso/physmem_drivers</a></li>

<li><a href="https://www.secureauth.com/labs/advisories/gigabyte-drivers-elevation-privilege-vulnerabilities">https://www.secureauth.com/labs/advisories/gigabyte-drivers-elevation-privilege-vulnerabilities</a></li>

<li><a href="https://medium.com/@fsx30/weaponizing-vulnerable-driver-for-privilege-escalation-gigabyte-edition-e73ee523598b">https://medium.com/@fsx30/weaponizing-vulnerable-driver-for-privilege-escalation-gigabyte-edition-e73ee523598b</a></li>


<br>


#### Binary Metadata
<br>



<li><a href="https://www.virustotal.com/gui/file/31f4cfb4c71da44120752721103a16512444c13c2ac2d857a7e6f13cb679b427">31f4cfb4c71da44120752721103a16512444c13c2ac2d857a7e6f13cb679b427</a></li>

<li><a href="https://www.virustotal.com/gui/file/ff6729518a380bf57f1bc6f1ec0aa7f3012e1618b8d9b0f31a61d299ee2b4339">ff6729518a380bf57f1bc6f1ec0aa7f3012e1618b8d9b0f31a61d299ee2b4339</a></li>



- binary: 
- Verified: 
- Date: 2013-07-03 17:32:00 UTC, 2017-11-30 18:40:00 UTC
- Publisher: 
- Company: 
- Description: GIGABYTE Tools, GIGA-BYTE NonPNP Driver
- Product: Windows (R) Server 2003 DDK driver, gdrv64
- ProductVersion: 
- FileVersion: 
- MachineType: 
- OriginalFilename: gdrv.sys

[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/gdrv.sys.yml)

*last_updated:* 2023-02-28


{{< /column >}}
{{< /block >}}
