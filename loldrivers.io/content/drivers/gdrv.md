+++

description = ""
title = "gdrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# gdrv.sys ![:inline](/images/twitter_verified.png) 


### Description

gdrv.sys is vulnerable to multiple CVEs: CVE-2018-19320, CVE-2018-19322, CVE-2018-19323, CVE-2018-19321. Read/Write Physical memory, read/write to/from IO ports, exposes ring0 memcpy-like functionality,  read and write Machine Specific Registers (MSRs).

- **Created**: 2023-01-09
- **Author**: Michael Haag, rasta-mouse
- **Acknowledgement**: MattNotMax | [@mattnotmax](https://twitter.com/@mattnotmax)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/9ab9f3b75a2eb87fafb1b7361be9dfb3.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create gdrv.sys binPath=C:\windows\temp\gdrv.sys type=kernel &amp;&amp; sc.exe start gdrv.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges, tamper with PPL or system processes | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://github.com/hoangprod/DanSpecial">https://github.com/hoangprod/DanSpecial</a></li>
<li><a href="https://github.com/namazso/physmem_drivers">https://github.com/namazso/physmem_drivers</a></li>
<li><a href="https://www.secureauth.com/labs/advisories/gigabyte-drivers-elevation-privilege-vulnerabilities">https://www.secureauth.com/labs/advisories/gigabyte-drivers-elevation-privilege-vulnerabilities</a></li>
<li><a href="https://medium.com/@fsx30/weaponizing-vulnerable-driver-for-privilege-escalation-gigabyte-edition-e73ee523598b">https://medium.com/@fsx30/weaponizing-vulnerable-driver-for-privilege-escalation-gigabyte-edition-e73ee523598b</a></li>
<li><a href="https://github.com/namazso/physmem_drivers">https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | gdrv.sys |
| MD5                | [9ab9f3b75a2eb87fafb1b7361be9dfb3](https://www.virustotal.com/gui/file/9ab9f3b75a2eb87fafb1b7361be9dfb3) |
| SHA1               | [fe10018af723986db50701c8532df5ed98b17c39](https://www.virustotal.com/gui/file/fe10018af723986db50701c8532df5ed98b17c39) |
| SHA256             | [31f4cfb4c71da44120752721103a16512444c13c2ac2d857a7e6f13cb679b427](https://www.virustotal.com/gui/file/31f4cfb4c71da44120752721103a16512444c13c2ac2d857a7e6f13cb679b427) |
| Authentihash MD5   | [b18b1bff521337695d2d6a0768340252](https://www.virustotal.com/gui/search/authentihash%253Ab18b1bff521337695d2d6a0768340252) |
| Authentihash SHA1  | [0f5034fcf5b34be22a72d2ecc29e348e93b6f00f](https://www.virustotal.com/gui/search/authentihash%253A0f5034fcf5b34be22a72d2ecc29e348e93b6f00f) |
| Authentihash SHA256| [9c0e80958b907c8df345ec2f8d711acefb4951ee3e6e84892ecd429f5e1f3acb](https://www.virustotal.com/gui/search/authentihash%253A9c0e80958b907c8df345ec2f8d711acefb4951ee3e6e84892ecd429f5e1f3acb) |
| Signature         | Giga-Byte Technology, VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |
| Date                | 2013-07-03 17:32:00 UTC, 2017-11-30 18:40:00 UTC |
| Company           | Windows (R) Server 2003 DDK provider |
| Description       | GIGABYTE Tools |
| Product           | Windows (R) Server 2003 DDK driver |
| OriginalFilename  | gdrv.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoCreateDevice
* RtlInitUnicodeString
* DbgPrint
* IoDeleteSymbolicLink
* ExFreePoolWithTag
* MmUnmapIoSpace
* IoFreeMdl
* MmUnmapLockedPages
* MmMapIoSpace
* ZwClose
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* IoCreateSymbolicLink
* KeAcquireInStackQueuedSpinLock
* MmFreeContiguousMemory
* MmIsAddressValid
* MmAllocateContiguousMemory
* MmGetPhysicalAddress
* IofCompleteRequest
* ExAllocatePoolWithTag
* MmMapLockedPages
* MmBuildMdlForNonPagedPool
* IoAllocateMdl
* ZwUnmapViewOfSection
* KeReleaseInStackQueuedSpinLock
* IoDeleteDevice
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | gdrv.sys |
| MD5                | [1cff7b947f8c3dea1d34dc791fc78cdc](https://www.virustotal.com/gui/file/1cff7b947f8c3dea1d34dc791fc78cdc) |
| SHA1               | [8d59fd14a445c8f3f0f7991fa6cd717d466b3754](https://www.virustotal.com/gui/file/8d59fd14a445c8f3f0f7991fa6cd717d466b3754) |
| SHA256             | [ff6729518a380bf57f1bc6f1ec0aa7f3012e1618b8d9b0f31a61d299ee2b4339](https://www.virustotal.com/gui/file/ff6729518a380bf57f1bc6f1ec0aa7f3012e1618b8d9b0f31a61d299ee2b4339) |
| Authentihash MD5   | [bf45a5d10968424666abede02113a509](https://www.virustotal.com/gui/search/authentihash%253Abf45a5d10968424666abede02113a509) |
| Authentihash SHA1  | [5c26f130f6a5ad8bdd2eed29140542dae0885b17](https://www.virustotal.com/gui/search/authentihash%253A5c26f130f6a5ad8bdd2eed29140542dae0885b17) |
| Authentihash SHA256| [34da66774ba09c4a8fc59349401ca1fefaaf4e66a9c620c7782c072a16089ba3](https://www.virustotal.com/gui/search/authentihash%253A34da66774ba09c4a8fc59349401ca1fefaaf4e66a9c620c7782c072a16089ba3) |
| Signature         | GIGA-BYTE TECHNOLOGY CO., LTD., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |
| Date                | 2013-07-03 17:32:00 UTC, 2017-11-30 18:40:00 UTC |
| Company           | GIGA-BYTE TECHNOLOGY CO., LTD. |
| Description       | GIGA-BYTE NonPNP Driver |
| Product           | gdrv64 |
| OriginalFilename  | gdrv.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* KeAcquireInStackQueuedSpinLock
* KeReleaseInStackQueuedSpinLock
* ExAllocatePool
* ExFreePoolWithTag
* MmBuildMdlForNonPagedPool
* MmMapLockedPages
* MmUnmapLockedPages
* MmMapIoSpace
* MmUnmapIoSpace
* MmAllocateContiguousMemory
* MmFreeContiguousMemory
* IoAllocateMdl
* IofCompleteRequest
* DbgPrint
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* IoFreeMdl
* ObReferenceObjectByHandle
* ZwClose
* ZwOpenSection
* ZwMapViewOfSection
* ZwUnmapViewOfSection
* MmGetPhysicalAddress
* MmIsAddressValid
* KeBugCheckEx
* IoCreateDevice
* RtlInitUnicodeString
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/gdrv.yaml)

*last_updated:* 2023-04-22








{{< /column >}}
{{< /block >}}
