+++

description = ""
title = "AsrRapidStartDrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrRapidStartDrv.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrRapidStartDrv.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/31469f1313871690e8dc2e8ee4799b22.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create AsrRapidStartDrv.sys binPath=C:\windows\temp\AsrRapidStartDrv.sys     type=kernel &amp;&amp; sc.exe start AsrRapidStartDrv.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<li><a href="https://github.com/namazso/physmem_drivers">https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | AsrRapidStartDrv.sys |
| MD5                | [31469f1313871690e8dc2e8ee4799b22](https://www.virustotal.com/gui/file/31469f1313871690e8dc2e8ee4799b22) |
| SHA1               | [89cd760e8cb19d29ee08c430fb17a5fd4455c741](https://www.virustotal.com/gui/file/89cd760e8cb19d29ee08c430fb17a5fd4455c741) |
| SHA256             | [0aafa9f47acf69d46c9542985994ff5321f00842a28df2396d4a3076776a83cb](https://www.virustotal.com/gui/file/0aafa9f47acf69d46c9542985994ff5321f00842a28df2396d4a3076776a83cb) |
| Authentihash MD5   | [98a9518fefaf056f5804b631e735ff73](https://www.virustotal.com/gui/search/authentihash%253A98a9518fefaf056f5804b631e735ff73) |
| Authentihash SHA1  | [5ac05af283a3bda3b09ce8ad292ba5c689216b7a](https://www.virustotal.com/gui/search/authentihash%253A5ac05af283a3bda3b09ce8ad292ba5c689216b7a) |
| Authentihash SHA256| [913ab7134ea3460e76db753cf68f336ada8f0b9c397be88c75f9567a8694f4a5](https://www.virustotal.com/gui/search/authentihash%253A913ab7134ea3460e76db753cf68f336ada8f0b9c397be88c75f9567a8694f4a5) |
| Publisher         | ASROCK Incorporation |
| Signature         | ASROCK Incorporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | RW-Everything |
| Description       | RW-Everything Read &amp; Write Driver |
| Product           | RW-Everything Read &amp; Write Driver |
| OriginalFilename  | RwDrv.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoDeleteSymbolicLink
* ExFreePoolWithTag
* MmFreeContiguousMemorySpecifyCache
* RtlInitUnicodeString
* IoDeleteDevice
* RtlQueryRegistryValues
* MmUnmapIoSpace
* IoFreeMdl
* MmGetPhysicalAddress
* IoBuildAsynchronousFsdRequest
* MmMapIoSpace
* IofCompleteRequest
* IoFreeIrp
* RtlCompareMemory
* MmUnlockPages
* IoCreateSymbolicLink
* IoCreateDevice
* MmAllocateContiguousMemorySpecifyCache
* IofCallDriver
* KeBugCheckEx
* ExAllocatePoolWithTag
* KeStallExecutionProcessor

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrrapidstartdrv.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
