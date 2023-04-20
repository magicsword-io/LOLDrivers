+++

description = ""
title = "phymem64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# phymem64.sys ![:inline](/images/twitter_verified.png) 


### Description

phymem64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/2c54859a67306e20bfdc8887b537de72.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create phymem64.sys binPath=C:\windows\temp\phymem64.sys type=kernel &amp;&amp; sc.exe start phymem64.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md"> https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<li><a href="https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md">https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | phymem64.sys |
| MD5                | [2c54859a67306e20bfdc8887b537de72](https://www.virustotal.com/gui/file/2c54859a67306e20bfdc8887b537de72) |
| SHA1               | [d7f7594ff084201c0d9fa2f4ef1626635b67bce5](https://www.virustotal.com/gui/file/d7f7594ff084201c0d9fa2f4ef1626635b67bce5) |
| SHA256             | [1963d5a0e512b72353953aadbe694f73a9a576f0241a988378fa40bf574eda52](https://www.virustotal.com/gui/file/1963d5a0e512b72353953aadbe694f73a9a576f0241a988378fa40bf574eda52) |
| Authentihash MD5   | [aa43aa9f88e2fed984077a8852d85a4f](https://www.virustotal.com/gui/search/authentihash%253Aaa43aa9f88e2fed984077a8852d85a4f) |
| Authentihash SHA1  | [52a8cd44646973b59c244b5f7b04b33a412634a2](https://www.virustotal.com/gui/search/authentihash%253A52a8cd44646973b59c244b5f7b04b33a412634a2) |
| Authentihash SHA256| [6ed3379d7ac1ad8bcfd13cd2502420569088ee7f1e04522ada48481d9a545a08](https://www.virustotal.com/gui/search/authentihash%253A6ed3379d7ac1ad8bcfd13cd2502420569088ee7f1e04522ada48481d9a545a08) |
| Signature         | Super Micro Computer, Inc., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | Super Micro Computer, Inc. |
| Description       | phymem Application |
| Product           | phymem |
| OriginalFilename  | phymem.sys |


#### Imports
{{< details "Expand" >}}
* NTOSKRNL.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* KeWaitForSingleObject
* IofCallDriver
* IoBuildSynchronousFsdRequest
* KeInitializeEvent
* IoDeleteDevice
* IoCreateSymbolicLink
* IoCreateDevice
* RtlInitUnicodeString
* ExAllocatePool
* IofCompleteRequest
* ExFreePoolWithTag
* IoFreeMdl
* MmUnmapLockedPages
* MmUnmapIoSpace
* ExReleaseFastMutex
* ExAcquireFastMutex
* MmMapLockedPages
* MmBuildMdlForNonPagedPool
* IoAllocateMdl
* MmMapIoSpace
* IoDeleteSymbolicLink
* MmMapLockedPagesSpecifyCache
* IoGetDeviceObjectPointer

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/phymem64.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
