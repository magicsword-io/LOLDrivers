+++

description = ""
title = "rtkiow8x64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# rtkiow8x64.sys ![:inline](/images/twitter_verified.png) 


### Description

rtkiow8x64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/b8b6686324f7aa77f570bc019ec214e6.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create rtkiow8x64.sys binPath=C:\windows\temp\rtkiow8x64.sys type=kernel &amp;&amp; sc.exe start rtkiow8x64.sys
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

| Filename | rtkiow8x64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/b8b6686324f7aa77f570bc019ec214e6">b8b6686324f7aa77f570bc019ec214e6</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/6a3d3b9ab3d201cd6b0316a7f9c3fb4d34d0f403">6a3d3b9ab3d201cd6b0316a7f9c3fb4d34d0f403</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/082c39fe2e3217004206535e271ebd45c11eb072efde4cc9885b25ba5c39f91d">082c39fe2e3217004206535e271ebd45c11eb072efde4cc9885b25ba5c39f91d</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ad2914b13c253d24728fade34df3d91df">d2914b13c253d24728fade34df3d91df</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Afa7fbb04748088557085ef3060b5fdb65a7b6b10">fa7fbb04748088557085ef3060b5fdb65a7b6b10</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Aed68f30f8246730c2b57495ed1db1480350d879b01d070999d35f38630865f5c">ed68f30f8246730c2b57495ed1db1480350d879b01d070999d35f38630865f5c</a> || Signature | Realtek Semiconductor Corp., DigiCert EV Code Signing CA, DigiCert   || Company | Realtek                                             || Description | Realtek IO Driver || Product | Realtek IO Driver                       || OriginalFilename | rtkiow8x64.sys  |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* KfRaiseIrql
* MmMapIoSpace
* MmUnmapIoSpace
* RtlInitUnicodeString
* MmGetSystemRoutineAddress
* RtlCompareMemory
* KeSetSystemAffinityThreadEx
* KeQueryActiveProcessors
* ExAllocatePoolWithTag
* ExFreePoolWithTag
* ExCreateCallback
* ExRegisterCallback
* ExUnregisterCallback
* MmBuildMdlForNonPagedPool
* MmMapLockedPagesSpecifyCache
* KeLowerIrql
* IoAllocateMdl
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* IoFreeMdl
* IoRegisterShutdownNotification
* IoUnregisterShutdownNotification
* IoWMIRegistrationControl
* ObfDereferenceObject
* ZwClose
* ZwOpenKey
* ZwQueryValueKey
* __C_specific_handler
* MmUnmapLockedPages
* _vsnprintf
* KeStallExecutionProcessor
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/rtkiow8x64.yaml)

*last_updated:* 2023-04-16








{{< /column >}}
{{< /block >}}
