+++

description = ""
title = "rtkiow10x64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# rtkiow10x64.sys ![:inline](/images/twitter_verified.png) 


### Description

rtkiow10x64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)


{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0ae30291c6cbfa7be39320badd6e8de0.bin" "Download" >}}

{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create rtkiow10x64.sys binPath=C:\windows\temp\rtkiow10x64.sys     type=kernel type=kernel &amp;&amp; sc.exe start rtkiow10x64.sys
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

| Filename | rtkiow10x64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/b5ada7fd226d20ec6634fc24768f9e22">b5ada7fd226d20ec6634fc24768f9e22</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/947db58d6f36a8df9fa2a1057f3a7f653ccbc42e">947db58d6f36a8df9fa2a1057f3a7f653ccbc42e</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/32e1a8513eee746d17eb5402fb9d8ff9507fb6e1238e7ff06f7a5c50ff3df993">32e1a8513eee746d17eb5402fb9d8ff9507fb6e1238e7ff06f7a5c50ff3df993</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%4d01000bdb93d60aa1ff5700b4b0a9a2">4d01000bdb93d60aa1ff5700b4b0a9a2</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%5e85fc1f7ef1c3c2745c842739c0ab596f87f9f9">5e85fc1f7ef1c3c2745c842739c0ab596f87f9f9</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%bc65d8ade2e72475a585307311e3058b3dbc4a7d2be6740c2c53a5902e698e7f">bc65d8ade2e72475a585307311e3058b3dbc4a7d2be6740c2c53a5902e698e7f</a> || Signature | Realtek Semiconductor Corp., DigiCert EV Code Signing CA, DigiCert   || Company | Realtek                                             || Description | Realtek IO Driver || Product | Realtek IO Driver                       || OriginalFilename | rtkiow10x64.sys  |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* KfRaiseIrql
* MmUnmapIoSpace
* MmMapIoSpaceEx
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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/rtkiow10x64.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
