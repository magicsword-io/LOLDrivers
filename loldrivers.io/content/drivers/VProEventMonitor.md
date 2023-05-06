+++

description = ""
title = "VProEventMonitor.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# VProEventMonitor.sys ![:inline](/images/twitter_verified.png) 


### Description

VProEventMonitor.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/cd9f0fcecf1664facb3671c0130dc8bb.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create VProEventMonitor.sys binPath=C:\windows\temp\VProEventMonitor.sys     type=kernel &amp;&amp; sc.exe start VProEventMonitor.sys
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
| Filename           | VProEventMonitor.sys |
| MD5                | [cd9f0fcecf1664facb3671c0130dc8bb](https://www.virustotal.com/gui/file/cd9f0fcecf1664facb3671c0130dc8bb) |
| SHA1               | [0c26ab1299adcd9a385b541ef1653728270aa23e](https://www.virustotal.com/gui/file/0c26ab1299adcd9a385b541ef1653728270aa23e) |
| SHA256             | [7877c1b0e7429453b750218ca491c2825dae684ad9616642eff7b41715c70aca](https://www.virustotal.com/gui/file/7877c1b0e7429453b750218ca491c2825dae684ad9616642eff7b41715c70aca) |
| Authentihash MD5   | [ed01170d94a5e21d04b6d7212b53c994](https://www.virustotal.com/gui/search/authentihash%253Aed01170d94a5e21d04b6d7212b53c994) |
| Authentihash SHA1  | [cbaa70aac878a389c8213a5bc0df830b1d5b4e04](https://www.virustotal.com/gui/search/authentihash%253Acbaa70aac878a389c8213a5bc0df830b1d5b4e04) |
| Authentihash SHA256| [9994990c02c37472625cc7b2255044feef9b73c08ca3a70c06861b7d26b27a25](https://www.virustotal.com/gui/search/authentihash%253A9994990c02c37472625cc7b2255044feef9b73c08ca3a70c06861b7d26b27a25) |
| Signature         | Symantec Corporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | Symantec Corporation |
| Description       | VProEventMonitor.Sys - Event Monitoring driver |
| Product           | Symantec Event Monitors Driver Development Edition |
| OriginalFilename  | VProEventMonitor.Sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* PsGetVersion
* strncmp
* ZwOpenProcess
* ExAcquireFastMutex
* IoCreateSymbolicLink
* PsLookupProcessByProcessId
* RtlCopyUnicodeString
* ObfDereferenceObject
* IoCreateDevice
* RtlInitUnicodeString
* IoDeleteDevice
* KeSetEvent
* IoCreateNotificationEvent
* MmGetSystemRoutineAddress
* KeInitializeEvent
* PsSetCreateProcessNotifyRoutine
* ExAllocatePoolWithTag
* IoGetCurrentProcess
* KeClearEvent
* ZwClose
* IoDeleteSymbolicLink
* IofCompleteRequest
* ExFreePoolWithTag
* KeBugCheckEx
* DbgPrint
* ExReleaseFastMutex
* KeQueryPerformanceCounter

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/vproeventmonitor.yaml)

*last_updated:* 2023-05-06








{{< /column >}}
{{< /block >}}
