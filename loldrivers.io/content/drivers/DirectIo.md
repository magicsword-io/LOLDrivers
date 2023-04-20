+++

description = ""
title = "DirectIo.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# DirectIo.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

DirectIo.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/a785b3bc4309d2eb111911c1b55e793f.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create DirectIo.sys binPath=C:\windows\temp\DirectIo.sys type=kernel &amp;&amp; sc.exe start DirectIo.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules"> https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<li><a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules">https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | DirectIo.sys |
| MD5                | [a785b3bc4309d2eb111911c1b55e793f](https://www.virustotal.com/gui/file/a785b3bc4309d2eb111911c1b55e793f) |
| SHA1               | [19f3343bfad0ef3595f41d60272d21746c92ffca](https://www.virustotal.com/gui/file/19f3343bfad0ef3595f41d60272d21746c92ffca) |
| SHA256             | [4422851a0a102f654e95d3b79c357ae3af1b096d7d1576663c027cfbc04abaf9](https://www.virustotal.com/gui/file/4422851a0a102f654e95d3b79c357ae3af1b096d7d1576663c027cfbc04abaf9) |
| Authentihash MD5   | [c6fbe703bcefd3a5a191dce9cd2bf71d](https://www.virustotal.com/gui/search/authentihash%253Ac6fbe703bcefd3a5a191dce9cd2bf71d) |
| Authentihash SHA1  | [7d24a5e3a9bb0eba2a4cf19f516384c7a0c95eb7](https://www.virustotal.com/gui/search/authentihash%253A7d24a5e3a9bb0eba2a4cf19f516384c7a0c95eb7) |
| Authentihash SHA256| [129fa1795cffca9973f59df59f880a9f2bdb3aa9873363f8e2f598ccc6e32542](https://www.virustotal.com/gui/search/authentihash%253A129fa1795cffca9973f59df59f880a9f2bdb3aa9873363f8e2f598ccc6e32542) |
| Signature         | PassMark Software Pty Ltd, VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwMapViewOfSection
* ObReferenceObjectByHandle
* ZwOpenSection
* ZwUnmapViewOfSection
* ZwWriteFile
* PsGetProcessId
* NtBuildNumber
* RtlFillMemoryUlong
* ZwCreateFile
* memset
* memcpy
* MmGetPhysicalMemoryRanges
* IoWriteErrorLogEntry
* memmove
* IoAllocateErrorLogEntry
* IofCompleteRequest
* IoDeleteDevice
* RtlAppendUnicodeStringToString
* ObfDereferenceObject
* RtlAppendUnicodeToString
* IoDeleteSymbolicLink
* RtlQueryRegistryValues
* ZwOpenKey
* RtlWriteRegistryValue
* KeWaitForSingleObject
* IofCallDriver
* IoBuildDeviceIoControlRequest
* KeInitializeEvent
* IoCreateSymbolicLink
* ObReferenceObjectByPointer
* IoGetDeviceObjectPointer
* IoCreateDevice
* KeQueryActiveProcessors
* KeRevertToUserAffinityThread
* KeSetSystemAffinityThread
* KeTickCount
* KeBugCheckEx
* ZwClose
* DbgPrint
* RtlInitUnicodeString
* ExAllocatePoolWithTag
* ZwQueryValueKey
* ExFreePoolWithTag
* RtlIntegerToUnicodeString
* RtlAssert
* READ_PORT_USHORT
* READ_PORT_UCHAR
* WRITE_PORT_ULONG
* WRITE_PORT_USHORT
* WRITE_PORT_UCHAR
* KeGetCurrentIrql
* READ_PORT_ULONG

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/directio.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
