+++

description = ""
title = "Dh_Kernel.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# Dh_Kernel.sys ![:inline](/images/twitter_verified.png) 


### Description

Dh_Kernel.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/98763a3dee3cf03de334f00f95fc071a.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create Dh_Kernel.sys binPath=C:\windows\temp\Dh_Kernel.sys type=kernel &amp;&amp; sc.exe start Dh_Kernel.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<li><a href="https://github.com/namazso/physmem_drivers">https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | Dh_Kernel.sys |
| MD5                | [98763a3dee3cf03de334f00f95fc071a](https://www.virustotal.com/gui/file/98763a3dee3cf03de334f00f95fc071a) |
| SHA1               | [745bad097052134548fe159f158c04be5616afc2](https://www.virustotal.com/gui/file/745bad097052134548fe159f158c04be5616afc2) |
| SHA256             | [bb50818a07b0eb1bd317467139b7eb4bad6cd89053fecdabfeae111689825955](https://www.virustotal.com/gui/file/bb50818a07b0eb1bd317467139b7eb4bad6cd89053fecdabfeae111689825955) |
| Authentihash MD5   | [2d03bf608f236ee1f4654e06857a3062](https://www.virustotal.com/gui/search/authentihash%253A2d03bf608f236ee1f4654e06857a3062) |
| Authentihash SHA1  | [508c1a26486188aa1268d6c23c65e57b8efe71f6](https://www.virustotal.com/gui/search/authentihash%253A508c1a26486188aa1268d6c23c65e57b8efe71f6) |
| Authentihash SHA256| [f5215f83138901ca7ade60c2222446fa3dd7e8900a745bd339f8a596cb29356c](https://www.virustotal.com/gui/search/authentihash%253Af5215f83138901ca7ade60c2222446fa3dd7e8900a745bd339f8a596cb29356c) |
| Publisher         | YY Inc. |
| Signature         | YY Inc., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | YY Inc. |
| Description       | dianhu |
| Product           | dianhu |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* WDFLDR.SYS

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ExFreePoolWithTag
* ProbeForRead
* MmProbeAndLockPages
* MmBuildMdlForNonPagedPool
* MmMapLockedPages
* MmGetSystemRoutineAddress
* MmUnmapLockedPages
* MmCreateMdl
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* IoFreeMdl
* ExAllocatePoolWithTag
* MmIsAddressValid
* KeAttachProcess
* KeDetachProcess
* KeStackAttachProcess
* KeUnstackDetachProcess
* PsLookupProcessByProcessId
* PsGetProcessSectionBaseAddress
* KeBugCheckEx
* __C_specific_handler
* RtlCopyUnicodeString
* ExAllocatePool
* DbgPrintEx
* RtlInitUnicodeString
* ObfDereferenceObject
* _stricmp
* WdfVersionBindClass
* WdfVersionBind
* WdfVersionUnbind
* WdfVersionUnbindClass

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/dh_kernel.yaml)

*last_updated:* 2023-04-22








{{< /column >}}
{{< /block >}}
