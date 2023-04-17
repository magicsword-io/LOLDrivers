+++

description = ""
title = "HwOs2Ec7x64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# HwOs2Ec7x64.sys ![:inline](/images/twitter_verified.png) 


### Description

HwOs2Ec7x64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/bae1f127c4ff21d8fe45e2bbfc59c180.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create HwOs2Ec7x64.sys binPath=C:\windows\temp\HwOs2Ec7x64.sys     type=kernel type=kernel &amp;&amp; sc.exe start HwOs2Ec7x64.sys
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

| Filename | HwOs2Ec7x64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/bae1f127c4ff21d8fe45e2bbfc59c180">bae1f127c4ff21d8fe45e2bbfc59c180</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/26c4a7b392d7e7bd7f0a2a758534e45c0d9a56ab">26c4a7b392d7e7bd7f0a2a758534e45c0d9a56ab</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/b179e1ab6dc0b1aee783adbcad4ad6bb75a8a64cb798f30c0dd2ee8aaf43e6de">b179e1ab6dc0b1aee783adbcad4ad6bb75a8a64cb798f30c0dd2ee8aaf43e6de</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A9a0c8745f43136476aa78ea77af67a0a">9a0c8745f43136476aa78ea77af67a0a</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Adcfc27b5aac3e1911c0617d6c1823e65267c09a3">dcfc27b5aac3e1911c0617d6c1823e65267c09a3</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ab78cb190a4968d06f2cdab65ea0106bc47eefdaffc871ba5dd2c2dccadb1e403">b78cb190a4968d06f2cdab65ea0106bc47eefdaffc871ba5dd2c2dccadb1e403</a> || Signature | Huawei Technologies Co.,Ltd., VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Company | Huawei || Description | HwOs2Ec || Product | Huawei MateBook || OriginalFilename | HwOs2Ec.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* DbgPrint
* IofCompleteRequest
* IoCreateDevice
* IoCreateSymbolicLink
* IoDeleteDevice
* IoDeleteSymbolicLink
* IoGetCurrentProcess
* InitSafeBootMode
* memcpy_s
* RtlInitUnicodeString
* RtlEqualUnicodeString
* RtlCopyUnicodeString
* RtlAppendUnicodeToString
* ExAllocatePool
* ExFreePoolWithTag
* MmProbeAndLockPages
* MmMapLockedPagesSpecifyCache
* MmUnmapLockedPages
* IoAllocateMdl
* IoFreeMdl
* ObReferenceObjectByHandle
* ObfDereferenceObject
* ZwClose
* PsSetCreateProcessNotifyRoutine
* ZwOpenProcess
* ZwQuerySystemInformation
* ZwAllocateVirtualMemory
* ZwFreeVirtualMemory
* KeInitializeApc
* ZwOpenThread
* KeInsertQueueApc
* PsGetProcessPeb
* RtlImageDirectoryEntryToData
* KeStackAttachProcess
* KeUnstackDetachProcess
* __C_specific_handler
* PsProcessType
* PsThreadType
* PsGetThreadId
* PsGetThreadProcessId
* RtlGetVersion
* ExAllocatePoolWithTag
* MmGetSystemRoutineAddress
* ZwTerminateProcess
* KeInitializeEvent
* ExAcquireFastMutex
* ExReleaseFastMutex
* KeSetEvent
* KeWaitForMultipleObjects
* KeWaitForSingleObject
* PsCreateSystemThread
* PsTerminateSystemThread
* RtlCompareUnicodeStrings
* wcscpy_s
* _wcsnicmp
* RtlCompareUnicodeString
* RtlAppendUnicodeStringToString
* ZwCreateFile
* ZwOpenKey
* ZwQueryValueKey
* ZwQueryInformationProcess
* ObOpenObjectByPointer
* ObQueryNameString
* IoFileObjectType
* KeBugCheckEx
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/hwos2ec7x64.yaml)

*last_updated:* 2023-04-16








{{< /column >}}
{{< /block >}}
