+++

description = ""
title = "IObitUnlocker.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# IObitUnlocker.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

IObitUnlocker.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/2391fb461b061d0e5fccb050d4af7941.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create IObitUnlocker.sys binPath=C:\windows\temp\IObitUnlocker.sys     type=kernel type=kernel &amp;&amp; sc.exe start IObitUnlocker.sys
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

| Filename | IObitUnlocker.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/2391fb461b061d0e5fccb050d4af7941">2391fb461b061d0e5fccb050d4af7941</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/7c6cad6a268230f6e08417d278dda4d66bb00d13">7c6cad6a268230f6e08417d278dda4d66bb00d13</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/f85cca4badff17d1aa90752153ccec77a68ad282b69e3985fdc4743eaea85004">f85cca4badff17d1aa90752153ccec77a68ad282b69e3985fdc4743eaea85004</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%253A751c91ae91cb43aadaeaa1bb187c593a">751c91ae91cb43aadaeaa1bb187c593a</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%253Add220acea885a954085e614b94da2b5bba5c0cc3">dd220acea885a954085e614b94da2b5bba5c0cc3</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%253Ae0aff24a54400fe9f86564b8ce9f874e7ff51e96085ff950baff05844cff2bd1">e0aff24a54400fe9f86564b8ce9f874e7ff51e96085ff950baff05844cff2bd1</a> || Signature | IObit CO., LTD, DigiCert EV Code Signing CA, DigiCert   || Company | IObit Information Technology || Description | Unlocker Driver || Product | Unlocker || OriginalFilename | IObitUnlocker.sys |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ExAllocatePoolWithTag
* IoDeleteSymbolicLink
* ExFreePoolWithTag
* IoDeleteDevice
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* _wcsnicmp
* ZwReadFile
* IoGetRelatedDeviceObject
* MmGetSystemRoutineAddress
* KeInitializeEvent
* ExInterlockedPopEntryList
* KeDelayExecutionThread
* IoFileObjectType
* ZwWaitForSingleObject
* ZwCreateFile
* ExAllocatePool
* IoGetCurrentProcess
* ZwClose
* ObReferenceObjectByHandle
* KeWaitForSingleObject
* RtlCompareUnicodeString
* IoAllocateIrp
* ObfDereferenceObject
* ZwQueryInformationFile
* ZwWriteFile
* ObOpenObjectByPointer
* DbgPrint
* IofCallDriver
* _wcsicmp
* PsGetProcessPeb
* PsLookupProcessByProcessId
* ZwQuerySymbolicLinkObject
* RtlInitUnicodeString
* KeSetEvent
* RtlAppendUnicodeToString
* IoCreateFile
* ZwQuerySystemInformation
* ZwOpenSymbolicLinkObject
* KeUnstackDetachProcess
* ObQueryNameString
* wcsrchr
* ZwQueryDirectoryFile
* _vsnwprintf
* RtlAppendUnicodeStringToString
* ZwDuplicateObject
* IoFreeIrp
* ZwOpenProcess
* PsGetCurrentProcessId
* MmIsAddressValid
* ZwTerminateProcess
* ExInterlockedPushEntryList
* KeStackAttachProcess
* KeBugCheckEx
* __C_specific_handler
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/iobitunlocker.yaml)

*last_updated:* 2023-04-16








{{< /column >}}
{{< /block >}}
