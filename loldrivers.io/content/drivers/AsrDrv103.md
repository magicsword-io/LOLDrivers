+++

description = ""
title = "AsrDrv103.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsrDrv103.sys ![:inline](/images/twitter_verified.png) 


### Description

AsrDrv103.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/7c72a7e1d42b0790773efd8700e24952.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create AsrDrv103.sys binPath=C:\windows\temp\AsrDrv103.sys type=kernel &amp;&amp; sc.exe start AsrDrv103.sys
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
| Filename           | AsrDrv103.sys |
| MD5                | [7c72a7e1d42b0790773efd8700e24952](https://www.virustotal.com/gui/file/7c72a7e1d42b0790773efd8700e24952) |
| SHA1               | [15d1a6a904c8409fb47a82aefa42f8c3c7d8c370](https://www.virustotal.com/gui/file/15d1a6a904c8409fb47a82aefa42f8c3c7d8c370) |
| SHA256             | [2003b478b9fd1b3d76ec5bf4172c2e8915babbbee7ad1783794acbf8d4c2519d](https://www.virustotal.com/gui/file/2003b478b9fd1b3d76ec5bf4172c2e8915babbbee7ad1783794acbf8d4c2519d) |
| Authentihash MD5   | [bb59340eceecb279389290775536523a](https://www.virustotal.com/gui/search/authentihash%253Abb59340eceecb279389290775536523a) |
| Authentihash SHA1  | [b3410021ea5a46818d9ff05a96c2809a9abe8e4a](https://www.virustotal.com/gui/search/authentihash%253Ab3410021ea5a46818d9ff05a96c2809a9abe8e4a) |
| Authentihash SHA256| [b6bf2460e023b1005cc60e107b14a3cfdf9284cc378a086d92e5dcdf6e432e2c](https://www.virustotal.com/gui/search/authentihash%253Ab6bf2460e023b1005cc60e107b14a3cfdf9284cc378a086d92e5dcdf6e432e2c) |
| Signature         | ASROCK Incorporation, VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | ASRock Incorporation |
| Description       | ASRock IO Driver |
| Product           | ASRock IO Driver |
| OriginalFilename  | AsrDrv.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll
* cng.sys

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
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
* MmAllocateContiguousMemorySpecifyCache
* IofCallDriver
* KeBugCheckEx
* IoDeleteDevice
* MmGetSystemRoutineAddress
* IoCreateDevice
* ZwClose
* ObOpenObjectByPointer
* ZwSetSecurityObject
* IoDeviceObjectType
* _snwprintf
* RtlLengthSecurityDescriptor
* SeCaptureSecurityDescriptor
* RtlCreateSecurityDescriptor
* RtlSetDaclSecurityDescriptor
* RtlAbsoluteToSelfRelativeSD
* IoIsWdmVersionAvailable
* SeExports
* wcschr
* _wcsnicmp
* RtlLengthSid
* RtlAddAccessAllowedAce
* RtlGetSaclSecurityDescriptor
* RtlGetDaclSecurityDescriptor
* RtlGetGroupSecurityDescriptor
* RtlGetOwnerSecurityDescriptor
* ZwOpenKey
* ZwCreateKey
* ZwQueryValueKey
* ZwSetValueKey
* RtlFreeUnicodeString
* RtlInitUnicodeString
* MmFreeContiguousMemorySpecifyCache
* ExFreePoolWithTag
* IoDeleteSymbolicLink
* ExAllocatePoolWithTag
* KeStallExecutionProcessor
* BCryptCloseAlgorithmProvider
* BCryptGenerateSymmetricKey
* BCryptOpenAlgorithmProvider
* BCryptDecrypt
* BCryptDestroyKey

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asrdrv103.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
