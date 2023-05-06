+++

description = ""
title = "ncpl.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# ncpl.sys ![:inline](/images/twitter_verified.png) 


### Description

ncpl.sys is a vulnerable driver. CVE-2013-3956.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/a26e600652c33dd054731b4693bf5b01.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create ncpl.sys binPath=C:\windows\temp \n \n \n  cpl.sys type=kernel &amp;&amp; sc.exe start ncpl.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/jbaines-r7/dellicious"> https://github.com/jbaines-r7/dellicious</a></li>
<li><a href=" https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"> https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<li><a href="https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/">https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | ncpl.sys |
| MD5                | [a26e600652c33dd054731b4693bf5b01](https://www.virustotal.com/gui/file/a26e600652c33dd054731b4693bf5b01) |
| SHA1               | [bbc1e5fd826961d93b76abd161314cb3592c4436](https://www.virustotal.com/gui/file/bbc1e5fd826961d93b76abd161314cb3592c4436) |
| SHA256             | [6c7120e40fc850e4715058b233f5ad4527d1084a909114fd6a36b7b7573c4a44](https://www.virustotal.com/gui/file/6c7120e40fc850e4715058b233f5ad4527d1084a909114fd6a36b7b7573c4a44) |
| Authentihash MD5   | [f3387f3cdaec9306dcc5205eebaf3faf](https://www.virustotal.com/gui/search/authentihash%253Af3387f3cdaec9306dcc5205eebaf3faf) |
| Authentihash SHA1  | [eecf71aa5767c90ead5f86f5438951f4c764b655](https://www.virustotal.com/gui/search/authentihash%253Aeecf71aa5767c90ead5f86f5438951f4c764b655) |
| Authentihash SHA256| [7b68763c39b45534854ec382434fd5a9640942c1f7393857af642ee327d4c570](https://www.virustotal.com/gui/search/authentihash%253A7b68763c39b45534854ec382434fd5a9640942c1f7393857af642ee327d4c570) |
| Signature         | Novell, Inc., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |
| Company           | Novell, Inc. |
| Description       | Novell Client Portability Layer |
| Product           | Novell XTier |
| OriginalFilename  | NICM.SYS |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* nicm.sys

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* KeWaitForSingleObject
* ExAllocatePoolWithTag
* ZwCreateKey
* ExFreePoolWithTag
* ExReleaseFastMutex
* ExAcquireFastMutex
* RtlInitUnicodeString
* ZwSetValueKey
* ZwQueryValueKey
* ZwEnumerateValueKey
* ZwClose
* RtlAppendUnicodeStringToString
* RtlCopyUnicodeString
* ZwDeleteKey
* ZwEnumerateKey
* ZwOpenKey
* DbgPrintEx
* RtlUpcaseUnicodeString
* RtlAnsiStringToUnicodeString
* RtlUnicodeStringToAnsiString
* RtlUnicodeStringToOemString
* RtlFreeUnicodeString
* RtlOemStringToUnicodeString
* RtlFreeAnsiString
* DbgPrint
* KeReleaseSpinLock
* KeAcquireSpinLockRaiseToDpc
* RtlIntegerToUnicodeString
* RtlAppendUnicodeToString
* RtlInitString
* RtlEqualUnicodeString
* RtlCompareString
* RtlCopyString
* KeReleaseMutex
* RtlEqualString
* RtlUnicodeStringToInteger
* ExAcquireResourceExclusiveLite
* KeResetEvent
* KeInitializeMutex
* KeLeaveCriticalRegion
* KeSetEvent
* ExIsResourceAcquiredSharedLite
* ExIsResourceAcquiredExclusiveLite
* KeEnterCriticalRegion
* ExAcquireResourceSharedLite
* ExReleaseResourceLite
* ExDeleteResourceLite
* ExInitializeResourceLite
* KeWaitForMultipleObjects
* KeSetPriorityThread
* IoDeleteDevice
* IoCreateDevice
* PsCreateSystemThread
* PsTerminateSystemThread
* RtlCompareMemory
* IoUninitializeWorkItem
* IoFreeWorkItem
* KeInitializeDpc
* KeInitializeTimer
* KeDelayExecutionThread
* IoAllocateWorkItem
* KeSetTimer
* IoInitializeWorkItem
* IoQueueWorkItem
* KeCancelTimer
* KeBugCheckEx
* RtlCompareUnicodeString
* KeInitializeEvent
* NicmCreateInstance

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}
* DllGetClassObject
* XTCOM_Table

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/ncpl.yaml)

*last_updated:* 2023-05-06








{{< /column >}}
{{< /block >}}
