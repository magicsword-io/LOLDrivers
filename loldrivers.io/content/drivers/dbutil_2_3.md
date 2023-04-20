+++

description = ""
title = "dbutil_2_3.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# dbutil_2_3.sys ![:inline](/images/twitter_verified.png) 


### Description

dbutil_2_3.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/c996d7971c49252c582171d9380360f2.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create dbutil_2_3.sys binPath=C:\windows\temp\dbutil_2_3.sys type=kernel &amp;&amp; sc.exe start dbutil_2_3.sys
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
| Filename           | dbutil_2_3.sys |
| MD5                | [c996d7971c49252c582171d9380360f2](https://www.virustotal.com/gui/file/c996d7971c49252c582171d9380360f2) |
| SHA1               | [c948ae14761095e4d76b55d9de86412258be7afd](https://www.virustotal.com/gui/file/c948ae14761095e4d76b55d9de86412258be7afd) |
| SHA256             | [0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5](https://www.virustotal.com/gui/file/0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5) |
| Authentihash MD5   | [e593dd14a41fd9a6cb42fdae324c3092](https://www.virustotal.com/gui/search/authentihash%253Ae593dd14a41fd9a6cb42fdae324c3092) |
| Authentihash SHA1  | [e3c1dd569aa4758552566b0213ee4d1fe6382c4b](https://www.virustotal.com/gui/search/authentihash%253Ae3c1dd569aa4758552566b0213ee4d1fe6382c4b) |
| Authentihash SHA256| [fe4270a61dbed978c28b2915fcc2826d011148dcb7533fa8bd072ddce5944cef](https://www.virustotal.com/gui/search/authentihash%253Afe4270a61dbed978c28b2915fcc2826d011148dcb7533fa8bd072ddce5944cef) |
| Publisher         | Dell Inc. |
| Signature         | Dell Inc., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* KeSetImportanceDpc
* KeSetTargetProcessorDpc
* MmFreeContiguousMemorySpecifyCache
* KeSetPriorityThread
* RtlInitUnicodeString
* IoDeleteDevice
* KeInitializeDpc
* MmUnmapIoSpace
* MmGetPhysicalAddress
* MmMapIoSpace
* KeInsertQueueDpc
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* MmAllocateContiguousMemorySpecifyCache
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | dbutil_2_3.sys |
| MD5                | [c996d7971c49252c582171d9380360f2](https://www.virustotal.com/gui/file/c996d7971c49252c582171d9380360f2) |
| SHA1               | [c948ae14761095e4d76b55d9de86412258be7afd](https://www.virustotal.com/gui/file/c948ae14761095e4d76b55d9de86412258be7afd) |
| SHA256             | [0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5](https://www.virustotal.com/gui/file/0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5) |
| Authentihash MD5   | [e593dd14a41fd9a6cb42fdae324c3092](https://www.virustotal.com/gui/search/authentihash%253Ae593dd14a41fd9a6cb42fdae324c3092) |
| Authentihash SHA1  | [e3c1dd569aa4758552566b0213ee4d1fe6382c4b](https://www.virustotal.com/gui/search/authentihash%253Ae3c1dd569aa4758552566b0213ee4d1fe6382c4b) |
| Authentihash SHA256| [fe4270a61dbed978c28b2915fcc2826d011148dcb7533fa8bd072ddce5944cef](https://www.virustotal.com/gui/search/authentihash%253Afe4270a61dbed978c28b2915fcc2826d011148dcb7533fa8bd072ddce5944cef) |
| Publisher         | Dell Inc. |
| Signature         | Dell Inc., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* KeSetImportanceDpc
* KeSetTargetProcessorDpc
* MmFreeContiguousMemorySpecifyCache
* KeSetPriorityThread
* RtlInitUnicodeString
* IoDeleteDevice
* KeInitializeDpc
* MmUnmapIoSpace
* MmGetPhysicalAddress
* MmMapIoSpace
* KeInsertQueueDpc
* IofCompleteRequest
* IoCreateSymbolicLink
* IoCreateDevice
* MmAllocateContiguousMemorySpecifyCache
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/dbutil_2_3.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
