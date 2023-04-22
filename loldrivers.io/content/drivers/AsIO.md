+++

description = ""
title = "AsIO.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# AsIO.sys ![:inline](/images/twitter_verified.png) 


### Description

AsIO.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/1dc94a6a82697c62a04e461d7a94d0b0.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create AsIO.sys binPath=C:\windows\temp\AsIO.sys type=kernel &amp;&amp; sc.exe start AsIO.sys
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
| Filename           | AsIO.sys |
| MD5                | [1dc94a6a82697c62a04e461d7a94d0b0](https://www.virustotal.com/gui/file/1dc94a6a82697c62a04e461d7a94d0b0) |
| SHA1               | [b97a8d506be2e7eaa4385f70c009b22adbd071ba](https://www.virustotal.com/gui/file/b97a8d506be2e7eaa4385f70c009b22adbd071ba) |
| SHA256             | [2da330a2088409efc351118445a824f11edbe51cf3d653b298053785097fe40e](https://www.virustotal.com/gui/file/2da330a2088409efc351118445a824f11edbe51cf3d653b298053785097fe40e) |
| Authentihash MD5   | [9fd03554246c6c74c232919c680d7be8](https://www.virustotal.com/gui/search/authentihash%253A9fd03554246c6c74c232919c680d7be8) |
| Authentihash SHA1  | [b25550309c902a21b03367ae27694c5a29b891b5](https://www.virustotal.com/gui/search/authentihash%253Ab25550309c902a21b03367ae27694c5a29b891b5) |
| Authentihash SHA256| [c3e3719ca592ba65a67f594ec1a08d0d7ad724b088be77d48cb33627c56f4614](https://www.virustotal.com/gui/search/authentihash%253Ac3e3719ca592ba65a67f594ec1a08d0d7ad724b088be77d48cb33627c56f4614) |
| Publisher         | ASUSTeK Computer Inc. |
| Signature         | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |


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
* RtlInitUnicodeString
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwClose
* MmGetPhysicalAddress
* MmAllocateContiguousMemory
* ZwUnmapViewOfSection
* IoIs32bitProcess
* IoCreateSymbolicLink
* IoCreateDevice
* IofCompleteRequest
* KeDelayExecutionThread
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | AsIO.sys |
| MD5                | [798de15f187c1f013095bbbeb6fb6197](https://www.virustotal.com/gui/file/798de15f187c1f013095bbbeb6fb6197) |
| SHA1               | [92f251358b3fe86fd5e7aa9b17330afa0d64a705](https://www.virustotal.com/gui/file/92f251358b3fe86fd5e7aa9b17330afa0d64a705) |
| SHA256             | [436ccab6f62fa2d29827916e054ade7acae485b3de1d3e5c6c62d3debf1480e7](https://www.virustotal.com/gui/file/436ccab6f62fa2d29827916e054ade7acae485b3de1d3e5c6c62d3debf1480e7) |
| Authentihash MD5   | [7bb2dcc29ba50372d08fea800c190f09](https://www.virustotal.com/gui/search/authentihash%253A7bb2dcc29ba50372d08fea800c190f09) |
| Authentihash SHA1  | [e5c090903a20744ba3583a8ea684d035e8cecc34](https://www.virustotal.com/gui/search/authentihash%253Ae5c090903a20744ba3583a8ea684d035e8cecc34) |
| Authentihash SHA256| [9dcfd796e244d0687cc35eac9538f209f76c6df12de166f19dbc7d2c47fb16b3](https://www.virustotal.com/gui/search/authentihash%253A9dcfd796e244d0687cc35eac9538f209f76c6df12de166f19dbc7d2c47fb16b3) |
| Publisher         | ASUSTeK Computer Inc. |
| Signature         | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ObReferenceObjectByHandle
* ZwOpenSection
* RtlInitUnicodeString
* ZwClose
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwMapViewOfSection
* MmGetPhysicalAddress
* MmAllocateContiguousMemory
* ZwUnmapViewOfSection
* IoIs32bitProcess
* IoCreateSymbolicLink
* IoCreateDevice
* IofCompleteRequest
* KeDelayExecutionThread
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | AsIO.sys |
| MD5                | [1392b92179b07b672720763d9b1028a5](https://www.virustotal.com/gui/file/1392b92179b07b672720763d9b1028a5) |
| SHA1               | [8b6aa5b2bff44766ef7afbe095966a71bc4183fa](https://www.virustotal.com/gui/file/8b6aa5b2bff44766ef7afbe095966a71bc4183fa) |
| SHA256             | [b4d47ea790920a4531e3df5a4b4b0721b7fea6b49a35679f0652f1e590422602](https://www.virustotal.com/gui/file/b4d47ea790920a4531e3df5a4b4b0721b7fea6b49a35679f0652f1e590422602) |
| Authentihash MD5   | [1e97ead4c5049f8fefe2b72edd5fa90e](https://www.virustotal.com/gui/search/authentihash%253A1e97ead4c5049f8fefe2b72edd5fa90e) |
| Authentihash SHA1  | [2a95f882dd9bafcc57f144a2708a7ec67dd7844c](https://www.virustotal.com/gui/search/authentihash%253A2a95f882dd9bafcc57f144a2708a7ec67dd7844c) |
| Authentihash SHA256| [7f75d91844b0c162eeb24d14bcf63b7f230e111daa7b0a26eaa489eeb22d9057](https://www.virustotal.com/gui/search/authentihash%253A7f75d91844b0c162eeb24d14bcf63b7f230e111daa7b0a26eaa489eeb22d9057) |
| Publisher         | ASUSTeK Computer Inc. |
| Signature         | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |


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
* RtlInitUnicodeString
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwClose
* MmGetPhysicalAddress
* MmAllocateContiguousMemory
* ZwUnmapViewOfSection
* IoIs32bitProcess
* IoCreateSymbolicLink
* IoCreateDevice
* IofCompleteRequest
* KeDelayExecutionThread
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----
| Property           | Value |
|:-------------------|:------|
| Filename           | AsIO.sys |
| MD5                | [fef9dd9ea587f8886ade43c1befbdafe](https://www.virustotal.com/gui/file/fef9dd9ea587f8886ade43c1befbdafe) |
| SHA1               | [af6e1f2cfb230907476e8b2d676129b6d6657124](https://www.virustotal.com/gui/file/af6e1f2cfb230907476e8b2d676129b6d6657124) |
| SHA256             | [dde6f28b3f7f2abbee59d4864435108791631e9cb4cdfb1f178e5aa9859956d8](https://www.virustotal.com/gui/file/dde6f28b3f7f2abbee59d4864435108791631e9cb4cdfb1f178e5aa9859956d8) |
| Authentihash MD5   | [9e7fb1f3c75f1f5e6769813c545643fc](https://www.virustotal.com/gui/search/authentihash%253A9e7fb1f3c75f1f5e6769813c545643fc) |
| Authentihash SHA1  | [86f07797273b7f0e0805d2add8c1a0be116eb88c](https://www.virustotal.com/gui/search/authentihash%253A86f07797273b7f0e0805d2add8c1a0be116eb88c) |
| Authentihash SHA256| [191689c53195dbe828f406b206cb167dcd4671ecdab32b80e01c885f706a6baf](https://www.virustotal.com/gui/search/authentihash%253A191689c53195dbe828f406b206cb167dcd4671ecdab32b80e01c885f706a6baf) |
| Publisher         | ASUSTeK Computer Inc. |
| Signature         | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2009-2 CA, VeriSign Class 3 Public Primary CA   |


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
* RtlInitUnicodeString
* IoDeleteDevice
* IoDeleteSymbolicLink
* ZwClose
* MmGetPhysicalAddress
* MmAllocateContiguousMemory
* ZwUnmapViewOfSection
* IoIs32bitProcess
* IoCreateSymbolicLink
* IoCreateDevice
* IofCompleteRequest
* KeDelayExecutionThread
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/asio.yaml)

*last_updated:* 2023-04-22








{{< /column >}}
{{< /block >}}
