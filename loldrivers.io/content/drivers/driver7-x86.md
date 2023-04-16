+++

description = ""
title = "driver7-x86.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# driver7-x86.sys ![:inline](/images/twitter_verified.png) 


### Description

driver7-x86.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)


{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0ae30291c6cbfa7be39320badd6e8de0.bin" "Download" >}}

{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create driver7-x86.sys binPath=C:\windows\temp\driver7-x86.sys     type=kernel type=kernel &amp;&amp; sc.exe start driver7-x86.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/Chigusa0w0/AsusDriversPrivEscala"> https://github.com/Chigusa0w0/AsusDriversPrivEscala</a></li>
<li><a href="https://github.com/Chigusa0w0/AsusDriversPrivEscala">https://github.com/Chigusa0w0/AsusDriversPrivEscala</a></li>
<br>

### Known Vulnerable Samples

| Filename | driver7-x86.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/1f950cfd5ed8dd9de3de004f5416fe20">1f950cfd5ed8dd9de3de004f5416fe20</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/00b4e8b7644d1bf93f5ddb5740b444b445e81b02">00b4e8b7644d1bf93f5ddb5740b444b445e81b02</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/42851a01469ba97cdc38939b10cf9ea13237aa1f6c37b1ac84904c5a12a81fa0">42851a01469ba97cdc38939b10cf9ea13237aa1f6c37b1ac84904c5a12a81fa0</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%c5d6296b11390f68dc48dcec40990676">c5d6296b11390f68dc48dcec40990676</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%7a3c1908302851a032d45a73e67c4a3e699807a5">7a3c1908302851a032d45a73e67c4a3e699807a5</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%c67c6f1e03a466dc660bcad6051fc38eb6e9004a4e252abe52c6155f5768ad90">c67c6f1e03a466dc660bcad6051fc38eb6e9004a4e252abe52c6155f5768ad90</a> || Signature | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Company | ASUStek || Description | The driver for the ECtool driver-based tools || Product | EC tool || OriginalFilename | Driver7 |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* HAL.dll
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* ExFreePoolWithTag
* MmGetPhysicalAddress
* ExAllocatePoolWithTag
* memcpy
* memset
* ObfDereferenceObject
* IoWMIQueryAllData
* DbgPrint
* IoDeleteDevice
* IoDeleteSymbolicLink
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* KeBugCheckEx
* ZwUnmapViewOfSection
* RtlInitUnicodeString
* ZwOpenSection
* ObReferenceObjectByHandle
* ZwMapViewOfSection
* ZwClose
* IoWMIOpenBlock
* IofCompleteRequest
* WRITE_PORT_ULONG
* READ_PORT_USHORT
* WRITE_PORT_USHORT
* HalTranslateBusAddress
* WRITE_PORT_UCHAR
* READ_PORT_UCHAR
* READ_PORT_ULONG
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/driver7-x86.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
