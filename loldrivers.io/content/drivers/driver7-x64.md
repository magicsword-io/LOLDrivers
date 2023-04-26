+++

description = ""
title = "driver7-x64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# driver7-x64.sys ![:inline](/images/twitter_verified.png) 


### Description

driver7-x64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/715f8efab1d1c660e4188055c4b28eed.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create driver7-x64.sys binPath=C:\windows\temp\driver7-x64.sys     type=kernel &amp;&amp; sc.exe start driver7-x64.sys
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

| Property           | Value |
|:-------------------|:------|
| Filename           | driver7-x64.sys |
| MD5                | [715f8efab1d1c660e4188055c4b28eed](https://www.virustotal.com/gui/file/715f8efab1d1c660e4188055c4b28eed) |
| SHA1               | [7ba19a701c8af76988006d616a5f77484c13cb0a](https://www.virustotal.com/gui/file/7ba19a701c8af76988006d616a5f77484c13cb0a) |
| SHA256             | [771a8d05f1af6214e0ef0886662be500ee910ab99f0154227067fddcfe08a3dd](https://www.virustotal.com/gui/file/771a8d05f1af6214e0ef0886662be500ee910ab99f0154227067fddcfe08a3dd) |
| Authentihash MD5   | [7f66b6e24dc4f3af2f19ad9a95b1e9fa](https://www.virustotal.com/gui/search/authentihash%253A7f66b6e24dc4f3af2f19ad9a95b1e9fa) |
| Authentihash SHA1  | [5ad545cf58d644be2fc3382881cc07f0f7edfeba](https://www.virustotal.com/gui/search/authentihash%253A5ad545cf58d644be2fc3382881cc07f0f7edfeba) |
| Authentihash SHA256| [d8f7ddf5de213c6dc0356dc83b6307ec596e66c33c3cdd826a612c12004ba9dc](https://www.virustotal.com/gui/search/authentihash%253Ad8f7ddf5de213c6dc0356dc83b6307ec596e66c33c3cdd826a612c12004ba9dc) |
| Signature         | ASUSTeK Computer Inc., VeriSign Class 3 Code Signing 2010 CA, VeriSign   |
| Company           | ASUStek |
| Description       | The driver for the ECtool driver-based tools |
| Product           | EC tool |
| OriginalFilename  | Driver7 |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ExFreePoolWithTag
* IoWMIQueryAllData
* ZwMapViewOfSection
* RtlInitUnicodeString
* IoWMIOpenBlock
* MmGetPhysicalAddress
* ZwUnmapViewOfSection
* ZwClose
* ExAllocatePoolWithTag
* ObReferenceObjectByHandle
* ObfDereferenceObject
* RtlAssert
* ZwOpenSection
* IoDeleteSymbolicLink
* IoDeleteDevice
* IoCreateSymbolicLink
* IoCreateDevice
* KeBugCheckEx
* IofCompleteRequest
* DbgPrint
* HalTranslateBusAddress

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/driver7-x64.yaml)

*last_updated:* 2023-04-26








{{< /column >}}
{{< /block >}}
