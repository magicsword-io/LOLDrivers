+++

description = ""
title = "POORTRY1.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# POORTRY1.sys ![:inline](/images/twitter_verified.png) 


### Description

Driver categorized as POORTRY by Mandiant.

- **Created**: 2023-03-04
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/acac842a46f3501fe407b1db1b247a0b.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malicious driver!

{{< /tip >}}

### Commands

```
sc.exe create POORTRY1.sys binPath=C:\windows\temp\POORTRY1.sys type=kernel &amp;&amp; sc.exe start POORTRY1.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware">https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware</a></li>
<li><a href=""></a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | POORTRY1.sys |
| MD5                | [acac842a46f3501fe407b1db1b247a0b](https://www.virustotal.com/gui/file/acac842a46f3501fe407b1db1b247a0b) |
| SHA1               | [31fac347aa26e92db4d8c9e1ba37a7c7a2234f08](https://www.virustotal.com/gui/file/31fac347aa26e92db4d8c9e1ba37a7c7a2234f08) |
| SHA256             | [575e58b62afab094c20c296604dc3b7dd2e1a50f5978d8ee24b7dca028e97316](https://www.virustotal.com/gui/file/575e58b62afab094c20c296604dc3b7dd2e1a50f5978d8ee24b7dca028e97316) |
| Authentihash MD5   | [887c566bdc8ed5231f45a37845d5ee89](https://www.virustotal.com/gui/search/authentihash%253A887c566bdc8ed5231f45a37845d5ee89) |
| Authentihash SHA1  | [e6ab2bbad89502d8985381b33d7351eb97cb2b78](https://www.virustotal.com/gui/search/authentihash%253Ae6ab2bbad89502d8985381b33d7351eb97cb2b78) |
| Authentihash SHA256| [565733b6e6d8f7b9661f04a3b4f29372f5dec080512551204b92ac4916a144cb](https://www.virustotal.com/gui/search/authentihash%253A565733b6e6d8f7b9661f04a3b4f29372f5dec080512551204b92ac4916a144cb) |
| Signature         | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2014, Microsoft Root Certificate Authority 2010   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ExAllocatePoolWithTag
* IoDeleteSymbolicLink
* ExFreePoolWithTag
* RtlAnsiStringToUnicodeString
* RtlInitUnicodeString
* IoDeleteDevice
* IoCreateFile
* RtlInitString
* RtlFreeUnicodeString
* ZwQueryDirectoryFile
* ZwClose
* IofCompleteRequest
* IoIsWdmVersionAvailable
* IoCreateSymbolicLink
* IoCreateDevice
* DbgPrint
* KeBugCheckEx
* __chkstk

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/poortry1.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
