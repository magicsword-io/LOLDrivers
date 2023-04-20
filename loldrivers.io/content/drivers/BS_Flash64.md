+++

description = ""
title = "BS_Flash64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# BS_Flash64.sys ![:inline](/images/twitter_verified.png) 


### Description

BS_Flash64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/f5051c756035ef5de9c4c48bacb0612b.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create BS_Flash64.sys binPath=C:\windows\temp\BS_Flash64.sys type=kernel &amp;&amp; sc.exe start BS_Flash64.sys
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
| Filename           | BS_Flash64.sys |
| MD5                | [f5051c756035ef5de9c4c48bacb0612b](https://www.virustotal.com/gui/file/f5051c756035ef5de9c4c48bacb0612b) |
| SHA1               | [e83458c4a6383223759cd8024e60c17be4e7c85f](https://www.virustotal.com/gui/file/e83458c4a6383223759cd8024e60c17be4e7c85f) |
| SHA256             | [86a8e0aa29a5b52c84921188cc1f0eca9a7904dcfe09544602933d8377720219](https://www.virustotal.com/gui/file/86a8e0aa29a5b52c84921188cc1f0eca9a7904dcfe09544602933d8377720219) |
| Authentihash MD5   | [cf428ad377e1fd1a045e058b896fcee2](https://www.virustotal.com/gui/search/authentihash%253Acf428ad377e1fd1a045e058b896fcee2) |
| Authentihash SHA1  | [5107438a02164e1bcedd556a786f37f59cd04231](https://www.virustotal.com/gui/search/authentihash%253A5107438a02164e1bcedd556a786f37f59cd04231) |
| Authentihash SHA256| [543c3f024e4affd0aafa3a229fa19dbe7a70972bb18ed6347d3492dd174edac5](https://www.virustotal.com/gui/search/authentihash%253A543c3f024e4affd0aafa3a229fa19dbe7a70972bb18ed6347d3492dd174edac5) |
| Signature         | BIOSTAR MICROTECH INT&#39;L CORP, VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoDeleteDevice
* RtlFreeUnicodeString
* IoCreateSymbolicLink
* IoCreateDevice
* RtlAnsiStringToUnicodeString
* RtlInitString
* IofCompleteRequest
* MmMapLockedPages
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* ExFreePoolWithTag
* ExAllocatePoolWithTag
* MmUnmapIoSpace
* MmMapIoSpace
* KeBugCheckEx

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bs_flash64.yaml)

*last_updated:* 2023-04-20








{{< /column >}}
{{< /block >}}
