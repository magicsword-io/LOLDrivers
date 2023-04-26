+++

description = ""
title = "smep_namco.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# smep_namco.sys ![:inline](/images/twitter_verified.png) 


### Description

smep_namco.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/02198692732722681f246c1b33f7a9d9.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create smep_namco.sys binPath=C:\windows\temp\smep_namco.sys type=kernel &amp;&amp; sc.exe start smep_namco.sys
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
| Filename           | smep_namco.sys |
| MD5                | [02198692732722681f246c1b33f7a9d9](https://www.virustotal.com/gui/file/02198692732722681f246c1b33f7a9d9) |
| SHA1               | [f052dc35b74a1a6246842fbb35eb481577537826](https://www.virustotal.com/gui/file/f052dc35b74a1a6246842fbb35eb481577537826) |
| SHA256             | [7ec93f34eb323823eb199fbf8d06219086d517d0e8f4b9e348d7afd41ec9fd5d](https://www.virustotal.com/gui/file/7ec93f34eb323823eb199fbf8d06219086d517d0e8f4b9e348d7afd41ec9fd5d) |
| Authentihash MD5   | [5673638fc95d46f6b323144472c6e608](https://www.virustotal.com/gui/search/authentihash%253A5673638fc95d46f6b323144472c6e608) |
| Authentihash SHA1  | [0f780b7ada5dd8464d9f2cc537d973f5ac804e9c](https://www.virustotal.com/gui/search/authentihash%253A0f780b7ada5dd8464d9f2cc537d973f5ac804e9c) |
| Authentihash SHA256| [7fd788358585e0b863328475898bb4400ed8d478466d1b7f5cc0252671456cc8](https://www.virustotal.com/gui/search/authentihash%253A7fd788358585e0b863328475898bb4400ed8d478466d1b7f5cc0252671456cc8) |
| Signature         | NAMCO BANDAI Online Inc., GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* IofCompleteRequest
* MmGetSystemRoutineAddress
* IoCreateSymbolicLink
* IoCreateDevice
* IoDeleteDevice

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/smep_namco.yaml)

*last_updated:* 2023-04-26








{{< /column >}}
{{< /block >}}
