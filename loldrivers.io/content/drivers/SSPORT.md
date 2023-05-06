+++

description = ""
title = "SSPORT.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# SSPORT.sys ![:inline](/images/twitter_verified.png) 


### Description

SSPORT.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-04-15
- **Author**: Nasreddine Bencherchali
- **Acknowledgement**: Paolo Stagno | [Void_Sec](https://twitter.com/Void_Sec)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0211ab46b73a2623b86c1cfcb30579ab.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create SSPORT.sys binPath=C:\windows\temp\SSPORT.sys     type=kernel &amp;&amp; sc.exe start SSPORT.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://github.com/VoidSec/Exploit-Development/tree/b82b6d3ac1cce66221101d3e0f4634aa64cb4ca7/windows/x64/kernel/ssport_v1.0">https://github.com/VoidSec/Exploit-Development/tree/b82b6d3ac1cce66221101d3e0f4634aa64cb4ca7/windows/x64/kernel/ssport_v1.0</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | SSPORT.sys |
| MD5                | [0211ab46b73a2623b86c1cfcb30579ab](https://www.virustotal.com/gui/file/0211ab46b73a2623b86c1cfcb30579ab) |
| SHA1               | [ccd547ef957189eddb6ee213e5e0136e980186f9](https://www.virustotal.com/gui/file/ccd547ef957189eddb6ee213e5e0136e980186f9) |
| SHA256             | [7cc9ba2df7b9ea6bb17ee342898edd7f54703b93b6ded6a819e83a7ee9f938b4](https://www.virustotal.com/gui/file/7cc9ba2df7b9ea6bb17ee342898edd7f54703b93b6ded6a819e83a7ee9f938b4) |
| Authentihash MD5   | [ffc522ee567368a6f98c38dd2aa57f30](https://www.virustotal.com/gui/search/authentihash%253Affc522ee567368a6f98c38dd2aa57f30) |
| Authentihash SHA1  | [06643b15efe04a2177c08d0395a2be5a910ed58c](https://www.virustotal.com/gui/search/authentihash%253A06643b15efe04a2177c08d0395a2be5a910ed58c) |
| Authentihash SHA256| [710639fd1eb76520e8733840ad78a81e09ce03930e4d3c47998e3162ae95f90e](https://www.virustotal.com/gui/search/authentihash%253A710639fd1eb76520e8733840ad78a81e09ce03930e4d3c47998e3162ae95f90e) |
| Publisher         | N/A |
| Signature         | N, /, A   |
| Date                | N/A |
| Company           | Samsung Electronics |
| Description       | Port Contention Driver |
| Product           | Port Contention Driver |
| OriginalFilename  | SSPORT.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* IoDeleteDevice
* IoDeleteSymbolicLink
* RtlInitUnicodeString
* strncpy
* IoCreateSymbolicLink
* IoCreateDevice
* IofCompleteRequest

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/ssport.yaml)

*last_updated:* 2023-05-06








{{< /column >}}
{{< /block >}}
