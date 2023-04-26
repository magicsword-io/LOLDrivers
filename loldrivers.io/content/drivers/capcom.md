+++

description = ""
title = "capcom.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# capcom.sys ![:inline](/images/twitter_verified.png) 


### Description

capcom.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/73c98438ac64a68e88b7b0afd11ba140.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create capcom.sys binPath=C:\windows\temp\capcom.sys type=kernel &amp;&amp; sc.exe start capcom.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/elastic/protections-artifacts/search?q=VulnDriver"> https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<li><a href="https://github.com/elastic/protections-artifacts/search?q=VulnDriver">https://github.com/elastic/protections-artifacts/search?q=VulnDriver</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | capcom.sys |
| MD5                | [73c98438ac64a68e88b7b0afd11ba140](https://www.virustotal.com/gui/file/73c98438ac64a68e88b7b0afd11ba140) |
| SHA1               | [c1d5cf8c43e7679b782630e93f5e6420ca1749a7](https://www.virustotal.com/gui/file/c1d5cf8c43e7679b782630e93f5e6420ca1749a7) |
| SHA256             | [da6ca1fb539f825ca0f012ed6976baf57ef9c70143b7a1e88b4650bf7a925e24](https://www.virustotal.com/gui/file/da6ca1fb539f825ca0f012ed6976baf57ef9c70143b7a1e88b4650bf7a925e24) |
| Authentihash MD5   | [37458813b5115cbf06552da28fefbbbb](https://www.virustotal.com/gui/search/authentihash%253A37458813b5115cbf06552da28fefbbbb) |
| Authentihash SHA1  | [1d1cafc73c97c6bcd2331f8777d90fdca57125a3](https://www.virustotal.com/gui/search/authentihash%253A1d1cafc73c97c6bcd2331f8777d90fdca57125a3) |
| Authentihash SHA256| [faa08cb609a5b7be6bfdb61f1e4a5e8adf2f5a1d2492f262483df7326934f5d4](https://www.virustotal.com/gui/search/authentihash%253Afaa08cb609a5b7be6bfdb61f1e4a5e8adf2f5a1d2492f262483df7326934f5d4) |
| Signature         | CAPCOM Co.,Ltd., Symantec Class 3 SHA256 Code Signing CA, VeriSign   |


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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/capcom.yaml)

*last_updated:* 2023-04-26








{{< /column >}}
{{< /block >}}
