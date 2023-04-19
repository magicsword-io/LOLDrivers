+++

description = ""
title = "smep_capcom.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# smep_capcom.sys ![:inline](/images/twitter_verified.png) 


### Description

smep_capcom.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/f406c5536bcf9bacbeb7ce8a3c383bfa.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create smep_capcom.sys binPath=C:\windows\temp\smep_capcom.sys     type=kernel &amp;&amp; sc.exe start smep_capcom.sys
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
| Filename           | smep_capcom.sys |
| MD5                | [f406c5536bcf9bacbeb7ce8a3c383bfa](https://www.virustotal.com/gui/file/f406c5536bcf9bacbeb7ce8a3c383bfa) |
| SHA1               | [21edff2937eb5cd6f6b0acb7ee5247681f624260](https://www.virustotal.com/gui/file/21edff2937eb5cd6f6b0acb7ee5247681f624260) |
| SHA256             | [db2a9247177e8cdd50fe9433d066b86ffd2a84301aa6b2eb60f361cfff077004](https://www.virustotal.com/gui/file/db2a9247177e8cdd50fe9433d066b86ffd2a84301aa6b2eb60f361cfff077004) |
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


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/smep_capcom.yaml)

*last_updated:* 2023-04-19








{{< /column >}}
{{< /block >}}
