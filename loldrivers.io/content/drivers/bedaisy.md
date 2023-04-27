+++

description = ""
title = "bedaisy.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# bedaisy.sys ![:inline](/images/twitter_verified.png) 


### Description

BattlEye Anti-Cheat BEDAISY.SYS PPL privesc.

- **Created**: 2023-04-22
- **Author**: Wack0
- **Acknowledgement**: Wack0 | [Wack0](https://twitter.com/Wack0)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/7475bfea6ea1cd54029208ed59b96c6b.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create BEDaisy.sys binPath=C:\windows\temp\BEDaisy.sys type=kernel &amp;&amp; sc.exe start BEDaisy.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://github.com/magicsword-io/LOLDrivers/issues/23">https://github.com/magicsword-io/LOLDrivers/issues/23</a></li>
<li><a href="https://infosec.exchange/@Rairii/109310279380973806">https://infosec.exchange/@Rairii/109310279380973806</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | BEDAISY.SYS |
| MD5                | [7475bfea6ea1cd54029208ed59b96c6b](https://www.virustotal.com/gui/file/7475bfea6ea1cd54029208ed59b96c6b) |
| SHA1               | [fff7ee0febb8c93539220ca49d4206616e15c666](https://www.virustotal.com/gui/file/fff7ee0febb8c93539220ca49d4206616e15c666) |
| SHA256             | [2b120de80a5462f8395cfb7153c86dfd44f29f0776ea156ec4a34fa64e5c4797](https://www.virustotal.com/gui/file/2b120de80a5462f8395cfb7153c86dfd44f29f0776ea156ec4a34fa64e5c4797) |


#### Imports
{{< details "Expand" >}}

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/bedaisy.yaml)

*last_updated:* 2023-04-27








{{< /column >}}
{{< /block >}}
