+++

description = ""
title = "windbg.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# windbg.sys ![:inline](/images/twitter_verified.png) 


### Description

Kernel driver seen in a recent CopperStealer campaign.

- **Created**: 2023-04-22
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/88bea56ae9257b40063785cf47546024.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the malicious driver!

{{< /tip >}}

### Commands

```
sc.exe create windbg.sys binPath=C:\windows\temp\windbg.sys type=kernel &amp;&amp; sc.exe start windbg.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.proofpoint.com/us/blog/threat-insight/now-you-see-it-now-you-dont-copperstealer-performs-widespread-theft">https://www.proofpoint.com/us/blog/threat-insight/now-you-see-it-now-you-dont-copperstealer-performs-widespread-theft</a></li>
<li><a href="https://twitter.com/jaydinbas/status/1642898531445886978?s=20">https://twitter.com/jaydinbas/status/1642898531445886978?s=20</a></li>
<li><a href="https://twitter.com/jaydinbas/status/1646475092006785027?s=20">https://twitter.com/jaydinbas/status/1646475092006785027?s=20</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | windbg.sys |
| MD5                | [88bea56ae9257b40063785cf47546024](https://www.virustotal.com/gui/file/88bea56ae9257b40063785cf47546024) |
| SHA1               | [b5a8e2104d76dbb04cd9ffe86784113585822375](https://www.virustotal.com/gui/file/b5a8e2104d76dbb04cd9ffe86784113585822375) |
| SHA256             | [e1cb86386757b947b39086cc8639da988f6e8018ca9995dd669bdc03c8d39d7d](https://www.virustotal.com/gui/file/e1cb86386757b947b39086cc8639da988f6e8018ca9995dd669bdc03c8d39d7d) |


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
| Property           | Value |
|:-------------------|:------|
| Filename           | windbg.sys |
| MD5                | [b6b530dd25c5eb66499968ec82e8791e](https://www.virustotal.com/gui/file/b6b530dd25c5eb66499968ec82e8791e) |
| SHA1               | [9c1c9032aa1e33461f35dbf79b6f2d061bfc6774](https://www.virustotal.com/gui/file/9c1c9032aa1e33461f35dbf79b6f2d061bfc6774) |
| SHA256             | [fa9abb3e7e06f857be191a1e049dd37642ec41fb2520c105df2227fcac3de5d5](https://www.virustotal.com/gui/file/fa9abb3e7e06f857be191a1e049dd37642ec41fb2520c105df2227fcac3de5d5) |


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
| Property           | Value |
|:-------------------|:------|
| Filename           | windbg.sys |
| MD5                | [40b968ecdbe9e967d92c5da51c390eee](https://www.virustotal.com/gui/file/40b968ecdbe9e967d92c5da51c390eee) |
| SHA1               | [b8b123a413b7bccfa8433deba4f88669c969b543](https://www.virustotal.com/gui/file/b8b123a413b7bccfa8433deba4f88669c969b543) |
| SHA256             | [06c5ebd0371342d18bc81a96f5e5ce28de64101e3c2fd0161d0b54d8368d2f1f](https://www.virustotal.com/gui/file/06c5ebd0371342d18bc81a96f5e5ce28de64101e3c2fd0161d0b54d8368d2f1f) |


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



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/windbg.yaml)

*last_updated:* 2023-04-27








{{< /column >}}
{{< /block >}}
