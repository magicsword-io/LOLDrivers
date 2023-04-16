+++

description = ""
title = "DBUtilDrv2.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# DBUtilDrv2.sys ![:inline](/images/twitter_verified.png) 


### Description

DBUtilDrv2.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)


{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/0ae30291c6cbfa7be39320badd6e8de0.bin" "Download" >}}

{{< tip "warning" >}}
This download link contains the malcious driver!
{{< /tip >}}

### Commands

```
sc.exe create DBUtilDrv2.sys binPath=C:\windows\temp\DBUtilDrv2.sys type=kernel &amp;&amp; sc.exe start DBUtilDrv2.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/jbaines-r7/dellicious"> https://github.com/jbaines-r7/dellicious</a></li>
<li><a href=" https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"> https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<li><a href="https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/">https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<br>

### Known Vulnerable Samples

| Filename | DBUtilDrv2.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/dacb62578b3ea191ea37486d15f4f83c">dacb62578b3ea191ea37486d15f4f83c</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/90a76945fd2fa45fab2b7bcfdaf6563595f94891">90a76945fd2fa45fab2b7bcfdaf6563595f94891</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/2e6b339597a89e875f175023ed952aaac64e9d20d457bbc07acf1586e7fe2df8">2e6b339597a89e875f175023ed952aaac64e9d20d457bbc07acf1586e7fe2df8</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%3736439958e5533142648f0d278fe7df">3736439958e5533142648f0d278fe7df</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%6bc2ab0f03d7a58685a165b519e8fee6937526a6">6bc2ab0f03d7a58685a165b519e8fee6937526a6</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%d7c683ef033ac2dc4dfa0dc61f39931f91c0e8fd19e613f664cb03e14112ef6e">d7c683ef033ac2dc4dfa0dc61f39931f91c0e8fd19e613f664cb03e14112ef6e</a> || Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2012, Microsoft Root Certificate Authority 2010   |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* WppRecorder.sys
* WDFLDR.SYS
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmGetSystemRoutineAddress
* MmFreeContiguousMemorySpecifyCache
* MmAllocateContiguousMemorySpecifyCache
* MmUnmapIoSpace
* MmMapIoSpace
* MmGetPhysicalAddress
* RtlCopyUnicodeString
* KeSetPriorityThread
* KeInsertQueueDpc
* IoWMIRegistrationControl
* RtlInitUnicodeString
* imp_WppRecorderReplay
* WppAutoLogStop
* WppAutoLogStart
* WppAutoLogTrace
* WdfVersionUnbindClass
* WdfVersionBindClass
* WdfVersionUnbind
* WdfVersionBind
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}
| Filename | DBUtilDrv2.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/d104621c93213942b7b43d65b5d8d33e">d104621c93213942b7b43d65b5d8d33e</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/b03b1996a40bfea72e4584b82f6b845c503a9748">b03b1996a40bfea72e4584b82f6b845c503a9748</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/71fe5af0f1564dc187eea8d59c0fbc897712afa07d18316d2080330ba17cf009">71fe5af0f1564dc187eea8d59c0fbc897712afa07d18316d2080330ba17cf009</a> |
| Authentihash MD5 | <a href="https://www.virustotal.com/gui/search/authentihash%1e96108c0938d4c34d7072f04bc8b951">1e96108c0938d4c34d7072f04bc8b951</a> || Authentihash SHA1 | <a href="https://www.virustotal.com/gui/search/authentihash%d46ae9bcc746ca408fbb55fb0d61b638720a8f25">d46ae9bcc746ca408fbb55fb0d61b638720a8f25</a> || Authentihash SHA256 | <a href="https://www.virustotal.com/gui/search/authentihash%7bacb353363cc29f7f3815a9d01e85cd86202d92378d1ab1b11df1ab2f42f40a">7bacb353363cc29f7f3815a9d01e85cd86202d92378d1ab1b11df1ab2f42f40a</a> || Signature | Microsoft Windows Hardware Compatibility Publisher, Microsoft Windows Third Party Component CA 2012, Microsoft Root Certificate Authority 2010   || Company | Dell || Description | DBUtil || Product | DBUtil |
#### Imports
{{< details "Expand" >}}* ntoskrnl.exe
* WDFLDR.SYS
{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}* MmMapIoSpace
* MmUnmapIoSpace
* MmAllocateContiguousMemorySpecifyCache
* KeSetPriorityThread
* MmGetPhysicalAddress
* KeBugCheckEx
* KeInsertQueueDpc
* RtlCopyUnicodeString
* IoWMIRegistrationControl
* MmGetSystemRoutineAddress
* MmFreeContiguousMemorySpecifyCache
* RtlInitUnicodeString
* WdfVersionBind
* WdfVersionUnbind
* WdfVersionUnbindClass
* WdfVersionBindClass
{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}{{< /details >}}



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/dbutildrv2.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
