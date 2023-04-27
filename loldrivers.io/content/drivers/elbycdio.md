+++

description = ""
title = "elbycdio.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# elbycdio.sys ![:inline](/images/twitter_verified.png) 


### Description

elbycdio.sys is a vulnerable driver. CVE-2009-0824.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

{{< button "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/ae5eb2759305402821aeddc52ba9a6d6.bin" "Download" >}}
{{< tip "warning" >}}
This download link contains the vulnerable driver!

{{< /tip >}}

### Commands

```
sc.exe create elbycdio.sys binPath=C:\windows\temp\elbycdio.sys type=kernel &amp;&amp; sc.exe start elbycdio.sys
```

| Use Case | Privileges | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/jbaines-r7/dellicious"> https://github.com/jbaines-r7/dellicious</a></li>
<li><a href=" https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/"> https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<li><a href=" https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064459/Equation_group_questions_and_answers.pdf"> https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064459/Equation_group_questions_and_answers.pdf</a></li>
<li><a href="https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/">https://github.com/jbaines-r7/dellicious and https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/</a></li>
<br>

### Known Vulnerable Samples

| Property           | Value |
|:-------------------|:------|
| Filename           | elbycdio.sys |
| MD5                | [ae5eb2759305402821aeddc52ba9a6d6](https://www.virustotal.com/gui/file/ae5eb2759305402821aeddc52ba9a6d6) |
| SHA1               | [3599ea2ac1fa78f423423a4cf90106ea0938dde8](https://www.virustotal.com/gui/file/3599ea2ac1fa78f423423a4cf90106ea0938dde8) |
| SHA256             | [eea53103e7a5a55dc1df79797395a2a3e96123ebd71cdd2db4b1be80e7b3f02b](https://www.virustotal.com/gui/file/eea53103e7a5a55dc1df79797395a2a3e96123ebd71cdd2db4b1be80e7b3f02b) |
| Authentihash MD5   | [1e7d48bdea295db001ff57b6d05d99a2](https://www.virustotal.com/gui/search/authentihash%253A1e7d48bdea295db001ff57b6d05d99a2) |
| Authentihash SHA1  | [95a797b14c5718495e847f1aa7a5b554d1855893](https://www.virustotal.com/gui/search/authentihash%253A95a797b14c5718495e847f1aa7a5b554d1855893) |
| Authentihash SHA256| [45b7ec74cc78651975d01d88308f3231df4c96036d6c2273d79f53abdfc8888c](https://www.virustotal.com/gui/search/authentihash%253A45b7ec74cc78651975d01d88308f3231df4c96036d6c2273d79f53abdfc8888c) |
| Signature         | Elaborate Bytes AG, GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   |
| Company           | Elaborate Bytes AG |
| Description       | ElbyCD Windows NT/2000/XP I/O driver |
| Product           | CDRTools |
| OriginalFilename  | ElbyCDIO.sys |


#### Imports
{{< details "Expand" >}}
* ntoskrnl.exe
* HAL.dll

{{< /details >}}
#### ImportedFunctions
{{< details "Expand" >}}
* ZwWriteFile
* ZwCreateFile
* RtlInitUnicodeString
* swprintf
* ZwQueryVolumeInformationFile
* ZwOpenFile
* ZwClose
* ZwQuerySymbolicLinkObject
* ZwOpenSymbolicLinkObject
* PsTerminateSystemThread
* KeWaitForSingleObject
* ZwSetInformationThread
* KeSetEvent
* ObfDereferenceObject
* ObReferenceObjectByHandle
* PsCreateSystemThread
* KeInitializeEvent
* KeReleaseMutex
* ZwReadFile
* IofCompleteRequest
* KeInitializeMutex
* ExAllocatePool
* RtlFreeUnicodeString
* RtlAnsiStringToUnicodeString
* RtlInitAnsiString
* IoDeleteSymbolicLink
* IoDeleteDevice
* IofCallDriver
* IoBuildDeviceIoControlRequest
* _except_handler3
* ProbeForRead
* ProbeForWrite
* IoCreateSymbolicLink
* IoCreateDevice
* KeTickCount
* KeBugCheckEx
* KeInitializeSpinLock
* ExFreePool
* PsGetCurrentProcessId
* KfReleaseSpinLock
* KfAcquireSpinLock
* KeQueryPerformanceCounter

{{< /details >}}
#### ExportedFunctions
{{< details "Expand" >}}

{{< /details >}}
-----



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/elbycdio.yaml)

*last_updated:* 2023-04-27








{{< /column >}}
{{< /block >}}
