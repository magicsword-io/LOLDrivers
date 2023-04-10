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

| Filename | elbycdio.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/ae5eb2759305402821aeddc52ba9a6d6">ae5eb2759305402821aeddc52ba9a6d6</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/3599ea2ac1fa78f423423a4cf90106ea0938dde8">3599ea2ac1fa78f423423a4cf90106ea0938dde8</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/eea53103e7a5a55dc1df79797395a2a3e96123ebd71cdd2db4b1be80e7b3f02b">eea53103e7a5a55dc1df79797395a2a3e96123ebd71cdd2db4b1be80e7b3f02b</a> |
| Signature | Elaborate Bytes AG, GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/elbycdio.yaml)

*last_updated:* 2023-04-10








{{< /column >}}
{{< /block >}}
