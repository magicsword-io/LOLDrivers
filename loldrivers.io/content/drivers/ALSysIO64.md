+++

description = "https://github.com/namazso/physmem_drivers"
title = "ALSysIO64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# ALSysIO64.sys ![:inline](/images/twitter_verified.png) 


### Description

ALSysIO64.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create ALSysIO64.sys binPath=C:\windows\temp\ALSysIO64.sys type=kernel
sc.exe start ALSysIO64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://github.com/namazso/physmem_drivers"> https://github.com/namazso/physmem_drivers</a></li>
<br>

### Known Vulnerable Samples

| Filename | ALSysIO64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/13dda15ef67eb265869fc371c72d6ef0">13dda15ef67eb265869fc371c72d6ef0</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/2f991435a6f58e25c103a657d24ed892b99690b8">2f991435a6f58e25c103a657d24ed892b99690b8</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/7196187fb1ef8d108b380d37b2af8efdeb3ca1f6eefd37b5dc114c609147216d">7196187fb1ef8d108b380d37b2af8efdeb3ca1f6eefd37b5dc114c609147216d</a> |
| Publisher | Artur Liberman || Signature | Artur Liberman, GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Description | ALSysIO || Filename | ALSysIO64.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/ba5f0f6347780c2ed911bbf888e75bef">ba5f0f6347780c2ed911bbf888e75bef</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/f02af84393e9627ba808d4159841854a6601cf80">f02af84393e9627ba808d4159841854a6601cf80</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/7f375639a0df7fe51e5518cf87c3f513c55bc117db47d28da8c615642eb18bfa">7f375639a0df7fe51e5518cf87c3f513c55bc117db47d28da8c615642eb18bfa</a> |
| Publisher | Artur Liberman || Signature | Artur Liberman, GlobalSign CodeSigning CA - G2, GlobalSign Root CA - R1   || Description | ALSysIO |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/alsysio64.sys.yml)

*last_updated:* 2023-04-04








{{< /column >}}
{{< /block >}}
