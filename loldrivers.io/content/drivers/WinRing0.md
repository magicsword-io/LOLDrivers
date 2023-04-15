+++

description = ""
title = "WinRing0.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# WinRing0.sys ![:inline](/images/twitter_verified.png) 


### Description

WinRing0.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create WinRing0.sys binPath=C:\windows\temp\WinRing0.sys type=kernel &amp;&amp; sc.exe start WinRing0.sys
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

| Filename | WinRing0.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/828bb9cb1dd449cd65a29b18ec46055f">828bb9cb1dd449cd65a29b18ec46055f</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/558aad879b6a47d94a968f39d0a4e3a3aaef1ef1">558aad879b6a47d94a968f39d0a4e3a3aaef1ef1</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/3ec5ad51e6879464dfbccb9f4ed76c6325056a42548d5994ba869da9c4c039a8">3ec5ad51e6879464dfbccb9f4ed76c6325056a42548d5994ba869da9c4c039a8</a> |
| Signature | TOSHIBA AMERICA INFORMATION SYSTEMS, INC., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   || Company | OpenLibSys.org || Description | WinRing0 || Product | WinRing0 || OriginalFilename | WinRing0.sys || Filename | WinRing0.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/12cecc3c14160f32b21279c1a36b8338">12cecc3c14160f32b21279c1a36b8338</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/7fb52290883a6b69a96d480f2867643396727e83">7fb52290883a6b69a96d480f2867643396727e83</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/47eaebc920ccf99e09fc9924feb6b19b8a28589f52783327067c9b09754b5e84">47eaebc920ccf99e09fc9924feb6b19b8a28589f52783327067c9b09754b5e84</a> |
| Signature | Noriyuki MIYAZAKI, GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   || Company | OpenLibSys.org || Description | WinRing0 || Product | WinRing0 || OriginalFilename | WinRing0.sys || Filename | WinRing0.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/27bcbeec8a466178a6057b64bef66512">27bcbeec8a466178a6057b64bef66512</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/012db3a80faf1f7f727b538cbe5d94064e7159de">012db3a80faf1f7f727b538cbe5d94064e7159de</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/a7b000abbcc344444a9b00cfade7aa22ab92ce0cadec196c30eb1851ae4fa062">a7b000abbcc344444a9b00cfade7aa22ab92ce0cadec196c30eb1851ae4fa062</a> |
| Signature | EVGA, VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Company | OpenLibSys.org || Description | WinRing0 || Product | WinRing0 || OriginalFilename | WinRing0.sys |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/winring0.yaml)

*last_updated:* 2023-04-15








{{< /column >}}
{{< /block >}}
