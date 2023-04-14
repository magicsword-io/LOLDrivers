+++

description = ""
title = "OpenLibSys.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# OpenLibSys.sys ![:inline](/images/twitter_verified.png) 


### Description

OpenLibSys.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create OpenLibSys.sys binPath=C:\windows\temp\OpenLibSys.sys type=kernel &amp;&amp; sc.exe start OpenLibSys.sys
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

| Filename | OpenLibSys.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/ccf523b951afaa0147f22e2a7aae4976">ccf523b951afaa0147f22e2a7aae4976</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/ac600a2bc06b312d92e649b7b55e3e91e9d63451">ac600a2bc06b312d92e649b7b55e3e91e9d63451</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/91314768da140999e682d2a290d48b78bb25a35525ea12c1b1f9634d14602b2c">91314768da140999e682d2a290d48b78bb25a35525ea12c1b1f9634d14602b2c</a> |
| Signature | Noriyuki MIYAZAKI, GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   || Filename | OpenLibSys.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/96421b56dbda73e9b965f027a3bda7ba">96421b56dbda73e9b965f027a3bda7ba</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/da9cea92f996f938f699902482ac5313d5e8b28e">da9cea92f996f938f699902482ac5313d5e8b28e</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/f0605dda1def240dc7e14efa73927d6c6d89988c01ea8647b671667b2b167008">f0605dda1def240dc7e14efa73927d6c6d89988c01ea8647b671667b2b167008</a> |
| Signature | Noriyuki MIYAZAKI, GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/openlibsys.yaml)

*last_updated:* 2023-04-14








{{< /column >}}
{{< /block >}}
