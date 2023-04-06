+++

description = ""
title = "vboxdrv.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# vboxdrv.sys ![:inline](/images/twitter_verified.png) 


### Description

Used by unknown actor in Acid Rain malware. vboxdrv.sys is a vulnerable driver.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create vboxdrv.sys binPath=C:\windows\temp\vboxdrv.sys type=kernel
sc.exe start vboxdrv.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://unit42.paloaltonetworks.com/acidbox-rare-malware/">https://unit42.paloaltonetworks.com/acidbox-rare-malware/</a></li>
<li><a href="https://www.coresecurity.com/core-labs/advisories/virtualbox-privilege-escalation-vulnerability">https://www.coresecurity.com/core-labs/advisories/virtualbox-privilege-escalation-vulnerability</a></li>
<li><a href="https://unit42.paloaltonetworks.com/acidbox-rare-malware/">https://unit42.paloaltonetworks.com/acidbox-rare-malware/</a></li>
<br>

### Known Vulnerable Samples

| Filename | vboxdrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/bce7f34912ff59a3926216b206deb09f">bce7f34912ff59a3926216b206deb09f</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/696d68bdbe1d684029aaad2861c49af56694473a">696d68bdbe1d684029aaad2861c49af56694473a</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/78827fa00ea48d96ac9af8d1c1e317d02ce11793e7f7f6e4c7aac7b5d7dd490f">78827fa00ea48d96ac9af8d1c1e317d02ce11793e7f7f6e4c7aac7b5d7dd490f</a> |
| Signature | Sun Microsystems, Inc., VeriSign Class 3 Code Signing 2004 CA, VeriSign Class 3 Public Primary CA   || Description | VirtualBox Support Driver || Product | Sun VirtualBox || Filename | vboxdrv.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/eaea9ccb40c82af8f3867cd0f4dd5e9d">eaea9ccb40c82af8f3867cd0f4dd5e9d</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/7c1b25518dee1e30b5a6eaa1ea8e4a3780c24d0c">7c1b25518dee1e30b5a6eaa1ea8e4a3780c24d0c</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/cf3a7d4285d65bf8688215407bce1b51d7c6b22497f09021f0fce31cbeb78986">cf3a7d4285d65bf8688215407bce1b51d7c6b22497f09021f0fce31cbeb78986</a> |
| Signature | innotek GmbH, GlobalSign ObjectSign CA, GlobalSign Primary Object Publishing CA, GlobalSign Root CA - R1   || Description | VirtualBox Support Driver || Product | Sun VirtualBox |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/vboxdrv.yaml)

*last_updated:* 2023-04-06








{{< /column >}}
{{< /block >}}
