+++

description = ""
title = "Dh_Kernel_10.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# Dh_Kernel_10.sys ![:inline](/images/twitter_verified.png) 


### Description

Dh_Kernel_10.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create Dh_Kernel_10.sys binPath=C:\windows\temp\Dh_Kernel_10.sys     type=kernel type=kernel &amp;&amp; sc.exe start Dh_Kernel_10.sys
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

| Filename | Dh_Kernel_10.sys |
|:---- | ---- | 
| MD5 | <a href="https://www.virustotal.com/gui/file/51207adb8dab983332d6b22c29fe8129">51207adb8dab983332d6b22c29fe8129</a> |
| SHA1 | <a href="https://www.virustotal.com/gui/file/ddbe809b731a0962e404a045ab9e65a0b64917ad">ddbe809b731a0962e404a045ab9e65a0b64917ad</a> |
| SHA256 | <a href="https://www.virustotal.com/gui/file/80cbba9f404df3e642f22c476664d63d7c229d45d34f5cd0e19c65eb41becec3">80cbba9f404df3e642f22c476664d63d7c229d45d34f5cd0e19c65eb41becec3</a> |
| Publisher | YY Inc. || Signature | YY Inc., VeriSign Class 3 Code Signing 2010 CA, VeriSign   || Description | dianhu |


[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/dh_kernel_10.yaml)

*last_updated:* 2023-04-10








{{< /column >}}
{{< /block >}}
