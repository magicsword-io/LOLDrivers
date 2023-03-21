+++

description = "https://github.com/elastic/protections-artifacts/search?q=VulnDriver"
title = "Mslo64.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# Mslo64.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

This has been referenced as a vulnerable driver, but no hash has been found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create Mslo64.sys binPath=C:\windows\temp\Mslo64.sys type=kernel
sc.exe start Mslo64.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href="https://www.unknowncheats.me/forum/anti-cheat-bypass/334557-vulnerable-driver-megathread.html">https://www.unknowncheats.me/forum/anti-cheat-bypass/334557-vulnerable-driver-megathread.html</a></li>
<br>



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/mslo64.sys.yml)

*last_updated:* 2023-03-21








{{< /column >}}
{{< /block >}}
