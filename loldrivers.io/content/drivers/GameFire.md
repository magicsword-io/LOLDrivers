+++

description = "https://eclypsium.com/2019/11/12/mother-of-all-drivers/"
title = "GameFire.sys"
weight = 10

+++


{{< block "grid-1" >}}
{{< column "mt-2 pt-1">}}


# GameFire.sys 


{{< tip "warning" >}}
We were not able to verify the hash of this driver successfully, it has not been confirmed.
{{< /tip >}}


### Description

GameFire.sys is a vulnerable driver and more information will be added as found.

- **Created**: 2023-01-09
- **Author**: Michael Haag
- **Acknowledgement**:  | [](https://twitter.com/)

### Commands

```
sc.exe create GameFire.sys binPath=C:\windows\temp\GameFire.sys type=kernel
sc.exe start GameFire.sys
```

| Use Case | Privilages | Operating System | 
|:---- | ---- | ---- |
| Elevate privileges | kernel | Windows 10 |

### Resources
<br>
<li><a href=" https://eclypsium.com/2019/11/12/mother-of-all-drivers/"> https://eclypsium.com/2019/11/12/mother-of-all-drivers/</a></li>
<br>



[*source*](https://github.com/magicsword-io/LOLDrivers/tree/main/yaml/gamefire.sys.yml)

*last_updated:* 2023-03-21








{{< /column >}}
{{< /block >}}
