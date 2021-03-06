# chksum

（这个README是从 https://github.com/Glavo/gchecksum 抄的，因为我懒得写-_-|||）

**Chinese** | English (TODO)

English documents are not available, welcome to contribute.

(English help is available, please execute `chksum help` to view)

一个简单的文件夹校验工具，用于为文件夹下所有文件生成哈希码并保存到文件，
以及使用保存的哈希码对文件夹内容进行校验。

默认使用并发校验。

简单用法：
```
# 创建校验码
chksum g

# 校验文件
chksum v
```

帮助（可以使用 `chksum help` 查看）：
```
用法:
    chksum g [选项] <directory>   : 创建校验文件
    chksum v [选项]               : 使用校验文件对文件进行验证

Options:
    <directory>             指定要验证的文件夹（默认值为当前工作路径）
    --version               打印程序版本信息
    -h --help               打印本帮助信息
    -f <checksums file>     指定校验文件路径（默认值为 checksums.txt）
    -a --algorithm          指定将使用的哈希算法（create 模式下默认为 SHA-256，verify 模式下默认根据哈希值长度自动选择）
    -q --quiet              校验哈希时只显示校验错误的文件名
    -n --num-threads        指定计算哈希值的并发线程数（默认为当前物理处理器数s）
    -x --exclude            生成文件哈希的时候跳过指定的文件（默认跳过输出的校验文件）
```

## 介绍

chksum 有两种模式：创建（generate）模式，校验（verify）模式。
通过将 `g`或 `v` 作为第一个参数传递指定。

`-f` 选项用于指定 checksums 文件的路径，默认为当前工作路径下的 `checksums.txt` 文件，当文件名为`-`时使用标准输入/输出流。

`-a` 选项用于指定使用的哈希算法。
未指定时，创建模式会默认选择 SHA-256 算法生成校验文件，而校验模式会根据校验文件第一行中哈希码的长度来自动判断算法。

当前支持的哈希算法有：

* MD5
* SHA-1
* SHA-224
* SHA-256
* SHA-384
* SHA-512

**注意：** 校验模式自动选择算法通常很准确（因为当前哈希码位数与算法一一对应），
但未来可能会引入其他冲突的算法（例如，SHA-512/256 算法的哈希码长度与 SHA-256 相同），这时就必须显式指定。

`--num-threads`（`-n`） 选项用于指定并发计算哈希值的线程数，必须为正整数。
默认值为运行平台物理处理器数。

## checksums 文件

checksums 文件内容形式类似这样：
```
862b930590e9abbc9595179a62b3e640a4ecfd22b324f09843375412b9934cc5  Config.json
5d7090789c8956083887f10bea8628a58c179b3422c7d53bff315e150a812b25  libs/aliyun-java-sdk-alidns-2.6.29.jar
d9ff177868630668f2da1e4c8b30d215440e4bbaa953d9ccafaaba200a2f7ffc  libs/aliyun-java-sdk-core-4.5.20.jar
12ff01eeaf0c09c6a68f2ec024b3bf9fa4cad6e68b74b968bf62c7f759047032  libs/annotations-19.0.0.jar
1f58b77470d8d147a0538d515347dd322f49a83b9e884b8970051160464b65b3  libs/apiguardian-api-1.0.0.jar
d68131283c01f81cc1532ae26aebaf760f6e0b92675a0e13816d45e7f28a7f58  libs/atomicfu-common-0.14.1.jar
e73c935ed4ecb62de04b56fdf2d0256e7757b47887551a28a34cd5eafa465f3b  libs/atomicfu-jvm-0.15.1.jar
a4f463ce552b908a722fa198ef4892a226b3225e453f8df10d5c0a5bfe5db6b6  libs/bcprov-jdk15on-1.64.jar
e599d5318e97aa48f42136a2927e6dfa4e8881dff0e6c8e3109ddbbff51d7b7d  libs/commons-codec-1.11.jar
daddea1ea0be0f56978ab3006b8ac92834afeefbd9b7e4e6316fca57df0fa636  libs/commons-logging-1.2.jar
c8fb4839054d280b3033f800d1f5a97de2f028eb8ba2eb458ad287e536f3f25f  libs/gson-2.8.6.jar
6fe9026a566c6a5001608cf3fc32196641f6c1e5e1986d1037ccdbd5f31ef743  libs/httpclient-4.5.13.jar
f956209e450cb1d0c51776dfbd23e53e9dd8db9a1298ed62b70bf0944ba63b28  libs/httpcore-4.4.14.jar
aad60635eee567254ed29f18fb18c0f9e4c4dacf51c8229128203183bb35e2dd  libs/ini4j-0.5.4.jar
43fdef0b5b6ceb31b0424b208b930c74ab58fac2ceeb7b3f6fd3aeb8b5ca4393  libs/javax.activation-api-1.2.0.jar
2f8e3b5c3c0e3eddd11ed025d3937085d9b7a8f6330ccc9e1497dd2f02297875  logs/2021-03-10_045632.log
9a728db7640fb6d4b0f257ad94d0185dd76e6ccd650896acee7d80dd835d8f64  logs/2021-03-10_045852.log
738c3a5d41a582929be1be1374452b53c098a3678f896727a3916155dc137ee6  logs/2021-03-10_050400.log
0d60e31e04ad4918a25273ad082bcf5b2064792dc5fbfe27c28a39cd3cefa4eb  logs/2021-03-11_120522.log
520c311f7684a81a6d8acdd92f416e8370700c23f1b669f8a7dfce60003f0119  logs/2021-03-11_120659.log
8f9a12d9bee054d28fe40ae73e5cce128d8cd4c108ca75e7066d1f7f1edd981e  logs/2021-03-12_203327.log
```

每行的内容为 哈希码-空格*2-文件路径。文件中不存储哈希码使用的算法。

chksum 生成时会按路径排序，但校验时不要求顺序。
