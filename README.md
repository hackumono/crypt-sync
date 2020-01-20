# Crypt Sync

Crypt Sync encrypts and optionally compresses files and directories, while preserving the file structure. 

## Motivation

One easy way to create an encrypted and compressed backup of a directory is by creating an archive, like the following:
```bash
gtar -cf - some_dir/ |
  pigz --fast - | 
  gpg --pinentry-mode=loopback -c - > archive.tar.gz.gpg
```

There are some pain points with this, mostly because this creates one large file:
1. Some cloud storage services don't allow files greater than some fixed size limit
1. Making small updates is impossible; you have to remake the whole archive

Crypt Sync aims to solve this problem by preserving the directory structure during the compression/encrpytion.

## Example

For example running `csync` on the following `src/` directory would result in something like

```bash
src/
├── clargs.rs
├── crypt/
│  ├── mod.rs
│  └── ...
├── encoders/
│  ├── mod.rs
│  └── ...
└── main.rs
```

```bash
ABASID==.zst.csync/
├── AS8D9122.zst.csync/
├── IOJSGDIU.zst.csync/
│  ├── SGIUD278.zst.csync
│  └── ...
├── 78SDGKF=.zst.csync/
│  ├── 89ZZJJFW.zst.csync
│  └── ...
└── KLO1284=.zst.csync
```
 
<!--
[![Colmac crate](https://img.shields.io/crates/v/colmac.svg)](https://crates.io/crates/colmac)
[![Colmac documentation](https://docs.rs/colmac/badge.svg)](https://docs.rs/colmac)
-->
