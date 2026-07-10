# Nezha Agent

Agent of Nezha Monitoring

## Build compatibility

- Windows 7 uses the `windows/386` or `windows/amd64` release. These artifacts use the primary `go.mod` dependency set and a checksum-pinned [XTLS/go-win7](https://github.com/XTLS/go-win7) Go 1.26.5 toolchain. The legacy source overlay also covers systems without KB3125574.
- Windows ARM64 uses the modern dependency set and targets supported Windows 10/11 systems. Windows 7 did not provide an ARM64 platform.
- Linux, macOS, FreeBSD, and Windows ARM64 builds use the official Go 1.26.5 toolchain.
- Official Go releases only support Windows 7 through Go 1.20. The Windows 7 artifacts therefore depend on the pinned third-party toolchain above; update its version and both archive checksums together.

## Self-update

- The updater is implemented locally in `internal/selfupdate` and uses only the Go standard library plus the project's semantic-version package.
- Stable releases are queried from GitHub or Gitee. The updater selects the exact `server-agent_<os>_<arch>.zip` asset and never installs an equal or older version.
- Every archive must match the SHA-256 value published in the same release's `checksums.txt`. Missing checksums, oversized responses, invalid ZIP files, or unexpected executable names abort the update without replacing the current binary.
- Unix systems stage and atomically rename the new executable. Windows moves the running executable aside, activates the new file, and removes the hidden old file on the next start.
- Update checks are serialized in-process. If a Gitee release exists but its current-platform asset was not fully synchronized, the agent falls back to the matching GitHub release.
- `--disable-auto-update` disables startup and periodic checks. `--disable-force-update` ignores update tasks sent by the panel, and `--gitee` selects Gitee as the primary release source.

## Contributors

<!--GAMFC_DELIMITER--><a href="https://github.com/naiba" title="naiba"><img src="https://avatars.githubusercontent.com/u/29243953?v=4" width="50;" alt="naiba"/></a>
<a href="https://github.com/uubulb" title="UUBulb"><img src="https://avatars.githubusercontent.com/u/35923940?v=4" width="50;" alt="UUBulb"/></a>
<a href="https://github.com/funnyzak" title="Leon"><img src="https://avatars.githubusercontent.com/u/2562087?v=4" width="50;" alt="Leon"/></a>
<a href="https://github.com/zhangnew" title="zhangnew"><img src="https://avatars.githubusercontent.com/u/9146834?v=4" width="50;" alt="zhangnew"/></a>
<a href="https://github.com/wwng2333" title=":D"><img src="https://avatars.githubusercontent.com/u/17147265?v=4" width="50;" alt=":D"/></a>
<a href="https://github.com/DarcJC" title="Darc Z."><img src="https://avatars.githubusercontent.com/u/53445798?v=4" width="50;" alt="Darc Z."/></a>
<a href="https://github.com/xykt" title="xykt"><img src="https://avatars.githubusercontent.com/u/152045469?v=4" width="50;" alt="xykt"/></a>
<a href="https://github.com/Erope" title="卖女孩的小火柴"><img src="https://avatars.githubusercontent.com/u/44471469?v=4" width="50;" alt="卖女孩的小火柴"/></a>
<a href="https://github.com/liuran001" title="Chisato22"><img src="https://avatars.githubusercontent.com/u/32791471?v=4" width="50;" alt="Chisato22"/></a><!--GAMFC_DELIMITER_END-->
