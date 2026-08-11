# Proxmox 編輯 LXC runbook

目標是 Proxmox VLAN 10 的非特權 Ubuntu 24.04 LTS LXC。預設值：CT `109`、`192.168.10.22/24`、gateway `192.168.10.1`、2 vCPU、2 GB RAM、24 GB 磁碟、Docker nesting。建立前若 ID 或 IP 已占用，就依序選下一個可用值，不要覆蓋既有 CT。

## 建立前檢查

在 Proxmox shell 先確認資源與網路：

```bash
pvesh get /cluster/resources --type vm
pct list
ping -c 2 192.168.10.22
```

確認有 Ubuntu 24.04 LTS template，並為 LXC 保留固定 DHCP reservation 或靜態租約。建立時使用非特權 CT、`nesting=1`；不要把 Proxmox API token 放進 repository。

## CT 建立後

```bash
pct set 109 --unprivileged 1 --cores 2 --memory 2048 --swap 512 \
  --net0 name=eth0,bridge=vmbr10,ip=192.168.10.22/24,gw=192.168.10.1 \
  --features nesting=1,keyctl=1
pct start 109
pct enter 109
apt update && apt full-upgrade -y
apt install -y ca-certificates curl git openssh-client
```

依 Docker 官方 Ubuntu 安裝方式裝固定 major 的 Docker Engine／Compose plugin，再把本目錄的 `ops/hedgedoc` 複製到 `/opt/blog-editor`。確認 `docker compose config` 通過後才 `docker compose up -d --build`。

## 備份與還原演練

- Proxmox backup job：每天 03:30，保留 7 份每日、4 份每週。
- CT 內每天 03:00 執行 `ops/proxmox/backup-postgres.sh`，將兩個 PostgreSQL custom-format dump 寫入 `ops/hedgedoc/backups/postgres/`，再隨 03:30 LXC backup 一起保存。
- 每季建立隔離還原 CT，還原 dump、HedgeDoc uploads volume 與 publisher DB，驗證登入、草稿圖片及發布器 health。
- LXC 關機時，`chang929.site` 與 `media.chang929.site` 必須仍可正常讀取；只有 `edit.chang929.site` 與發布功能暫停。

此 runbook 只描述可重複的配置；實際 CT 建立、Cloudflare tunnel／Access／R2 連線需要在你的 Proxmox 與 Cloudflare 帳戶中執行，不能由 repository build 自動完成。
