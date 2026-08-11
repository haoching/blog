# GitHub App 與分支設定

發布器使用只安裝在 `haoching/blog` 的 GitHub App installation token。App 權限最小化為：

- Repository contents：Read and write
- Actions：Read-only
- Metadata：Read-only（GitHub 強制）

不要把 App private key 放在 HedgeDoc note、repository 或 Docker image；在 LXC secret store／root-only `.env` 產生短期 installation token，填入 `GITHUB_TOKEN`。目前程式也接受 fine-grained token 作為 bootstrap，但正式環境應換回 App installation token。

## 分支流程

1. 保留現有預設分支名稱 `master`，建立 `v2` 作為 preview 開發分支。
2. `v2` push 只部署 `blog-preview`；先驗收文章、舊 URL alias、手機版與圖片。
3. 驗收完成後以 pull request 合併至 `master`；`master` push 才部署 `blog`。
4. 建議保護 `master`，要求 CI build 通過並禁止未經 review 的 force-push。

發布器寫入 `content/posts/<slug>/index.md`，同一 note 的 `source_hash` 沒變時直接回傳既有 commit，不建立重複 commit。GitHub 409／branch conflict 會回傳具體錯誤，必須重新從確認頁讀取最新文章後再發布。
