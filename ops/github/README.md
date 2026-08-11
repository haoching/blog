# GitHub App 與分支設定

發布器使用只安裝在 `haoching/blog` 的 GitHub App installation token。App 權限最小化為：

- Repository contents：Read and write
- Actions：Read-only
- Metadata：Read-only（GitHub 強制）

不要把 App private key 放在 HedgeDoc note、repository 或 Docker image。正式環境把 PEM 存在 `ops/hedgedoc/secrets/github-app.pem`（root-only，且已 gitignore），並設定 `GITHUB_APP_ID` 與 `GITHUB_APP_INSTALLATION_ID`；發布器會自動產生及更新短期 installation token。`GITHUB_TOKEN` 只保留作為 bootstrap fallback，正式環境應留空。

## 分支流程

1. 保留現有預設分支名稱 `master`，建立 `v2` 作為 preview 開發分支。
2. `v2` push 只部署 `blog-preview`；先驗收文章、舊 URL alias、手機版與圖片。
3. 驗收完成後以 pull request 合併至 `master`；`master` push 才部署 `blog`。
4. 建議保護 `master`，要求 CI build 通過並禁止未經 review 的 force-push。

發布器寫入 `content/posts/<slug>/index.md`，同一 note 的 `source_hash` 沒變時直接回傳既有 commit，不建立重複 commit。GitHub 409／branch conflict 會回傳具體錯誤，必須重新從確認頁讀取最新文章後再發布。
