# 共通独立AI09：公開PRを安全に受け入れる入口（段階1）

状態：**局所テスト合格／GitHub Actions最新版未実行／独立モデル審査未実行／HOLD**。2026-11-02。対象は既存PR #2だけ。これは審査エンジン完成宣言ではない。

## なぜ既存PR #2を使うか

このリポジトリの既存PR #2には、公開用実モデル8応答、隔離実行、暗号化された検証証拠と安全境界がある。新しい審査AIを増やさず、この基盤に**公開PRを受け入れるための小さな入口**を追加した。従来の固定v0.5 ZIP、AES鍵、プライベートEnvironment、公開モデル実行の消費済み予算、104チャンクの凍結原本には手を加えていない。従来の固定対象審査は引き続き0/8・0/104でHOLD。

## 今回実装したもの

- `public_pr_scope.py`: **tokenなし／GETだけ**で、明示許可済みの公開リポジトリ、同一リポジトリ内のOpen PR、固定された現在のHEADとbase、許可済みCI workflow、成功した必須ジョブ、欠落のない比較差分を照合する。
- `tests/test_public_pr_scope.py`: 合成APIレスポンス23件。古いCIの成功、違うSHA、PRの差し替え、fork/private、未許可のリポジトリ、必須Chromeジョブのskip、欠落・巨大・バイナリ差分、コミット不足を拒否。
- `tools/public_pr_admission.py`: 引数で指定した対象について公開情報だけの確認結果を表示する。独立AIモデルを呼ばない。公開ログにコード差分・応答・秘密情報を出さない。
- 初期許可対象は `haji84/AI-VIDEO-STUDIO` のみ。ワークフロー `.github/workflows/manual-smoke.yml` とジョブ `offline-prototype-smoke`／`synthetic-browser-acceptance` の両方が、指定したPR HEAD上で成功している必要がある。他プロジェクトは承認されたポリシーを追加するだけで同じ実装を利用する。

## 操作（GitHub APIへ到達できる実行環境で）

```sh
python3 -I -B tools/public_pr_admission.py \
  --repo haji84/AI-VIDEO-STUDIO --pr 26 \
  --expected-head <最新の完全な40文字SHA> --ci-run <そのHEADで成功したCI ID>
```

正しい条件がそろえば `PUBLIC_SOURCE_VERIFIED` という**入力審査のみ**の受付JSONを返す。`independent_model_review=NOT_RUN`、`github_approval_satisfied=false`、`merge_authorized=false` は固定。旧CIを与えても合格にしない。Python標準ライブラリのみ、対象のPRコードをcheckout・import・実行しない。既存のモデル、Runner、鍵管理やGitHub権限を変更しない。

### 今回の検証証拠

ローカル Python 3.13.5 で `python3 -m unittest -v test_public_pr_scope.py` を実行し、**23件PASS／失敗0**。このローカルテストは合成GitHub応答であり実GitHub通信を試験したわけではない。追加CLIは不正なHEADを指定したとき `INVALID_EXPECTED_HEAD`／終了コード2を実測。送信したGit blob SHAは `public_pr_scope.py=6554748828c8aa8c0b0bb1c70f681c4de0692feb`、`tests/test_public_pr_scope.py=25ded4eb60f729e32c614d06e555d5539cb0d0ee`、`tools/public_pr_admission.py=72a0e0340dd27e6c85bc10c4e4d6be1ef5cf40d4` でローカル実行ファイルと一致。

AI VIDEO STUDIO PR #26の直近確認HEAD `465a1111df0fbf91f0073b4c726a8a0c0182ff44` に対し、既知の成功CI `41386923713` は旧HEAD `7c972adc77979d58dde84f0b7dbdc334a63f2abc` を対象としていた。よって**現時点の審査受付条件は未充足**。同じ成功結果を使い回して合格としない。最新版の確認は再開時に必ずGitHubから行う。

## 独立審査として完成するまでの未達

1. この追加コードに対する別モデル・別実行者の独立設計・実装レビュー。自己検査は代用不可。
2. 既存PR #2の最新版に対するCI。既存ワークフローはプルリクの明示パス指定があるため、この3ファイルの追加だけではGitHub Actionsの実行を主張できない。**消費済みモデル試験の再実行予算をリセットしたり、自動トリガーを勝手に拡張しない**。
3. 本当に別モデルを用いる、対象PRの全差分を欠測なく読む共通モデル実行アダプター。既存AI09ソースを再利用するが、固定104チャンクの契約を公開PRの任意サイズに見せかけて再利用しない。モデル名/digest、実行SHA、回答・引用・未判定を正規化し、推論しただけで欠陥確定とはしない。
4. AI VIDEO STUDIO PR #26の**最終HEADに対応する新CI成功**を取得した上で、実モデルの審査入力、全対象カバレッジ、指摘の独立再現、ステイル再検証、本人による統合判断を実証。審査AIのコメントはGitHub正式APPROVEDを偽装しない。
5. 認証・鍵・秘密媒体・既存固定ZIP・Private Environment・課金/公開条件・Publisher/main統合に関する変更は、それぞれのHuman Gateなしに実施しない。

**CopilotとCodeRabbitは使用禁止。** 検証不能・不完全・旧HEADの状態は `HOLD` または `INCONCLUSIVE` として残す。
