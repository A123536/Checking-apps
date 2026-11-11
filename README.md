# Checking-apps

ATP、IPB、OPB、SPB 板卡日志解析与源码辅助 RCA 分析软件，使用 Qt Widgets、SQLite 和 DeepSeek。

## 功能

- 按日志文件名自动识别板卡，使用对应配置头文件预处理 C 源码。
- 原始日志解析为 CSV，已解析 CSV 可直接进入 AI 分析。
- 建立板卡专用函数调用关系库，查询日志编码、函数、调用者和被调用者。
- 按 `crash-log-rca` 技能进行周期切段、逐层回溯和自检逐项核对。
- 正常基线与故障样本维护，支持任务取消和事务回滚。
- 主界面选择源码分支，各分支独立保存源码关系库、字典、正常基线和版本设置。

## 目录

```text
LogDiagnosis/                 Qt 客户端、测试、源码索引工具和 SKILL
  LogDiagnosis.pro
  skills/crash-log-rca/SKILL.md
  source_relations/
    build.ps1
    index_source.py
    board_profiles.json
    plugin/                   Qt 查询与 AI 证据插件
  NewAnalysis/                工程内的共享解析器和基线代码
  board_config/               本地板卡配置
  code_branches/              分支源码、配置清单、关系库与分析数据
  分支使用说明.md
```

## 构建

已使用 Windows、Qt 5.12.1、MinGW 7.3 64 位和 Python 3.12 验证。Qt 需要 Core、Gui、Widgets、Sql、Network、Concurrent，测试另需 TestLib。

```powershell
powershell -ExecutionPolicy Bypass -File .\LogDiagnosis\source_relations\build.ps1 `
  -QtRoot 'D:\Qt\Qt5.12.1' -BuildRoot 'D:\Qt\build-Checking-apps'
```

脚本在独立 Python 环境安装 `requirements.txt` 中的依赖，构建索引工具、插件和客户端，输出到 `LogDiagnosis/bin/`。运行时请通过 Qt 部署工具补齐 Qt DLL、平台插件及 SQLite 驱动，HTTPS 使用匹配 Qt 版本的 OpenSSL 运行库。

## 本地分析资料

首次从仓库构建时，请在本地准备四种板卡的实际配置头文件，分别放入 `LogDiagnosis/board_config/ATP`、`IPB`、`OPB`、`SPB` 下的 `PROJECT_OR_BOARD_PTCL.h`。程序新建分支时会复制这些配置作为模板，再按对应分支核对和替换。配置头的本地 include 依赖也需要保留。

当前 MSCP 分支的源码放入 `LogDiagnosis/code_branches/MSCP_MSCP/source/`，保留完整 C/H 源码目录结构。对应字典可放入 `code_branches/MSCP_MSCP/board_config/板卡名/dictionary_PLFM.csv`，也可在设置中选择。其他分支通过主界面的“新建分支”准备目录，操作步骤见 [分支使用说明](LogDiagnosis/分支使用说明.md)。

```powershell
& .\LogDiagnosis\bin\source_relations\SourceIndexer.exe `
  --source '.\LogDiagnosis\code_branches\MSCP_MSCP\source' `
  --output '.\LogDiagnosis\code_branches\MSCP_MSCP\relations\source.sqlite' `
  --profiles '.\LogDiagnosis\code_branches\MSCP_MSCP\board_profiles.json' `
  --all-boards --version '软件版本或源码快照标记'
```

配置头、固件源码、字典、日志和生成的数据库按 `.gitignore` 作为本地分析资料管理。关系库保存源码快照，更新分支源码后通过“源码关系查询 → 重建关系库”更新快照。

启动 `LogDiagnosis/bin/LogDiagnosis.exe`，配置字典及 DeepSeek API Key 后导入日志。正常基线可按板卡建立，用于数值对照。API Key 由 Windows 凭据管理器保存。

## 测试

```powershell
python -m pip install -r .\LogDiagnosis\source_relations\requirements.txt
python -m unittest discover -s .\LogDiagnosis\source_relations -p 'test_*.py' -v
```

Qt 测试工程为 `LogDiagnosis/tests/DiagnosisTests.pro`、`LogDiagnosis/tests/DiagnosisUiTests.pro` 和 `LogDiagnosis/source_relations/tests/SourceQueryTests.pro`。基础测试使用临时数据和本地模拟请求。板卡源码库测试通过 `SOURCE_RELATIONS_DATABASE`、`SOURCE_RELATIONS_PLUGIN` 指定本地夹具，完整索引器测试还需将 `SourceIndexer.exe` 放入测试程序目录的 `source_relations/`。

AI 请求测试从测试程序目录的 `skills/crash-log-rca/SKILL.md` 读取技能，测试部署时复制项目中的技能文件与匹配的 OpenSSL 运行库。

详细使用说明见 [LogDiagnosis](LogDiagnosis/README.md) 和 [源码关系库](LogDiagnosis/source_relations/README.md)。
