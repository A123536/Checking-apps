# Checking-apps

ATP、IPB、OPB、SPB 板卡日志解析与源码辅助 RCA 分析软件，使用 Qt Widgets、SQLite 和 DeepSeek。

## 功能

- 按日志文件名自动识别板卡，使用对应配置头文件预处理 C 源码。
- 原始日志解析为 CSV，已解析 CSV 可直接进入 AI 分析。
- 建立板卡专用函数调用关系库，查询日志编码、函数、调用者和被调用者。
- 按 `crash-log-rca` 技能进行周期切段、逐层回溯和自检逐项核对。
- 正常基线与故障样本维护，支持任务取消和事务回滚。

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
NewAnalysis/                  当前客户端使用的共享解析器和基线代码
```

## 构建

已使用 Windows、Qt 5.12.1、MinGW 7.3 64 位和 Python 3.12 验证。Qt 需要 Core、Gui、Widgets、Sql、Network、Concurrent，测试另需 TestLib。

```powershell
powershell -ExecutionPolicy Bypass -File .\LogDiagnosis\source_relations\build.ps1 `
  -QtRoot 'D:\Qt\Qt5.12.1' -BuildRoot 'D:\Qt\build-Checking-apps'
```

脚本在独立 Python 环境安装 `requirements.txt` 中的依赖，构建索引工具、插件和客户端，输出到 `LogDiagnosis/bin/`。运行时请通过 Qt 部署工具补齐 Qt DLL、平台插件及 SQLite 驱动，HTTPS 使用匹配 Qt 版本的 OpenSSL 运行库。

## 本地分析资料

按需在本地准备 MSCP C/H 源码、四个板卡的 `PROJECT_OR_BOARD_PTCL.h`、PLFM 字典和待分析日志。在 Windows 桌面的 `ATP`、`IPB`、`OPB`、`SPB` 文件夹放置配置头文件，或修改 `board_profiles.json` 中的路径。

```powershell
& .\LogDiagnosis\bin\source_relations\SourceIndexer.exe `
  --source 'C:\path\to\MSCP_MSCP' `
  --output '.\LogDiagnosis\bin\source_relations\MSCP_MSCP.sqlite' `
  --all-boards --version '软件版本或源码快照标记'
```

配置头和固件源码用于本地建库，生成的 SQLite 会保存源码文本。将这些资料与数据库保存在 `.gitignore` 指定的本地目录中。

启动 `LogDiagnosis/bin/LogDiagnosis.exe`，配置字典及 DeepSeek API Key 后导入日志。正常基线可按板卡建立，用于数值对照。API Key 由 Windows 凭据管理器保存。

## 测试

```powershell
python -m pip install -r .\LogDiagnosis\source_relations\requirements.txt
python -m unittest discover -s .\LogDiagnosis\source_relations -p 'test_*.py' -v
```

Qt 测试工程为 `LogDiagnosis/tests/DiagnosisTests.pro`、`LogDiagnosis/tests/DiagnosisUiTests.pro` 和 `LogDiagnosis/source_relations/tests/SourceQueryTests.pro`。基础测试使用临时数据和本地模拟请求。板卡源码库测试通过 `SOURCE_RELATIONS_DATABASE`、`SOURCE_RELATIONS_PLUGIN` 指定本地夹具，完整索引器测试还需将 `SourceIndexer.exe` 放入测试程序目录的 `source_relations/`。

AI 请求测试从测试程序目录的 `skills/crash-log-rca/SKILL.md` 读取技能，测试部署时复制项目中的技能文件与匹配的 OpenSSL 运行库。

详细使用说明见 [LogDiagnosis](LogDiagnosis/README.md) 和 [源码关系库](LogDiagnosis/source_relations/README.md)。
