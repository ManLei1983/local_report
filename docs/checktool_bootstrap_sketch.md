# checktool + local_report 草图

## 目标

- `local_report` 负责保存每台 VM 的任务配置、资源清单、版本信息和运行状态。
- `checktool` 负责启动前拉取最新配置、检查更新、写入本地配置文件、下载资源，然后启动 C++ 主程序。
- C++ 主程序继续专注业务执行和状态上报。

## 推荐流程

1. 启动 `checktool.py`
2. 读取本机 `agent_id`，例如 `VM-3-1`
3. 请求 `GET /api/bootstrap?agent_id=VM-3-1`
4. 解析返回的任务、版本、启动配置和资源清单地址
5. 如果配置版本或资源版本变化：
   - 下载资源
   - 校验 `sha256`
   - 写入本地配置文件
   - 必要时更新 `QianNian.exe`
6. 如果没有变化：
   - 直接生成运行配置
   - 启动 `QianNian.exe`
7. C++ 主程序运行中继续调用 `POST /api/report`

## 已实现接口

- `GET /console`
  Web 配置台，维护 VM 配置和资源清单
- `GET /api/bootstrap`
  根据 `agent_id` 返回某台 VM 的任务、配置、启动参数和资源信息
- `GET /api/resources/manifest`
  返回资源清单，可按 `agent_id` 过滤
- `POST /api/report`
  运行中的状态上报

## bootstrap 返回建议

```json
{
  "ok": true,
  "server_time": "2026-03-09 18:00:00",
  "agent_id": "VM-3-1",
  "profile_version": "2026-03-09-01",
  "task": {
    "enabled": true,
    "region": "97区",
    "group_start": 32,
    "group_end": 80,
    "task_mode": "normal",
    "priority": 1,
    "notes": "今天优先处理 97 区"
  },
  "config": {
    "version": "2026-03-09-script",
    "payload_text": "{\"region\":\"97区\"}",
    "payload_json": {
      "region": "97区"
    }
  },
  "launch": {
    "startup_exe": "QianNian.exe",
    "startup_args": "--mode auto",
    "script_entry": "main.lua"
  },
  "downloads": {
    "exe": {
      "version": "1.0.0",
      "url": "http://192.168.8.102/files/QianNian.zip",
      "sha256": "..."
    },
    "resources_manifest": {
      "version": "2026-03-09-manifest",
      "url": "http://192.168.8.102:18080/api/resources/manifest?agent_id=VM-3-1",
      "count": 3
    }
  }
}
```

## Manifest 条目建议

```json
{
  "ok": true,
  "agent_id": "VM-3-1",
  "count": 2,
  "items": [
    {
      "name": "gamebase.json",
      "kind": "config",
      "version": "2026-03-09-01",
      "target_path": "runtime/gamebase.json",
      "url": "http://192.168.8.102/files/gamebase.json",
      "sha256": "...",
      "size_bytes": 12345,
      "target_agents": []
    },
    {
      "name": "images_pack.zip",
      "kind": "image_pack",
      "version": "2026-03-09-01",
      "target_path": "assets/images_pack.zip",
      "url": "http://192.168.8.102/files/images_pack.zip",
      "sha256": "...",
      "size_bytes": 456789,
      "target_agents": ["VM-3-1", "VM-3-2"]
    }
  ]
}
```

## 本地目录建议

```text
vm_runtime/
  checktool.py
  cache/
  downloads/
  backups/
  runtime/
    gamebase.json
    offset.json
    task.json
  assets/
    images_pack.zip
  QianNian.exe
```

## checktool 第一版建议

- 只做“启动前同步”，不要一开始就做运行中热更新
- 所有下载文件先放到 `downloads/` 再校验
- 校验通过后再覆盖正式目录
- 启动失败时保留备份，便于回滚
- `agent_id` 建议统一成 `VM-区域-序号` 这类稳定格式
