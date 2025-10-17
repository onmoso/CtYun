### windows用户直接下载Releases执行即可。

只需要登录一次即可，登录成功会保存缓存数据，

### docker使用指南

```
docker run -d \
  --name ctyun \
  -e APP_USER="你的账号" \
  -e APP_PASSWORD='你的密码' \
  su3817807/ctyun:latest

```
```
非必须参数，使用登录缓存。不写为不适应，1为使用
-e LOAD_CACHE ='1'
```

### 查看日志检查是否登录并连接成功。

```
docker logs -f ctyun

```


### Python 客户端使用说明

本仓库包含一个 Python 实现（跨平台可用），功能等价于 C# 主程序。

1) 安装依赖

```
cd python_ctyun
pip install -r requirements.txt
```

2) 命令行使用（交互式输入账号/密码，首次登录会缓存 `connect.txt`）

```
python -m python_ctyun.cli --load-cache
```

3) 容器/无头环境（读取环境变量）

```
export APP_USER="你的账号"
export APP_PASSWORD="你的明文密码"
# 使用缓存（可选）
export LOAD_CACHE=1

python -m python_ctyun.cli
```

说明：
- `--load-cache` 或设置 `LOAD_CACHE=1` 将复用本地 `connect.txt`，减少重复登录。
- 首次登录需要进行验证码识别（自动调用 OCR 接口），登录成功会保存缓存。
- 连接成功后，日志中出现“发送保活消息成功。”即表示握手和保活正常。

### 云函数/Serverless 使用

Python 版本可在云函数环境（AWS Lambda、阿里云函数计算、腾讯云 SCF、GCP Cloud Functions）中运行：

1) 打包依赖（示例以层或自带依赖方式部署）

```
cd python_ctyun
pip install -r requirements.txt -t ./package
cp -r python_ctyun ./package/
cd package && zip -r ../ctyun_fn.zip .
```

2) 入口函数

```
python_ctyun.serverless.handler
```

3) 事件输入（JSON）：

```
{
  "user": "你的账号",
  "password": "你的明文密码",
  "loadCache": true
}
```

也可通过环境变量 `APP_USER`、`APP_PASSWORD`、`LOAD_CACHE=1` 传入。

函数执行会在 ~10 秒内完成一次握手与保活应答，并返回：

```
{
  "ok": true,
  "sentKeepalive": true,
  "desktopId": "xxxx"
}
```

注意：云函数通常有冷启动与超时限制，示例实现将 WebSocket 交互控制在短时窗口内，便于集成定时触发或健康检查。


