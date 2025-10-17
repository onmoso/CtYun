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


