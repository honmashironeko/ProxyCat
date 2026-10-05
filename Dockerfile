FROM python:3.11.11-slim

WORKDIR /app

# tzdata 不可省：slim 基础镜像不保证带 /usr/share/zoneinfo，缺失时 compose 里的
# TZ=Asia/Shanghai 不生效，日志与访问记录的时间会整体落成 UTC。
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

RUN rm -f config/config.ini

# PUID/PGID 由 compose 从宿主传入，容器用户必须与 bind mount 进来的
# config/logs/data 属主一致：镜像里的 chown 对挂载点无效，属主不匹配时容器内的
# 非 root 用户写不了这三个目录。宿主 UID/GID 不是 1000 时在 .env 里设 PUID/PGID。
ARG PUID=1000
ARG PGID=1000
RUN groupadd -g ${PGID} proxycat && \
    useradd -u ${PUID} -g proxycat -M proxycat && \
    mkdir -p /app/logs /app/modules/proxypool/data /app/modules/proxypool/logs && \
    chown -R proxycat:proxycat /app
USER proxycat

# VOLUME 必须声明在 chown 之后：声明之后对卷目录内容的改动，旧版 builder 会丢弃、
# BuildKit 会保留，放在 chown 之前会让镜像里 config/ 的属主随构建器而变
VOLUME ["/app/config"]

# 按 config.ini 里实际的 web_port 探测（面板允许在线改端口，写死会让改过端口的容器
# 永远停在 unhealthy）。用 http.client 而不是 urllib：根路径是 302 跳转，urllib 会跟到
# 需要 token 的 /web 并因 401 判失败。encoding 必须显式给 utf-8-sig，否则 configparser
# 按系统本地代码页解码会失败。
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import configparser,http.client,sys;c=configparser.ConfigParser();c.read('/app/config/config.ini',encoding='utf-8-sig');p=c.get('Server','web_port',fallback='5001');h=http.client.HTTPConnection('127.0.0.1',int(p),timeout=3);h.request('GET','/');sys.exit(0 if h.getresponse().status<400 else 1)"

CMD ["python", "app.py"]
