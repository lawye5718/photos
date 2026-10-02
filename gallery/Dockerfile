# Gallery Studio —— 轻量元数据服务 / 私密门禁
# 依赖极少（fastapi + uvicorn + pyjwt），镜像约 150MB
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Asia/Shanghai \
    # 群晖直连 pypi 慢/不稳，走国内镜像
    PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/ \
    PIP_TRUSTED_HOST=mirrors.aliyun.com \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py ./
COPY web/ ./web/

EXPOSE 8890
CMD ["python", "server.py", "serve"]
