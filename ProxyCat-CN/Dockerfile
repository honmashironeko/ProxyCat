FROM python:3.8

WORKDIR /app

COPY . /app
RUN python -m venv /venv

RUN /venv/bin/pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple/

EXPOSE 1080

ENTRYPOINT ["/venv/bin/python", "ProxyCat-V1.9.py"]
