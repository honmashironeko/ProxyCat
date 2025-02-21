FROM python:3.11

WORKDIR /app

COPY requirements.txt .

RUN pip install --upgrade pip -i https://pypi.mirrors.ustc.edu.cn/simple/ && \
    pip install --no-cache-dir -r requirements.txt -i https://pypi.mirrors.ustc.edu.cn/simple/

COPY . .

RUN rm -f config/config.ini

VOLUME ["/app/config"]

CMD ["python", "app.py"]

