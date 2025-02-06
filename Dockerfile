FROM python:3.11

WORKDIR /app

COPY . .

RUN pip install --upgrade pip -i https://pypi.mirrors.ustc.edu.cn/simple/

RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.mirrors.ustc.edu.cn/simple/

EXPOSE 1080

CMD ["python", "ProxyCat.py"]

