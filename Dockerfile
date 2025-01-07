FROM python:3.11

WORKDIR /app

COPY . .

RUN pip install --upgrade pip

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 1080

CMD ["python", "ProxyCat.py"]

