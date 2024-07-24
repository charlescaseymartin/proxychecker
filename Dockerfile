FROM python:3.9.13-slim-buster

WORKDIR /app
COPY . .
RUN pip install -r ./requirements.txt

ENTRYPOINT ["python", "./main.py"]
