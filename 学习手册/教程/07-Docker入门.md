# Docker 入门
docker run -d -p 8080:80 --name web nginx；docker ps/logs/images。Dockerfile: FROM python:3.12-slim; WORKDIR /app; COPY . .; CMD ["python","app.py"]。docker build -t myapp . ; docker run -d -p 8000:8000 myapp。
