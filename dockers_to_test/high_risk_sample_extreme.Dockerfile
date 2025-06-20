
FROM ubuntu:latest
USER root
ENV PASSWORD=123456
ADD . /app
COPY . /
RUN apt-get update && apt-get install curl vim net-tools -y
EXPOSE 80
