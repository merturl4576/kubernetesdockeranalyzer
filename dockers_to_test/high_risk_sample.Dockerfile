FROM ubuntu:latest
USER root
ENV ADMIN_PASS=123456
ADD . /app
RUN apt-get update && apt-get install curl
EXPOSE 80
