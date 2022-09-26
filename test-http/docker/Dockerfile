FROM python:3.9-slim-buster

LABEL name="Dockerized Endpoint Testing"

WORKDIR /app
COPY docker/reqs.txt ./
COPY src ./src
COPY docker/entrypoint.sh ./

RUN pip3 --version
RUN python3 --version
RUN pip3 install -r reqs.txt

ENTRYPOINT ["/app/entrypoint.sh"]
