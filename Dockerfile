FROM python:3.10-slim as build

RUN apt-get update
RUN apt-get install -y --no-install-recommends build-essential gcc 

WORKDIR /usr/app

RUN python -m venv /usr/app/venv
ENV PATH="/usr/app/venv/bin:$PATH"

copy requirements.txt .

RUN pip install -r requirements.txt

# FROM python:3.12.0b3-slim@sha256:8e3ef64883278384c49293caf631d614b4bfdac7bb494d44e17cf2d711ce2652
FROM python:3.10-slim@sha256:cc91315c3561d0b87d0525cb814d430cfbc70f10ca54577def184da80e87c1db

RUN groupadd -g 999 python && \
    useradd -r -u 999 -g python python

RUN mkdir /usr/app && chown python:python /usr/app
WORKDIR /usr/app
COPY --chown=python:python --from=build /usr/app/venv ./venv
COPY --chown=python:python . .

USER 999

ENV PATH="/usr/app/venv/bin:$PATH"

CMD ["bash"]

