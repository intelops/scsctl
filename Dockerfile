FROM python:3.10-slim as build

RUN apt-get update
RUN apt-get install -y --no-install-recommends build-essential gcc

WORKDIR /usr/app

#install node and npm
RUN apt-get update -y
RUN apt-get install -y ca-certificates curl gnupg
RUN mkdir -p /etc/apt/keyrings
RUN curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
RUN echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_18.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list

RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y nodejs \
    npm
# RUN apt-get install nodejs -y

RUN npm install -g renovate -y

ENV VIRTUAL_ENV=/usr/app/venv

RUN python -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

COPY requirements.txt .

RUN pip install -r requirements.txt

# FROM python:3.12.0b3-slim@sha256:8e3ef64883278384c49293caf631d614b4bfdac7bb494d44e17cf2d711ce2652
FROM python:3.10-slim@sha256:2bac43769ace90ebd3ad83e5392295e25dfc58e58543d3ab326c3330b505283d

RUN groupadd -g 999 python && \
    useradd -r -u 999 -g python python

RUN mkdir /usr/app && chown python:python /usr/app
WORKDIR /usr/app
COPY --chown=python:python --from=build /usr/app/venv ./venv
COPY --chown=python:python . .

RUN apt-get -y update; apt-get -y install curl
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin


USER 999

ENV PATH="/usr/app/venv/bin:$PATH"

RUN pip install build

#Build the app
RUN python -m build


#Find the wheel file name and install the wheel
RUN pip install $(find dist -name "*.whl")

# RUN apt-get -y update; apt-get -y install curl


EXPOSE 5000

RUN chmod 755 ./run.sh

ENTRYPOINT ["./run.sh"]
