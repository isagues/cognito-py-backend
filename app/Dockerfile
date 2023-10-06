# pull official base image
FROM python:3.11.6
# set working directory
WORKDIR /usr/src/app

RUN apt-get update \
  && apt-get -y install sqlite3 \
  && apt-get clean \
  && groupadd -g 999 python \
  && useradd -r -u 999 -g python python \
  && python -m venv /usr/src/app/.venv \
  && chown -R python:python /usr/src/app 

ENV PATH="/usr/src/app/.venv/bin:$PATH"
ENV PIP_NO_CACHE_DIR=off
USER 999

COPY --chown=python:python requirements.txt requirements.txt
RUN python -m pip install --upgrade pip && \
    python -m pip install -r requirements.txt

COPY --chown=python:python init.sql init.sql
RUN sqlite3 sessions.db < init.sql

COPY --chown=python:python . .

EXPOSE 8000

# run gunicorn
CMD ["python", "auth.py"]
