FROM mcr.microsoft.com/playwright/python:v1.58.0-noble
ENV HOME=/tmp XDG_CACHE_HOME=/tmp
WORKDIR /srv
COPY sandbox/requirements.txt /srv/requirements-sandbox.txt
RUN pip install --no-cache-dir -r /srv/requirements-sandbox.txt
COPY app/__init__.py /srv/app/__init__.py
COPY app/security/__init__.py app/security/guard.py app/security/behaviour.py /srv/app/security/
COPY sandbox /srv/sandbox
RUN useradd --no-create-home --uid 10001 sandboxuser
USER 10001
EXPOSE 8090
CMD ["uvicorn", "sandbox.worker:app", "--host", "0.0.0.0", "--port", "8090", "--workers", "1"]
