# Build input tag is not a reproducible image digest. Pin an approved digest for your pilot.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends libseccomp2 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY published/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY published/ /app/published/
COPY soc/ /app/soc/
COPY enterprise/ /app/enterprise/
COPY assurance/ /app/assurance/
COPY gateway.py agent_worker.py confinement.py verify.py runtime_engine.py container_runtime.py /app/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8443
CMD ["python", "-u", "container_runtime.py", "--config", "/credentials/soc-config.json"]
