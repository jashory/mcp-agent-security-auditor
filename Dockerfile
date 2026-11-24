FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY mcp_security_auditor.py pyproject.toml README.md LICENSE ./
ENTRYPOINT ["python3", "-u", "/app/mcp_security_auditor.py", "--mcp"]
