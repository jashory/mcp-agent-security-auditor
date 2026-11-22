FROM python:3.11-slim
WORKDIR /app
COPY mcp_security_auditor.py pyproject.toml README.md LICENSE ./
ENTRYPOINT ["python3", "/app/mcp_security_auditor.py", "--mcp"]
