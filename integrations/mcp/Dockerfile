FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY integrations/mcp/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY integrations/mcp/appsec_mcp.py /app/appsec_mcp.py
USER 65532:65532
ENTRYPOINT ["python", "/app/appsec_mcp.py"]
CMD ["--transport", "http"]
