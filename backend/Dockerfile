FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./backend/
COPY frontend/xdr-dashboard/ ./frontend/xdr-dashboard/
COPY rules/ ./rules/
RUN mkdir -p /app/data
ENV XDR_DATABASE_PATH=/app/data/xdr.sqlite3
EXPOSE 8000
WORKDIR /app/backend
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]