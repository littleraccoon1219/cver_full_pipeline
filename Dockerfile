FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app
RUN python -m cver init-db
EXPOSE 8000
CMD ["python", "-m", "cver", "web", "--host", "0.0.0.0", "--port", "8000", "--profile", "demo"]
