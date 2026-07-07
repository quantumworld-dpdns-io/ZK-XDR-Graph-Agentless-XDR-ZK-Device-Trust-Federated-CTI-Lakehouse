FROM julia:1.10-slim
WORKDIR /app
COPY Project.toml .
RUN julia -e 'using Pkg; Pkg.instantiate()'
COPY src/ ./src/
EXPOSE 8086
CMD ["julia", "--project=.", "-e", "using AnomalyDetection; AnomalyDetection.run_http_server()"]
