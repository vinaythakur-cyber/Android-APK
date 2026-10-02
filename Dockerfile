# syntax=docker/dockerfile:1

# ---- build stage: turn the source tree into a wheel ---------------------------------------
FROM python:3.12-slim AS build
WORKDIR /src
RUN pip install --no-cache-dir build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m build --wheel --outdir /dist

# ---- runtime stage: minimal image, non-root user -------------------------------------------
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MPLCONFIGDIR=/tmp/matplotlib
RUN useradd --create-home --uid 10001 sentinel
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
USER sentinel
WORKDIR /work
# Mount your APK folder at /work:
#   docker run --rm -v "$PWD:/work" --user "$(id -u):$(id -g)" apk-sentinel \
#       scan samples/app.apk --out report/
ENTRYPOINT ["apk-sentinel"]
CMD ["--help"]
