FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb

RUN pip install --no-cache-dir pytest==8.4.1 pytest-json-ctrf==0.3.5
RUN mkdir -p /app/src /app/fixtures /app/target /tests/fixture_nodes \
    && mknod /tests/fixture_nodes/block b 8 1 \
    && mknod /tests/fixture_nodes/char c 1 3
COPY data/rootfs_apply.py /app/src/rootfs_apply.py
COPY data/SECURITY_SPEC.md /app/SECURITY_SPEC.md
COPY data/bundle.json /app/fixtures/bundle.json
COPY data/runtime-entrypoint.sh /usr/local/bin/dynamo-runtime-entrypoint
RUN chmod 0644 /app/src/rootfs_apply.py && chmod 0644 /app/SECURITY_SPEC.md /app/fixtures/bundle.json \
    && chmod 0755 /usr/local/bin/dynamo-runtime-entrypoint
WORKDIR /app
ENTRYPOINT ["/usr/local/bin/dynamo-runtime-entrypoint"]
