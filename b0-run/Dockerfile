# B0 uses no model. The shared action runtime and native transport are reusable
# by every comparison arm. The original task/provider images remain unchanged.
ARG PYTHON_IMAGE=python:3.11.17-slim-trixie
FROM ${PYTHON_IMAGE} AS sqlite-build
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev ca-certificates && rm -rf /var/lib/apt/lists/*
RUN python - <<'PY'
import hashlib, pathlib, urllib.request, zipfile, io
url='https://www.sqlite.org/2026/sqlite-amalgamation-3540100.zip'
expected='92281c86e2957f9b9305890f9ac04204caa7b677cc868dc326d942689df28e30'
raw=urllib.request.urlopen(url, timeout=120).read()
assert hashlib.sha3_256(raw).hexdigest()==expected
out=pathlib.Path('/tmp/sqlite'); out.mkdir()
with zipfile.ZipFile(io.BytesIO(raw)) as z:
    for name in ('sqlite3.c','sqlite3.h'):
        data=z.read('sqlite-amalgamation-3540100/'+name)
        (out/name).write_bytes(data)
assert hashlib.sha3_256((out/'sqlite3.c').read_bytes()).hexdigest()=='e2b869d3003b33c942b7dd7063604fbc53553e1b66609570df39b9b7b558ee81'
(out/'source-binding.json').write_text(__import__('json').dumps({'url':url,'archive_sha3_256':expected,'version':'3.54.1'}))
PY
RUN gcc -O2 -fPIC -shared -DSQLITE_THREADSAFE=1 -DSQLITE_ENABLE_COLUMN_METADATA=1 \
    -Wl,-soname,libsqlite3.so.0 -o /tmp/sqlite/libsqlite3.so.0 /tmp/sqlite/sqlite3.c -lpthread -ldl -lm

FROM ${PYTHON_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates bash \
    && rm -rf /var/lib/apt/lists/*
COPY --from=sqlite-build /tmp/sqlite/libsqlite3.so.0 /opt/b0/sqlite/libsqlite3.so.0
COPY --from=sqlite-build /tmp/sqlite/source-binding.json /opt/b0/build-record/sqlite-source-binding.json
COPY payload/ /opt/b0/
ENV LD_LIBRARY_PATH=/opt/b0/sqlite
RUN python -m venv /opt/native \
    && /opt/native/bin/python -m pip install --no-cache-dir -r /opt/b0/native_adapter/requirements-native.txt \
    && /opt/native/bin/python -m pip check > /opt/b0/build-record/native-pip-check.txt \
    && /opt/native/bin/python -m pip freeze > /opt/b0/build-record/native-freeze.txt \
    && dpkg-query -W > /opt/b0/build-record/os-packages.txt \
    && /opt/native/bin/python -c "import sqlite3; assert sqlite3.sqlite_version=='3.54.1'; print(sqlite3.sqlite_version, sqlite3.connect(':memory:').execute('select sqlite_source_id()').fetchone()[0])" \
       > /opt/b0/build-record/sqlite-runtime.txt \
    && sha256sum /opt/b0/sqlite/libsqlite3.so.0 > /opt/b0/build-record/sqlite-binary.sha256
ENV PYTHONPATH=/opt/b0/common_bridge:/opt/b0/strategy:/opt/b0/native_adapter:/opt/b0/integration
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /logs
ENTRYPOINT ["/bin/bash", "-c"]
