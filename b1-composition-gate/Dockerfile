# Offline combined-image materials only. The host records the resolved Python
# RepoDigest and image ID; this recipe does not qualify Controller or inference.
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

FROM ${PYTHON_IMAGE} AS llama-build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN git init /tmp/llama && git -C /tmp/llama remote add origin https://github.com/ggml-org/llama.cpp.git \
    && git -C /tmp/llama fetch --depth=1 origin f7591a6a01f9273de03331732bdc0b39721168be \
    && git -C /tmp/llama checkout --detach FETCH_HEAD \
    && test "$(git -C /tmp/llama rev-parse HEAD)" = f7591a6a01f9273de03331732bdc0b39721168be \
    && cmake -S /tmp/llama -B /tmp/llama/build -G Ninja \
       -DCMAKE_BUILD_TYPE=Release -DGGML_CUDA=OFF -DGGML_NATIVE=OFF \
       -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=ON -DLLAMA_CURL=OFF \
       -DLLAMA_USE_PREBUILT_UI=OFF -DLLAMA_BUILD_UI=OFF \
    && cmake --build /tmp/llama/build --target llama-server -j2

FROM ${PYTHON_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libgomp1 bash && rm -rf /var/lib/apt/lists/*
COPY --from=llama-build /tmp/llama/build/bin/ /opt/llama/bin/
COPY --from=sqlite-build /tmp/sqlite/libsqlite3.so.0 /opt/b0/sqlite/libsqlite3.so.0
COPY --from=sqlite-build /tmp/sqlite/source-binding.json /opt/b0/build-record/sqlite-source-binding.json
COPY b0-payload/ /opt/b0/
COPY g1-payload/ /opt/g1/
COPY session/ /opt/b1-common-session/
COPY composition/ /opt/b1-composition/
COPY INSTALLATION_MANIFEST.json /opt/b1-composition/INSTALLATION_MANIFEST.json
COPY models/Qwen3-8B-Q4_K_M.gguf /opt/models/Qwen3-8B-Q4_K_M.gguf
RUN echo 'd98cdcbd03e17ce47681435b5150e34c1417f50b5c0019dd560e4882c5745785  /opt/models/Qwen3-8B-Q4_K_M.gguf' | sha256sum -c -
ENV LD_LIBRARY_PATH=/opt/b0/sqlite:/opt/llama/bin
RUN python -m venv /opt/aios && python -m venv /opt/native \
    && /opt/aios/bin/python -m pip install --no-cache-dir 'torch==2.5.1+cpu' --index-url https://download.pytorch.org/whl/cpu \
    && /opt/aios/bin/python -m pip install --no-cache-dir --no-deps -r /opt/g1/integration/requirements-aios-container.txt \
    && /opt/native/bin/python -m pip install --no-cache-dir -r /opt/g1/native_adapter/requirements-native.txt
# Both original records describe the same actual native venv. The generator
# requires the two fixed requirements-native.txt files to be byte-identical.
RUN mkdir -p /opt/b0/build-record /opt/g1/build-record /opt/b1-composition/build-record /logs \
    && /opt/aios/bin/python -m pip freeze > /opt/g1/build-record/aios-freeze.txt \
    && /opt/native/bin/python -m pip freeze > /opt/g1/build-record/native-freeze.txt \
    && /opt/aios/bin/python -m pip check > /opt/g1/build-record/aios-pip-check.txt \
    && /opt/native/bin/python -m pip check > /opt/g1/build-record/native-pip-check.txt \
    && dpkg-query -W > /opt/g1/build-record/os-packages.txt \
    && sha256sum /opt/llama/bin/llama-server > /opt/g1/build-record/llama-binary.sha256 \
    && cp /opt/g1/build-record/native-freeze.txt /opt/b0/build-record/native-freeze.txt \
    && cp /opt/g1/build-record/native-pip-check.txt /opt/b0/build-record/native-pip-check.txt \
    && cp /opt/g1/build-record/os-packages.txt /opt/b0/build-record/os-packages.txt \
    && /opt/native/bin/python -c "import sqlite3; assert sqlite3.sqlite_version=='3.54.1'; print(sqlite3.sqlite_version, sqlite3.connect(':memory:').execute('select sqlite_source_id()').fetchone()[0])" \
       > /opt/b0/build-record/sqlite-runtime.txt \
    && sha256sum /opt/b0/sqlite/libsqlite3.so.0 > /opt/b0/build-record/sqlite-binary.sha256
# Only fixed public installation files are made readable. /logs stays empty;
# the host supplies private tmpfs/output directories for the one offline gate.
RUN python - <<'PY'
import hashlib, json, os, pathlib, stat
roots = [pathlib.Path('/opt/b0/sqlite'), pathlib.Path('/opt/llama/bin')]
entries = {}
def record(path):
    if not path.is_file() or path.is_symlink():
        raise ValueError('runtime_regular_file_required:' + str(path))
    sha = hashlib.sha256()
    size = 0
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            sha.update(block)
            size += len(block)
    return {'bytes': size, 'sha256': sha.hexdigest()}
for root in roots:
    if not root.is_dir() or root.is_symlink():
        raise ValueError('runtime_root_required')
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(root):
                raise ValueError('runtime_link_escaped_own_root')
            entries[str(path)] = {'type': 'symlink', 'target': os.readlink(path),
                                  'resolved_path': str(resolved), **record(resolved)}
        elif path.is_dir():
            continue
        else:
            entries[str(path)] = {'type': 'file', **record(path)}
inventory = {'schema': 'b1-composition-runtime-artifacts-v1',
             'roots': list(map(str, roots)), 'entries': entries}
pathlib.Path('/opt/b1-composition/build-record/runtime-artifacts.json').write_text(
    json.dumps(inventory, sort_keys=True, indent=2) + '\n')
for parent in ('/opt', '/opt/llama', '/opt/llama/bin', '/opt/models'):
    path = pathlib.Path(parent)
    if not path.is_dir() or path.is_symlink():
        raise ValueError('public_parent_directory_required:' + parent)
    path.chmod(0o755)
for source_root in ('/opt/b0', '/opt/g1', '/opt/b1-common-session', '/opt/b1-composition'):
    root = pathlib.Path(source_root)
    for path in [root, *sorted(root.rglob('*'))]:
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            path.chmod(0o755)
        elif stat.S_ISREG(mode):
            path.chmod(0o644)
        else:
            raise ValueError('public_source_link_or_special_node:' + str(path))
model = pathlib.Path('/opt/models/Qwen3-8B-Q4_K_M.gguf')
if model.stat().st_size != 5027783488:
    raise ValueError('fixed_model_size_changed')
model.chmod(0o644)
PY
# Each preflight subprocess supplies its own exact source path. There is no
# global B0/G1 PYTHONPATH that can shadow the other fixed source installation.
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONNOUSERSITE=1
ENV ORT_DISABLE_TELEMETRY=1 HF_HUB_OFFLINE=1 HF_DATASETS_OFFLINE=1 TRANSFORMERS_OFFLINE=1
WORKDIR /logs
ENTRYPOINT ["/opt/native/bin/python", "-B", "/opt/b1-composition/preflight.py"]
