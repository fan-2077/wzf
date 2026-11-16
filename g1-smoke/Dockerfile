# First engineering build only: the resolved base image and resulting image ID
# must be recorded. This unbuilt file is not a validated reproducible image.
ARG PYTHON_IMAGE=python:3.11.17-slim-trixie
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
    && cmake --build /tmp/llama/build --target llama-server -j2

FROM ${PYTHON_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libgomp1 bash && rm -rf /var/lib/apt/lists/*
COPY --from=llama-build /tmp/llama/build/bin/ /opt/llama/bin/
COPY payload/ /opt/g1/
COPY models/Qwen3-8B-Q4_K_M.gguf /opt/models/Qwen3-8B-Q4_K_M.gguf
RUN echo 'd98cdcbd03e17ce47681435b5150e34c1417f50b5c0019dd560e4882c5745785  /opt/models/Qwen3-8B-Q4_K_M.gguf' | sha256sum -c -
RUN python -m venv /opt/aios && python -m venv /opt/native \
    && /opt/aios/bin/python -m pip install --no-cache-dir 'torch==2.5.1+cpu' --index-url https://download.pytorch.org/whl/cpu \
    && /opt/aios/bin/python -m pip install --no-cache-dir --no-deps -r /opt/g1/integration/requirements-aios-container.txt \
    && /opt/native/bin/python -m pip install --no-cache-dir -r /opt/g1/native_adapter/requirements-native.txt
# The observed environment lacked optional mem0ai/ollama dependencies of the
# installed SDK distribution. This image instead uses the exact copied SDK
# source via PYTHONPATH; that distribution and the separately installed torch
# are excluded from requirements-aios-container.txt. New conflicts fail build.
RUN mkdir -p /opt/g1/build-record /logs \
    && /opt/aios/bin/python -m pip freeze > /opt/g1/build-record/aios-freeze.txt \
    && /opt/native/bin/python -m pip freeze > /opt/g1/build-record/native-freeze.txt \
    && /opt/aios/bin/python -m pip check > /opt/g1/build-record/aios-pip-check.txt \
    && /opt/native/bin/python -m pip check > /opt/g1/build-record/native-pip-check.txt \
    && dpkg-query -W > /opt/g1/build-record/os-packages.txt \
    && sha256sum /opt/llama/bin/llama-server > /opt/g1/build-record/llama-binary.sha256
ENV PYTHONPATH=/opt/g1/integration/source_terminal:/opt/g1/sdk:/opt/g1/typed_reads:/opt/g1/native_adapter
ENV LD_LIBRARY_PATH=/opt/llama/bin PYTHONDONTWRITEBYTECODE=1
ENV ORT_DISABLE_TELEMETRY=1 HF_HUB_OFFLINE=1 HF_DATASETS_OFFLINE=1 TRANSFORMERS_OFFLINE=1
WORKDIR /logs
ENTRYPOINT ["/bin/bash", "-c"]
