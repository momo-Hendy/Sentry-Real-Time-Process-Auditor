FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# 1) System dependencies (Git + C toolchain + Python + venv)
RUN apt-get update && apt-get install -y \
    git \
    ca-certificates \
    curl \
    build-essential \
    gcc \
    make \
    cmake \
    ninja-build \
    valgrind \
    cppcheck \
    libssl-dev \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# 2) Create a dedicated venv at build time
ENV VENV_PATH=/opt/sentry-venv
RUN python3 -m venv ${VENV_PATH}

# 3) Make the venv the default python/pip (no "source venv/bin/activate" needed)
ENV PATH="${VENV_PATH}/bin:${PATH}"

# 4) Upgrade pip tooling inside venv
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

WORKDIR /app

# 5) Install Python dependencies into the venv
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Optional: copy project files (uncomment if you want them baked in)
# COPY . /app

CMD ["/bin/bash"]