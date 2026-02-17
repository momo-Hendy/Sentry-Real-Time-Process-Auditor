FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# We added 'ninja-build' and 'cmake' to fix the error you saw
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    make \
    python3 \
    python3-pip \
    cmake \
    ninja-build \
    valgrind \
    cppcheck \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

CMD ["/bin/bash"]