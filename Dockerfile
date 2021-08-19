FROM ubuntu:20.04

# DEBIAN_FRONTEND=noninteractive necessary for tzdata dependency package
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
  git \
  cmake \
  clang

WORKDIR /root
RUN git clone -b v3.6.6 https://github.com/microsoft/SEAL && \
  cd SEAL && \
  cmake -S . -B build && \
  cmake --build build && \
  cmake --install build
