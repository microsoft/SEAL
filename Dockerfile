FROM ubuntu:18.04

COPY ./ /root/SEAL

RUN apt update && \
    apt install -y build-essential wget git libmsgsl-dev zlib1g-dev && \
    cd ~ && \
    wget https://cmake.org/files/v3.12/cmake-3.12.4.tar.gz && \
    tar -xf cmake-3.12.4.tar.gz && \
    cd cmake-3.12.4 && \
    ./bootstrap && \
    make && \
    make install && \
    cd ~/SEAL/native/src && \
    cmake . && \
    make && \
    make install && \
    cd ../..
