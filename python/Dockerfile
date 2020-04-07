#
# Container to build Linux SEAL libraries, python wrapper, and examples
#
FROM debian:buster

# Install binary dependencies
RUN apt-get -qqy update && apt-get install -qqy \
    	gcc \
	g++ \
	git \
	make \
	cmake \
	python3 \
	python3-dev \
	python3-pip \
	sudo \
        libdpkg-perl \
	--no-install-recommends

# Build SEAL libraries
RUN mkdir SEAL/
COPY native/ /SEAL/native/
COPY dotnet/ /SEAL/dotnet/
WORKDIR /SEAL/native/src/
RUN cmake . -DSEAL_LIB_BUILD_TYPE=Dynamic -DCMAKE_BUILD_TYPE=Release
RUN make
ENV LD_LIBRARY_PATH SEAL/native/lib:$LD_LIBRARY_PATH

# Build SEAL examples
WORKDIR /SEAL/native/examples/
RUN cmake .
RUN make

# Build SEAL Python wrapper
WORKDIR /SEAL/
RUN mkdir python 
COPY setup/ /SEAL/python/setup/
COPY examples/ /SEAL/python/examples/
WORKDIR /SEAL/python/setup
RUN pip3 install --upgrade pip
RUN pip3 install setuptools
RUN pip3 install -r requirements.txt
RUN git clone https://github.com/pybind/pybind11.git
RUN python3 setup.py build_ext -i
ENV PYTHONPATH $PYTHONPATH:/SEAL/python/setup:/SEAL/native/lib

# Add placeholder for notebooks directory to be mounted
VOLUME /notebooks

# Return to SEAL root directory
WORKDIR /SEAL

# Clean-up
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
