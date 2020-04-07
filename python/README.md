# Docker - Python Wrapper 

This module wraps the native C++ code into a python3 module using pybind11
(Pybind11)[https://pybind11.readthedocs.io/en/stable/]. It is inspied on the PySEAL
proof of concept (PySEAL)[https://github.com/exii-com/PySEAL]. 

The easier way to proceed is to build the docker image and run a jupyter 
notebook

````
./build-docker.sh
./run-docker-jupyter.sh
````

To run the examples written in python, use

````
./run-docker.sh
````
