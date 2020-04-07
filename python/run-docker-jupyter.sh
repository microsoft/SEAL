#!/bin/bash

port=12345

pushd $(dirname ${BASH_SOURCE[0]}) > /dev/null
docker run -d \
  -p "${port}":"${port}" \
  -v "$(pwd)/notebooks":"/notebooks" \
  -w "/notebooks" \
  --name pyseal-jupyter \
  seal-python \
  jupyter notebook --ip=0.0.0.0 --port="${port}"  --allow-root --NotebookApp.token=''

popd > /dev/null

sleep 2
echo "http://localhost:$port"
