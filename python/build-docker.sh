#!/bin/bash
cp -r ../native .
cp -r ../dotnet .
docker build -t seal-python -f Dockerfile .
rm -rf ./native
rm -rf ./dotnet
