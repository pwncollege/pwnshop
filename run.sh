#!/bin/sh

docker build -t pwnshop .
docker run -it --rm --privileged -v $PWD/challenges:/challenges pwnshop $@
