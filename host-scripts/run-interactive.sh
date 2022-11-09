#!/bin/bash

CMD=bash

if [[ $# -ge 2 ]] ; then
    DOCKER_DIR=$1
    SERVICE=$2
    if [[ $# -ge 3 ]] ; then
        CMD=$3
    fi

    cd $DOCKER_DIR
else
    SCRIPT_DIR=$(cd $(dirname $0); pwd)
    cd ${SCRIPT_DIR};

    SERVICE=$1
    if [[ -z $SERVICE ]] ; then
        echo "ERROR: No service provided..."
        exit 1
    fi
fi

export UID=$(id -u)
export GID=$(id -g)

docker-compose run --rm --entrypoint "$CMD" $SERVICE
