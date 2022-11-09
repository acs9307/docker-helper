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
    SERVICE=$1
    if [[ -z $SERVICE ]] ; then
        SERVICE_LIST=$(docker-compose config --services)
        for service in $SERVICE_LIST 
        do
            SERVICE=$service
            break
        done
        echo "No service provided, using \"$SERVICE\"."
    fi
fi

export UID=$(id -u)
export GID=$(id -g)

docker-compose run --rm --entrypoint "$CMD" $SERVICE
