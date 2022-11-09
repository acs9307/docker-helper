#!/bin/bash

# Arguments:
#   Pass in bash arguments to be run after user setup is complete. 
#
# Requirements:
#   Environment Variables:
#       UID 
#       USER
#       GID

# Setup the host defined user.
useradd -u ${UID} ${USER}
groupmod -g ${GID} ${USER}
usermod -a -G 0 ${USER}
chmod g+rwx /root

if [[ $# -ge 1 ]] ; then
    su $USER -c "$@"
fi
