#!/bin/bash

# Get the argument to variable and check if its a server, if it is then start the server.
if [ "$1" = 'server' ]; then
    echo "Starting server"
    exec python ./src/scsctl/server.py
fi

# If the argument is anything else then run scsctl as entrypoint.
exec scsctl "$@"
