#!/bin/sh
for topic in $(ipfs pubsub ls | sort); do
    echo "${topic}:"
    ipfs pubsub peers "$topic"
    echo 
done
