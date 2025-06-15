#!/bin/bash

while true; do
  echo "🌀 Keep alive at $(date)"
  curl -s https://example.com > /dev/null 2>&1
  sleep 30
done
