#!/usr/bin/env sh

ssh-keygen -t ed25519 -f user_ca_key -C "SSH User CA for Testing"
ssh-keygen -t ed25519 -f host_ca_key -C "SSH Host CA for Testing"
