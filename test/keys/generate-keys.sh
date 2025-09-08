#!/usr/bin/env sh

ssh-keygen -t ed25519 -f test-user-key -C "Test User"
ssh-keygen -t ed25519 -f dummy-host-key -C "Dummy Host"
