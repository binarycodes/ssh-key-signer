#!/usr/bin/env bash

tagname="v0.0.10"

git tag -d "$tagname"
git push --delete origin "$tagname"

git tag -a "$tagname" -m "release version $tagname"
git push origin tag "$tagname"
