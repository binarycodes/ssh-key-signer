#!/usr/bin/env bash

set -eu -o pipefail

EXIT_IF_DIRTY=false

if [ -n "$(git status --porcelain -uall)" ]; then
  echo "Working directory is dirty (tracked changes OR untracked files)."
  $EXIT_IF_DIRTY && exit 1
fi

pushd ./server

current_version=$(mvn help:evaluate -Dexpression=project.version -q -DforceStdout)

read -p "Current version is [$current_version] Please enter the next version : " version

branch_name="prepare-v${version}"
git switch -c ${branch_name}

mvn versions:set -DnewVersion=${version} -DprocessAllModules
mvn versions:update-properties -DincludeProperties=ssh-signer-common-lib.version
mvn versions:commit

git add .

popd
sed -i "s/tagname=\"v[0-9]\+\.[0-9]\+\.[0-9]\+\"/tagname=\"v$version\"/g" retry-tag-workflow.sh
git add retry-tag-workflow.sh

sed -i "s/version: [0-9]\+\.[0-9]\+\.[0-9]\+/version: $version/g" nfpm.yaml
git add nfpm.yaml

git commit -S -m "update version to $version"
git push --set-upstream origin ${branch_name}

gh auth status -h github.com -a > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "GitHub CLI is logged in. Proceeding..."
else
    echo "GitHub CLI is NOT logged in. Running gh auth login..."
    gh auth login -h github.com -p ssh --skip-ssh-key -w
fi

gh pr create \
    --base main \
    --head ${branch_name} \
    --title "chore: prepare for release of v${version}" \
    --body "This PR is in preparationg for release of version ${version}." \
