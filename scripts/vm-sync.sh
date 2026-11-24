#!/bin/sh
# Copies the working tree (without target/ and .git/) to a Linux VM on Google Compute Engine, for
# the Linux oracle tests that need dpkg, lintian, snapd and sudo:
#
#   VM=my-test-vm ZONE=us-central1-a PROJECT=my-project scripts/vm-sync.sh
#   gcloud compute ssh my-test-vm --zone us-central1-a --project my-project \
#     --command 'cd ~/packager && cargo test --test oracle_linux -- --include-ignored --test-threads 1'
set -eu
: "${VM:?set VM to the instance name}"
: "${ZONE:?set ZONE to the instance zone}"
: "${PROJECT:?set PROJECT to the Google Cloud project}"
cd "$(dirname "$0")/.."
tar czf - --exclude ./target --exclude ./.git . | gcloud compute ssh "$VM" --zone "$ZONE" --project "$PROJECT" --quiet --command 'rm -rf ~/packager && mkdir -p ~/packager && tar xzf - -C ~/packager 2>/dev/null'
