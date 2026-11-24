#!/bin/sh
# Copies the working tree (without target/ and .git/) to the Linux test VM.
# VM / ZONE / PROJECT can be overridden from the environment.
set -e
VM=${VM:-packager-linux-test}
ZONE=${ZONE:-us-central1-a}
PROJECT=${PROJECT:-tensorai-platform}
cd "$(dirname "$0")/.."
tar czf - --exclude ./target --exclude ./.git . | gcloud compute ssh "$VM" --zone "$ZONE" --project "$PROJECT" --quiet --command 'rm -rf ~/packager && mkdir -p ~/packager && tar xzf - -C ~/packager 2>/dev/null'
