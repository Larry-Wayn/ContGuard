#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="${IMAGE_NAME:-contguard:macos}"

docker build -t "${IMAGE_NAME}" -f src/Dockerfile.macos .

docker run --rm -it \
  --name contguard \
  --privileged \
  --pid=host \
  --cgroupns=host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)/src/logs:/app/src/logs" \
  "${IMAGE_NAME}"
#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="${IMAGE_NAME:-contguard:macos}"

docker build -t "${IMAGE_NAME}" -f src/Dockerfile.macos .

docker run --rm -it \
  --name contguard \
  --privileged \
  --pid=host \
  --cgroupns=host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)/src/logs:/app/src/logs" \
  "${IMAGE_NAME}"
