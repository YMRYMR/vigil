#!/bin/bash
set -euxo pipefail

exec /src/vigil/.clusterfuzzlite/build.sh
