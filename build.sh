#!/bin/bash
set -euxo pipefail

exec "$(dirname "$0")/.clusterfuzzlite/build.sh"
