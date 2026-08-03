#!/bin/sh
set -eu

case $0 in
    */*)
        script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
        ;;
    *)
        script_path=$(command -v "$0") || {
            echo "cannot locate script: $0" >&2
            exit 1
        }
        script_dir=$(CDPATH= cd -- "$(dirname -- "$script_path")" && pwd)
        ;;
esac
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
dist_dir="$repo_root/dist/debian"

for command_name in dpkg dpkg-architecture dpkg-buildpackage dpkg-parsechangelog; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "missing packaging command: $command_name" >&2
        exit 1
    }
done

dpkg_version=$(dpkg --version | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]/) { print $i; exit } }')
if ! dpkg --compare-versions "$dpkg_version" ge 1.21; then
    echo "dpkg >= 1.21 required for dpkg-buildpackage output-file options (found $dpkg_version)" >&2
    exit 1
fi

cd "$repo_root"

source_name=$(dpkg-parsechangelog -S Source)
version=$(dpkg-parsechangelog -S Version)
artifact_version=${version#*:}
arch=$(dpkg-architecture -qDEB_HOST_ARCH)

mkdir -p "$dist_dir"

dpkg-buildpackage -us -uc -b \
    --buildinfo-file="$dist_dir/${source_name}_${artifact_version}_${arch}.buildinfo" \
    --buildinfo-option="-u$dist_dir" \
    --changes-file="$dist_dir/${source_name}_${artifact_version}_${arch}.changes" \
    --changes-option="-u$dist_dir" \
    "$@"
