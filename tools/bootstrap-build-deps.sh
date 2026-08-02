#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
toolchain_root="$repo_root/.toolchain"
download_root="$toolchain_root/downloads"
zig_dir="$toolchain_root/zig"
deps_dir="$toolchain_root/deps/x86_64-linux-gnu"

for command_name in curl dpkg-deb sha256sum sha512sum tar uname; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "missing bootstrap command: $command_name" >&2
        exit 1
    }
done

case "$(uname -m)" in
    x86_64) ;;
    *)
        echo "bootstrap currently supports x86_64 Linux only" >&2
        exit 1
        ;;
esac

mkdir -p "$download_root"

download_sha256() {
    url=$1
    destination=$2
    checksum=$3
    if [ ! -f "$destination" ] || ! echo "$checksum  $destination" | sha256sum -c - >/dev/null 2>&1; then
        temporary="$destination.part"
        rm -f "$temporary"
        curl --fail --location --proto '=https' --tlsv1.2 "$url" --output "$temporary"
        echo "$checksum  $temporary" | sha256sum -c - >/dev/null
        mv "$temporary" "$destination"
    fi
}

download_sha512() {
    url=$1
    destination=$2
    checksum=$3
    if [ ! -f "$destination" ] || ! echo "$checksum  $destination" | sha512sum -c - >/dev/null 2>&1; then
        temporary="$destination.part"
        rm -f "$temporary"
        curl --fail --location --proto '=https' --tlsv1.2 "$url" --output "$temporary"
        echo "$checksum  $temporary" | sha512sum -c - >/dev/null
        mv "$temporary" "$destination"
    fi
}

zig_archive="$download_root/zig-x86_64-linux-0.16.0.tar.xz"
if [ ! -x "$zig_dir/zig" ] || [ "$("$zig_dir/zig" version 2>/dev/null || true)" != "0.16.0" ]; then
    download_sha256 \
        "https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz" \
        "$zig_archive" \
        "70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00"
    zig_staging=$(mktemp -d "$toolchain_root/zig.XXXXXX")
    tar -xJf "$zig_archive" -C "$zig_staging" --strip-components=1
    rm -rf "$zig_dir"
    mv "$zig_staging" "$zig_dir"
fi

libbpf_deb="$download_root/libbpf-dev_1.1.2-0+deb12u1_amd64.deb"
libelf_deb="$download_root/libelf-dev_0.188-2.1_amd64.deb"
zlib_deb="$download_root/zlib1g-dev_1.2.13.dfsg-1_amd64.deb"
zstd_deb="$download_root/libzstd-dev_1.5.4+dfsg2-5_amd64.deb"

download_sha512 \
    "https://deb.debian.org/debian/pool/main/libb/libbpf/libbpf-dev_1.1.2-0%2bdeb12u1_amd64.deb" \
    "$libbpf_deb" \
    "9989931bc65bba9eb911ed516b8e40ceb5c1ddadc0b64c6bf3ee6792c2a9f0c3dbde23d9b1deed73b446d9a1a84753d69c64669a01c9abf618630feffb13b2cd"
download_sha512 \
    "https://deb.debian.org/debian/pool/main/e/elfutils/libelf-dev_0.188-2.1_amd64.deb" \
    "$libelf_deb" \
    "321ea9802b03296b576d8c33a76fa8a94cf202c1d0887ac1f0542e204e1b8d6278d77b369a2f83a4e4ca2fdaeb8a98296a3091a6cf76dae99a702f63d0dcae1a"
download_sha512 \
    "https://deb.debian.org/debian/pool/main/z/zlib/zlib1g-dev_1.2.13.dfsg-1_amd64.deb" \
    "$zlib_deb" \
    "64179ac18b63c84d385c5d74cda40db28af451bbcc0800c26ca334dc0d18a1d10233945a6b57cb1b26cbf0fe7c47e4bb4cfd530d741fe09e5d8da0f070dc4d16"
download_sha512 \
    "https://deb.debian.org/debian/pool/main/libz/libzstd/libzstd-dev_1.5.4%2bdfsg2-5_amd64.deb" \
    "$zstd_deb" \
    "dca8acad9c3e612940d5417a8868920230d55ce2b812db53a0f7f4d3889f42c978986ae9aebcbb1aba4567251ca50bc63ec84e71b246f2e1866b94d2fed82316"

deps_staging=$(mktemp -d "$toolchain_root/deps.x86_64.XXXXXX")
for package in "$libbpf_deb" "$libelf_deb" "$zlib_deb" "$zstd_deb"; do
    dpkg-deb --extract "$package" "$deps_staging"
done

library_dir="$deps_staging/usr/lib/x86_64-linux-gnu"
for archive in libbpf.a libelf.a libz.a libzstd.a; do
    test -f "$library_dir/$archive" || {
        echo "bootstrap archive missing: $archive" >&2
        exit 1
    }
done
test -f "$deps_staging/usr/include/bpf/libbpf.h"

rm -rf "$deps_dir"
mkdir -p "$(dirname -- "$deps_dir")"
mv "$deps_staging" "$deps_dir"

echo "build dependencies ready under $toolchain_root"
