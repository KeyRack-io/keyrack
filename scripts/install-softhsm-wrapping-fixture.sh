#!/usr/bin/env bash
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
# Install the exact, unpatched native wrapping fixture into a new private prefix.
set -euo pipefail

if [[ $# != 1 || "$1" != /* || "$1" == / || -e "$1" || -L "$1" ]]; then
    echo "Usage: $0 /absolute/new/fixture-prefix (must not already exist)" >&2
    exit 1
fi
[[ $(uname -s) == Linux ]] || {
    echo "This fixture installer requires Linux and OpenSSL 3." >&2
    exit 1
}
fixture_prefix=$1
source_url=https://github.com/softhsm/SoftHSMv2/archive/refs/tags/2.7.0.tar.gz
source_sha256=be14a5820ec457eac5154462ffae51ba5d8a643f6760514d4b4b83a77be91573
for tool in curl sha256sum tar autoconf automake libtoolize pkg-config make g++ ldd; do
    command -v "$tool" >/dev/null || { echo "Required build tool missing: $tool" >&2; exit 1; }
done
crypto_version=$(pkg-config --modversion libcrypto)
[[ "$crypto_version" == 3.* ]] || {
    echo "The qualified fixture requires OpenSSL 3; found $crypto_version." >&2
    exit 1
}

build_directory=$(mktemp -d "${TMPDIR:-/tmp}/keyrack-softhsm-build.XXXXXXXX")
trap 'rm -rf -- "$build_directory"' EXIT
curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
    "$source_url" --output "$build_directory/source.tar.gz"
printf '%s  %s\n' "$source_sha256" "$build_directory/source.tar.gz" | sha256sum --check --strict
tar -xzf "$build_directory/source.tar.gz" -C "$build_directory"
cd "$build_directory/SoftHSMv2-2.7.0"
# No patches and no changes to system trust or token configuration.
./autogen.sh
./configure --prefix="$fixture_prefix" \
    --libdir="$fixture_prefix/lib" \
    --sysconfdir="$fixture_prefix/etc" --localstatedir="$fixture_prefix/var" \
    --disable-gost --with-crypto-backend=openssl
make -j2
make install

module_path="$fixture_prefix/lib/softhsm/libsofthsm2.so"
installed_version=$("$fixture_prefix/bin/softhsm2-util" --version)
[[ "$installed_version" == 2.7.0 ]] || {
    echo "Expected SoftHSM 2.7.0; installed $installed_version." >&2
    exit 1
}
[[ -f "$module_path" ]] || {
    echo "Expected installed native module missing: $module_path" >&2
    exit 1
}
ldd "$module_path" | grep -F 'libcrypto.so.3' >/dev/null || {
    echo "Installed module is not linked to OpenSSL 3." >&2
    exit 1
}
{
    printf 'source_url=%s\nsource_sha256=%s\nopenssl_version=%s\n' \
        "$source_url" "$source_sha256" "$crypto_version"
    printf 'softhsm_version=%s\n' "$("$fixture_prefix/bin/softhsm2-util" --version)"
    printf 'configure_flags=%s\n' '--disable-gost --with-crypto-backend=openssl'
    sha256sum "$module_path"
    ldd "$module_path"
} > "$fixture_prefix/BUILD-MANIFEST.txt"
cat "$fixture_prefix/BUILD-MANIFEST.txt"
printf 'Set PATH=%s/bin:$PATH and KMS_PKCS11_LIB=%s\n' "$fixture_prefix" "$module_path"
