#!/usr/bin/env bash
# static openssl and libssh2 for the os x build of legacyrayd and its helpers:
# x86_64, os x 10.8 and later, against the 10.8 sdk from xcode 4.6.3.
# everything lands in ~/.cache/legacyray-deps next to the armv7 builds.
#
#   scripts/build_deps_mac.sh
set -euo pipefail

THEOS="${THEOS:-$HOME/theos}"
TC="${LR_TC:-${THEOS}/toolchain/linux/iphone/bin}"
SDK="${LR_MAC_SDK:-${THEOS}/sdks/MacOSX10.8.sdk}"
MIN="${LR_MAC_MIN:-10.8}"
DEPS="${LR_DEPS:-${XDG_CACHE_HOME:-$HOME/.cache}/legacyray-deps}"
OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.8}"
LIBSSH2_VERSION="${LIBSSH2_VERSION:-1.11.1}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

[[ -x "${TC}/clang" ]] || { echo "no clang in ${TC}; set THEOS or LR_TC" >&2; exit 1; }
[[ -d "${SDK}" ]] || { echo "no sdk at ${SDK}: extract MacOSX10.8.sdk from Xcode 4.6.3 (see mac/README.md)" >&2; exit 1; }

OSSL_SRC="${DEPS}/src/openssl-${OPENSSL_VERSION}"
SSH2_SRC="${DEPS}/src/libssh2-${LIBSSH2_VERSION}"
if [[ ! -d "${OSSL_SRC}" || ! -d "${SSH2_SRC}" ]]; then
  echo "run scripts/build_deps.sh once first: it fetches the sources" >&2
  exit 1
fi

wrap_cc() {
  cat > "$1" <<W
#!/bin/sh
exec "${TC}/clang" -target x86_64-apple-macosx${MIN} -B "${TC}" -arch x86_64 \\
  -mmacosx-version-min=${MIN} -isysroot "${SDK}" "\$@"
W
  chmod +x "$1"
}

# asserts and debug lines name their source file, and __FILE__ is the path the
# compiler was given: inside this cache, so under the builder's home. these
# flags write the path's last part instead; a compiler without them builds
# the same library, with the paths left in
file_prefix_maps() {
  local cc="$1" flags="" dir
  shift
  for dir in "$@"; do flags+=" -fmacro-prefix-map=${dir}=$(basename "${dir}")"; done
  if "${cc}" ${flags} -E -x c /dev/null -o /dev/null 2>/dev/null; then
    echo "${flags}"
  else
    echo "warning: ${cc} has no -fmacro-prefix-map; source paths stay in" >&2
  fi
}

build_openssl_mac() {
  local prefix="${DEPS}/openssl-mac"
  local marker="${prefix}/.built-${OPENSSL_VERSION}-osx${MIN}-dirs"
  if [[ -f "${marker}" ]]; then echo "openssl mac up to date"; return; fi
  local bld="${DEPS}/build/openssl-mac"
  rm -rf "${bld}" "${prefix}"
  mkdir -p "${bld}" "${prefix}/lib"
  wrap_cc "${bld}/cc"
  echo "==> openssl ${OPENSSL_VERSION} x86_64 (OS X ${MIN}+)"
  (
    cd "${bld}"
    # the aes-ni, avx and sha extension paths are picked at run time, so the
    # same binary is fast on a 2008 core 2 and on a haswell.
    # no-async: makecontext is deprecated on os x and buys nothing here.
    # --prefix and --openssldir only name paths compiled into the library (the
    # files are copied out below, nothing is installed): the default, this
    # cache, put the builder's home into every binary, and openssl looked
    # there for roots on every handshake, which autofs answers slowly under
    # /home on a mac. no-filenames keeps the source paths of its error
    # records out as well
    "${OSSL_SRC}/Configure" darwin64-x86_64-cc \
      "CC=${bld}/cc" "AR=${TC}/llvm-ar" "RANLIB=${TC}/ranlib" \
      no-async no-shared no-dso no-tests no-engine no-ui-console \
      no-docs no-apps no-quic no-comp no-filenames \
      -O2 --prefix=/usr/local/legacyray --openssldir=/usr/local/legacyray/ssl >/dev/null
    make -j"${JOBS}" build_libs >/dev/null
    cp libssl.a libcrypto.a "${prefix}/lib/"
    mkdir -p "${prefix}/include"
    cp -R "${OSSL_SRC}/include/openssl" "${prefix}/include/"
    cp include/openssl/*.h "${prefix}/include/openssl/"
  )
  touch "${marker}"
}

build_libssh2_mac() {
  local prefix="${DEPS}/libssh2-mac"
  local marker="${prefix}/.built-${LIBSSH2_VERSION}-osx${MIN}-dirs"
  if [[ -f "${marker}" ]]; then echo "libssh2 mac up to date"; return; fi
  local bld="${DEPS}/build/libssh2-mac"
  rm -rf "${bld}" "${prefix}"
  mkdir -p "${bld}" "${prefix}"
  wrap_cc "${bld}/cc"
  local maps
  maps="$(file_prefix_maps "${bld}/cc" "${SSH2_SRC}" "${bld}")"
  echo "==> libssh2 ${LIBSSH2_VERSION} x86_64 (OS X ${MIN}+)"
  (
    cd "${bld}"
    "${SSH2_SRC}/configure" --host=x86_64-apple-darwin12 --prefix="${prefix}" \
      CC="${bld}/cc" AR="${TC}/llvm-ar" RANLIB="${TC}/ranlib" \
      CFLAGS="-O2${maps}" CPPFLAGS="-I${DEPS}/openssl-mac/include" \
      LDFLAGS="-L${DEPS}/openssl-mac/lib" LIBS="-lcrypto" \
      --with-crypto=openssl --with-libssl-prefix="${DEPS}/openssl-mac" \
      --disable-shared --enable-static --disable-examples-build \
      --disable-docker-tests --disable-sshd-tests --without-libz >/dev/null
    make -C src -j"${JOBS}" >/dev/null
    make -C src install >/dev/null
    mkdir -p "${prefix}/include"
    cp "${SSH2_SRC}"/include/*.h "${prefix}/include/"
  )
  touch "${marker}"
}

build_openssl_mac
build_libssh2_mac
echo "mac deps ready in ${DEPS}"
