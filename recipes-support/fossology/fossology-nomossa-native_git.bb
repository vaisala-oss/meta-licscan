SUMMARY = "Fossology's stand-alone nomos license scanner"
HOMEPAGE = "https://github.com/fossology/fossology"
SECTION = "console/utils"
LICENSE = "GPL-2.0-only"
LIC_FILES_CHKSUM = "file://GenCodeCopyright;md5=7296ec131dbd040718b64fb843d63048"
DEPENDS = "\
    coreutils-native \
    glib-2.0-native \
    pkgconfig-native \
    quilt-native \
    util-linux-native \
"
PROVIDES = "nomossa-native"

SRCREV = "45e65419e11f229cd21985c256aa7f9959a52e30"
PV = "3.4.0+git${SRCPV}"

SRC_URI = "\
    git://github.com/fossology/fossology.git;branch=master;subpath=src/nomos/agent \
    file://0001-Makefile-sa-relocate-makefile-conf.patch \
    file://0003-fix-strings-correct-typo.patch;striplevel=4 \
    file://0004-fix-nomos-nomos-crash-1337.patch;striplevel=4 \
    file://0005-feat-licenses-SPDX-identifier-detection-modified-to-.patch;striplevel=4 \
    file://0006-fix-nomos-segfault-for-large-offset-value.patch;striplevel=4 \
    file://0007-fix-nomos-CC-BY-SA-identification.patch;striplevel=4 \
    file://0008-fix-Nomos-Added-a-new-License-signature.patch;striplevel=4 \
    file://0009-feat-nomos-Apache-detection.patch;striplevel=4 \
    file://0010-feat-nomos-add-new-license-intel-binary.patch;striplevel=4 \
    file://0011-Nomos-New-licenses-from-SPDX-3.10-added.-Lots-of-oth.patch;striplevel=4 \
"

S = "${WORKDIR}/agent"

inherit native

EXTRA_OEMAKE = "-f Makefile.sa"

CC:append = " ${BUILD_LDFLAGS}"

do_configure:prepend() {
    printf 'DEFS = -DVERSION_S=\\"%s\\" -DCOMMIT_HASH_S=\\"%s\\"' \
        "$(printf '%s' ${PV} | awk -F'+' '{ print $1 }')" \
        "$(git rev-parse --short ${SRCREV})" \
        > ${S}/Makefile.conf
}

do_install() {
    install -d ${D}${bindir}
    install -m 0755 ${S}/nomossa ${D}${bindir}/
}

PARALLEL_MAKE = ""
