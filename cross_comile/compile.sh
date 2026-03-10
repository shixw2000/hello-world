#!/bin/bash -e

SH_DIR=$(dirname $(realpath -e "$0"))

source ${SH_DIR}/env.sh

## gcc need  mpc, mpfr, gmp
# binutil, glibc
# libtool, gettext, gperf, flex, texinfo
# kernel
##

[ -d ${SRC_DIR} ] || exit 1

echo "====sh_dir=${SH_DIR}==="

function chkret() {
 [ 0 -eq $? ] || { echo "ret=${ret}|"; exit $ret; } 
}

function makedir() {
 local dir
 
 dir="$1"
 [ -n "$dir" ] || return 100
 [ -d "$dir" ] || mkdir "$dir" || ret 101
}

function conf_binutil() {
 makedir "$1" \
&& (cd "$1" && "${SRC_DIR}/$2/configure" \
--prefix= \
--with-build-sysroot=${SYS_DIR}/${SYS_ROOT} \
--with-sysroot=${SYS_ROOT} \
--host=$HOST \
--target=$TARGET \
--enable-targets=${TARGET} \
--enable-languages=c,c++ \
--enable-gold \
--enable-initfini-array \
--enable-plugins \
--disable-nls \
--disable-doc \
--without-python \
--without-x \
--disable-gdb \
--disable-gdbtk \
--disable-tui \
--without-gdb \
--disable-multilib \
--disable-werror) || return 200
}

function install_binutil() {
 (cd "$1" && make DESTDIR="${SYS_DIR}" install) || return 202
}


##
## --with-newlib: use new lib, stage1 need this
#
function conf_gcc_boot() {
 makedir "$1" \
&& (cd "$1" && "${SRC_DIR}/$2/configure" \
--prefix= \
--with-build-sysroot=${SYS_DIR}/${SYS_ROOT} \
--with-sysroot=${SYS_ROOT} \
--host=$HOST \
--target=$TARGET \
--without-headers \
--without-isl \
--without-cloog \
--with-newlib \
--disable-nls \
--disable-multilib \
--enable-checking=yes \
--enable-languages=c,c++ \
--disable-shared \
--disable-threads \
--disable-libatomic \
--disable-libsanitizer \
--disable-decimal-float \
--disable-libquadmath \
--disable-libmudflap \
--disable-libgomp \
--disable-libssp \
--disable-werror) || return 300
}

function make_gcc_boot() {
 (cd "$1" && make -j $2 all-gcc all-target-libgcc) || return 301
}

function install_gcc_boot() {
 (cd "$1" && make DESTDIR="${SYS_DIR}" install-gcc install-target-libgcc) || return 302
}

function build_kernel() {
( cd "$1" \
 && make ARCH=${PROCESSOR} INSTALL_HDR_PATH=${SYS_DIR}/${SYS_ROOT}/usr headers_install ) || return 400
}

##
## ** prefix must be /usr and use DESTDIR to install***
##
function conf_glibc() {
 makedir "$1" \
&& (cd "$1" && "${SRC_DIR}/$2/configure" \
--prefix=/usr \
--host=$TARGET \
--enable-shared \
--disable-multilib \
libc_cv_forced_unwind=yes \
libc_cv_c_cleanup=yes \
libc_cv_ctors_header=yes \
--without-cvs \
--disable-nls \
--without-selinux \
--disable-profile \
--without-cvs \
--without-gd \
--disable-omitfp \
--disable-bounded \
--disable-sanity-checks \
--disable-werror) || return 500
}

function install_glibc() {
 (cd "$1" && make DESTDIR="${SYS_DIR}/${SYS_ROOT}" install) || return 502

#must do this for lib/../lib64 relative path *** 
[ -d "${SYS_DIR}/${SYS_ROOT}/usr/lib" ] || mkdir "${SYS_DIR}/${SYS_ROOT}/usr/lib" || return 503
}

## prefix must be empty as '/' ##
function conf_gcc_full() {
 makedir "$1" \
&& (cd "$1" && "${SRC_DIR}/$2/configure" \
--prefix= \
--with-build-sysroot=${SYS_DIR}/${SYS_ROOT} \
--with-sysroot=${SYS_ROOT} \
--target=$TARGET \
--disable-nls \
--enable-shared \
--disable-multilib \
--enable-checking=yes \
--enable-languages=c,c++ \
--disable-libssp \
--disable-libquadmath \
--disable-libmudflap \
--disable-werror) || return 800
}

function install_gcc_full() {
 (cd "$1" && make DESTDIR="${SYS_DIR}" install) || return 802
}


function conf_libs() {
 makedir "$1" \
&& (cd "$1" && "${SRC_DIR}/$2"/configure \
CC="${SYS_DIR}/bin/$TARGET-gcc" \
CXX="${SYS_DIR}/bin/$TARGET-g++" \
--prefix=/usr/local \
--with-sysroot=${SYS_DIR}/${SYS_ROOT} \
--disable-maintainer-mode \
--host=$TARGET \
--enable-shared) || return 100
}

function make_lib() {
 (cd "$1" && make -j $2) || return 101
}

function install_lib() {
 (cd "$1" && make DESTDIR="${SYS_DIR}/${SYS_ROOT}" install) || return 102
}

## start work ##
function install_all_gcc() {	
 #install binutil
 conf_binutil build_binutil binutils-2.35.2
 make_lib build_binutil 4
 install_binutil build_binutil 

 #install kernel header
 build_kernel "${KERNEL_DIR}/linux-5.14.0-611.5.1.el9_7"

 #install boot gcc
 conf_gcc_boot build_gcc_boot gcc-11.4.0
 make_gcc_boot build_gcc_boot 4
 install_gcc_boot build_gcc_boot

 #install glibc
 conf_glibc build_glibc glibc-2.34
 make_lib build_glibc 4
 install_glibc build_glibc

 #install full gcc
 conf_gcc_full build_gcc_full gcc-11.4.0
 make_lib build_gcc_full 4
 install_gcc_full build_gcc_full
}

## end work ##

##install new libs##
function install_gcc_required() {
 #install gmp first
 conf_libs build_gmp gmp-6.2.0
 make_lib build_gmp 4
 install_lib build_gmp 

 #install mpfr
 conf_libs build_mpfr mpfr-4.1.0
 make_lib build_mpfr 4
 install_lib build_mpfr

 #install mpc
 conf_libs build_mpc mpc-1.3.1
 make_lib build_mpc 4
 install_lib build_mpc 
}

install_all_gcc

"$SYS_DIR/bin/${TARGET}-gcc" --version
echo "=====end====" 
