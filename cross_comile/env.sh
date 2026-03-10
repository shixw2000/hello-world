
export HOST=
#export HOST=aarch64-none-linux-gnu
#export TARGET=aarch64-none-linux-gnu
#export PROCESSOR=arm64

export TARGET=riscv64-none-linux-gnu
export PROCESSOR=riscv

export BASE=/home/shixw/opt/cross_compile/devep
export SRC_DIR=${BASE}/src
export SYS_DIR=${BASE}/risc-v
export SYS_ROOT=/${TARGET}/sysroot
export KERNEL_DIR=${BASE}/src

export PATH=${SYS_DIR}/bin:/usr/sbin:/usr/bin:/bin:/sbin

export PKG_CONFIG_PATH=${SYS_DIR}/${SYS_ROOT}/usr/local/lib/pkgconfig\
:${SYS_DIR}/${SYS_ROOT}/usr/local/lib64/pkgconfig

export PKG_CONFIG_LIBDIR=${SYS_DIR}/${SYS_ROOT}/usr/local/lib/pkgconfig\
:${SYS_DIR}/${SYS_ROOT}/usr/local/lib64/pkgconfig
