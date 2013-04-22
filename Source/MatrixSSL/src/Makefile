#******************************************************************************
#
# Makefile - Rules for building the MatrixSSL library.
#
# Copyright (c) 2007 Luminary Micro, Inc.  All rights reserved.
# Luminary Micro Confidential - For Use Under NDA Only
#
#******************************************************************************

#
# Defines the part type that this project uses.
#
PART=LM3S6965

#
# The base directory for DriverLib.
#
ROOT=../../../DriverLib

#
# Set the flag we use to pull in Stellaris-specific code
#
CFLAGSgcc = -DLUMINARY_MICRO
CFLAGSewarm = -DLUMINARY_MICRO
CFLAGSsourcerygxx = -DLUMINARY_MICRO
CFLAGSrvmdk = -DLUMINARY_MICRO

#
# Add the MatrixSSL debug switch if performing a debug build.
#
ifneq (${DEBUG},1)
CFLAGSgcc += -DMATRIXSSL_DEBUG=1
CFLAGSewarm += -DMATRIXSSL_DEBUG=1
CFLAGSsourcerygxx += -DMATRIXSSL_DEBUG=1
CFLAGSrvmdk += -DMATRIXSSL_DEBUG=1
endif

#
# Where to find source files that do not live in this directory.
#
VPATH=./crypto
VPATH+=./crypto/peersec
VPATH+=./os
VPATH+=./os/no_os
VPATH+=./pki

#
# Where to find header files that do not live in the source directory.
#
IPATH=.
IPATH+=./crypto
IPATH+=./crypto/peersec
IPATH+=./os
IPATH+=./pki
IPATH+=${ROOT}

#
# Include the common make definitions.
#
include ${ROOT}/makedefs

#
# The default rule, which causes the Sample web server using lwIP and MatrixSSL. to be built.
#
all: ${COMPILER}
all: ${COMPILER}/libmatrixsslstatic.a

#
# The rule to clean out all the build products.
#
clean:
	@rm -rf ${COMPILER} settings
	@rm -rf ${wildcard *~} ${wildcard *.Bak} ${wildcard *.dep}

#
# The rule to create the target directory.
#
${COMPILER}:
	@mkdir ${COMPILER}

#
# Rules for building the MatrixSSL library.
#
${COMPILER}/libmatrixsslstatic.a: ${COMPILER}/cipherSuite.o
${COMPILER}/libmatrixsslstatic.a: ${COMPILER}/matrixSsl.o
${COMPILER}/libmatrixsslstatic.a: ${COMPILER}/sslDecode.o
${COMPILER}/libmatrixsslstatic.a: ${COMPILER}/sslEncode.o
${COMPILER}/libmatrixsslstatic.a: ${COMPILER}/sslv3.o
${COMPILER}/libmatrixsslstatic.a: ${COMPILER}/debug.o
${COMPILER}/libmatrixsslstatic.a: ${COMPILER}/no_os.o
${COMPILER}/libmatrixsslstatic.a: ${COMPILER}/arc4.o
${COMPILER}/libmatrixsslstatic.a: ${COMPILER}/base64.o
${COMPILER}/libmatrixsslstatic.a: ${COMPILER}/des3.o
${COMPILER}/libmatrixsslstatic.a: ${COMPILER}/md5.o
${COMPILER}/libmatrixsslstatic.a: ${COMPILER}/md2.o
${COMPILER}/libmatrixsslstatic.a: ${COMPILER}/mpi.o
${COMPILER}/libmatrixsslstatic.a: ${COMPILER}/rsa.o
${COMPILER}/libmatrixsslstatic.a: ${COMPILER}/sha1.o
${COMPILER}/libmatrixsslstatic.a: ${COMPILER}/asn1.o
${COMPILER}/libmatrixsslstatic.a: ${COMPILER}/rsaPki.o
${COMPILER}/libmatrixsslstatic.a: ${COMPILER}/x509.o

#
# Include the automatically generated dependency files.
#
ifneq (${MAKECMDGOALS},clean)
-include ${wildcard ${COMPILER}/*.d} __dummy__
endif
