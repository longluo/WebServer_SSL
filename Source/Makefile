#******************************************************************************
#
# Makefile - Rules for building the SSL web server using lwIP and MatrixSSL.
#
#******************************************************************************

#
# Defines the part type that this project uses.
#
PART=LM3S8962

#
# The base directory for the project.
#
ROOT=.

#
# Include the common make definitions.
#
include ${ROOT}/makedefs

#
# Where to find source files that do not live in this directory.
#
VPATH=./App/Src
VPATH+=./HAL
VPATH+=./HAL/Oled/Src
VPATH+=./HAL/IO/Src
VPATH+=./lwipConfig
#VPATH+=./lwip-1.3.2/apps/httpserver_raw
#VPATH+=./lwip-1.3.2/ports/stellaris
#VPATH+=./lwip-1.3.2/ports/stellaris/netif
#VPATH+=./lwip-1.3.2/arch
#VPATH+=./lwip-1.3.2/src/api
#VPATH+=./lwip-1.3.2/src/core
#VPATH+=./lwip-1.3.2/src/core/ipv4
#VPATH+=./lwip-1.3.2/src/core/snmp
#VPATH+=./lwip-1.3.2/src/netif
#VPATH+=./lwip-1.3.2/src/netif/ppp
VPATH+=./MatrixSSL/src
VPATH+=./MatrixSSL/src/crypto/peersec
VPATH+=./MatrixSSL/src/pki
VPATH+=./MatrixSSL/src/os
VPATH+=./MatrixSSL/src/os/no_os
VPATH+=./SSL/Cert
VPATH+=./SSL/Layer/Src
VPATH+=./MemManage
VPATH+=./fatfs/src
VPATH+=./fatfs/port
VPATH+=./Utils/Src
VPATH+=./WebServer


#
# Where to find header files that do not live in the source directory.
#
IPATH=.
IPATH+=./HAL/Oled/Head
IPATH+=./HAL/IO/Head
IPATH+=./LM3S_Lib/inc
IPATH+=./lwipConfig
IPATH+=./lwip-1.3.2/apps
IPATH+=./lwip-1.3.2/apps/httpserver_raw
IPATH+=./lwip-1.3.2/ports/stellaris/include
IPATH+=./lwip-1.3.2/src/include
IPATH+=./lwip-1.3.2/src/include/ipv4
IPATH+=./SSL/Layer/Head
IPATH+=./MatrixSSL
IPATH+=./MemManage
IPATH+=./Utils/Head
IPATH+=./WebServer


#
# The default rule, which causes the SSL web server using lwIP and MatrixSSL to be built.
#
all: ${COMPILER}
all: ${COMPILER}/webserver_ssl.axf

#
# The rule to clean out all the build products.
#
clean:
	@rm -rf ${COMPILER} ${wildcard *~}

#
# The rule to create the target directory.
#
${COMPILER}:
	@mkdir ${COMPILER}

#
# Rules for building the SSL web server using lwIP and MatrixSSL.
#
${COMPILER}/webserver_ssl.axf: ${COMPILER}/main.o
#${COMPILER}/webserver_ssl.axf: ${COMPILER}/cgifuncs.o

${COMPILER}/webserver_ssl.axf: ${COMPILER}/startup_${COMPILER}.o
${COMPILER}/webserver_ssl.axf: ${COMPILER}/rit128x96x4.o
${COMPILER}/webserver_ssl.axf: ${COMPILER}/display.o

${COMPILER}/webserver_ssl.axf: ${COMPILER}/lwiplib.o

${COMPILER}/webserver_ssl.axf: ${COMPILER}/cipherSuite.o
${COMPILER}/webserver_ssl.axf: ${COMPILER}/matrixSsl.o
${COMPILER}/webserver_ssl.axf: ${COMPILER}/sslDecode.o
${COMPILER}/webserver_ssl.axf: ${COMPILER}/sslEncode.o
${COMPILER}/webserver_ssl.axf: ${COMPILER}/sslv3.o

${COMPILER}/webserver_ssl.axf: ${COMPILER}/arc4.o
${COMPILER}/webserver_ssl.axf: ${COMPILER}/base64.o
${COMPILER}/webserver_ssl.axf: ${COMPILER}/des3.o
${COMPILER}/webserver_ssl.axf: ${COMPILER}/md2.o
${COMPILER}/webserver_ssl.axf: ${COMPILER}/md5.o
${COMPILER}/webserver_ssl.axf: ${COMPILER}/mpi.o
${COMPILER}/webserver_ssl.axf: ${COMPILER}/rsa.o
${COMPILER}/webserver_ssl.axf: ${COMPILER}/sha1.o

${COMPILER}/webserver_ssl.axf: ${COMPILER}/asn1.o
${COMPILER}/webserver_ssl.axf: ${COMPILER}/rsaPki.o
${COMPILER}/webserver_ssl.axf: ${COMPILER}/x509.o

${COMPILER}/webserver_ssl.axf: ${COMPILER}/no_os.o
${COMPILER}/webserver_ssl.axf: ${COMPILER}/debug.o

${COMPILER}/webserver_ssl.axf: ${COMPILER}/privkeySrv.o
${COMPILER}/webserver_ssl.axf: ${COMPILER}/certSrv.o

${COMPILER}/webserver_ssl.axf: ${COMPILER}/ssl.o

${COMPILER}/webserver_ssl.axf: ${COMPILER}/bget.o

${COMPILER}/webserver_ssl.axf: ${COMPILER}/ff.o
${COMPILER}/webserver_ssl.axf: ${COMPILER}/mmc-ek-lm3s8962.o

${COMPILER}/webserver_ssl.axf: ${COMPILER}/httpsd.o
${COMPILER}/webserver_ssl.axf: ${COMPILER}/lmi_fs.o

${COMPILER}/webserver_ssl.axf: ${COMPILER}/ustdlib.o
${COMPILER}/webserver_ssl.axf: ${COMPILER}/uartstdio.o

${COMPILER}/webserver_ssl.axf: ${ROOT}/LM3S_Lib/DriverLib/libdriver.a

ifeq (${COMPILER}, gcc)
${COMPILER}/webserver_ssl.axf: webserver_ssl.ld
endif

SCATTERgcc_webserver_ssl=webserver_ssl.ld

ifeq (${COMPILER}, sourcerygxx)
${COMPILER}/webserver_ssl.axf: webserver-ssl-ek-lm3s8962_sourcerygxx.ld
endif

SCATTERsourcerygxx_webserver-ssl-ek-lm3s8962=lm3s8962-rom.ld -T webserver-ssl-ek-lm3s8962_sourcerygxx.ld

ENTRY_webserver_ssl=ResetISR
CFLAGSgcc=-DLUMINARY_MICRO
CFLAGSsourcerygxx=-DLUMINARY_MICRO

#
# Include the automatically generated dependency files.
#
ifneq (${MAKECMDGOALS},clean)
-include ${wildcard ${COMPILER}/*.d} __dummy__
endif

