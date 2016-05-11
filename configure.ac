# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.59)

m4_define([DEFAULT_PREFIX], "/opt/vyatta")

m4_define([VERSION_ID], [m4_esyscmd([
	if test -f .version ; then
	    head -n 1 .version | tr -d \\n
	else
	    echo -n 2.4
	fi])])
AC_INIT([vyatta-op-vpn], VERSION_ID, [maintainers@vyos.net])

test -n "$VYATTA_VERSION" || VYATTA_VERSION=$PACKAGE_VERSION

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([config])
AM_INIT_AUTOMAKE([gnu no-dist-gzip dist-bzip2 subdir-objects])
AC_PREFIX_DEFAULT(DEFAULT_PREFIX)

if test "$prefix" = "NONE" ; then
  XSLDIR="DEFAULT_PREFIX/share/xsl/"
else
  XSLDIR="$prefix/share/xsl/"
fi

AC_PROG_CC
AC_PROG_CXX
AM_PROG_AS
AM_PROG_CC_C_O
AC_PROG_LIBTOOL
AC_PROG_LEX
AC_PROG_YACC

AC_ARG_ENABLE([nostrip],
	AC_HELP_STRING([--enable-nostrip],
	[include -nostrip option during packaging]),
	[NOSTRIP=-nostrip], [NOSTRIP=])

AC_SUBST(NOSTRIP)
AC_SUBST(XSLDIR)

AC_OUTPUT([
	Makefile
	scripts/vyatta-gen-x509-keypair.sh
])


echo "prefix: ${prefix}"
echo "sysconfdir: ${sysconfdir}"
echo "datarootdir: ${datarootdir}"
echo "XSLDIR: ${XSLDIR}"
