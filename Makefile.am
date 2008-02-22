opdir		 = $(datadir)/vyatta-op/templates

xsldir          = @XSLDIR@

bin_sudo_usersdir = $(bindir)/sudo-users

xsl_DATA =

bin_sudo_users_SCRIPTS = 

xsl_DATA        += src/xsl/show_vpn_ike_sa.xsl
xsl_DATA	+= src/xsl/show_vpn_ike_secrets.xsl
xsl_DATA	+= src/xsl/show_vpn_ike_status.xsl
xsl_DATA	+= src/xsl/show_vpn_ipsec_sa_statistics.xsl
xsl_DATA	+= src/xsl/show_vpn_ipsec_sa.xsl
xsl_DATA	+= src/xsl/show_vpn_ipsec_status.xsl

bin_sudo_users_PROGRAMS	= command_proc_show_vpn

bin_sudo_users_SCRIPTS	= scripts/gen_local_rsa_key.pl scripts/vyatta-show-vpn.pl scripts/vyatta-show-vpn-debug.pl

command_proc_show_vpn_SOURCES = src/command_proc_base.hh
command_proc_show_vpn_SOURCES += src/command_proc_show_vpn.cc
command_proc_show_vpn_SOURCES += src/command_proc_show_vpn.hh
command_proc_show_vpn_SOURCES += src/rl_str_proc.cc
command_proc_show_vpn_SOURCES += src/rl_str_proc.hh
command_proc_show_vpn_SOURCES += src/xsl_processor.cc
command_proc_show_vpn_SOURCES += src/xsl_processor.hh
command_proc_show_vpn_LDADD = -lsablot


cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
	cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(opdir)
	cd templates; $(cpiop) $(DESTDIR)$(opdir)


