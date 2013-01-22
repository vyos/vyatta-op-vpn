opdir		 = $(datadir)/vyatta-op/templates

bin_sudo_usersdir = $(bindir)/sudo-users
share_perl5dir	 = $(datarootdir)/perl5/Vyatta/VPN
share_perl5_vpnprofdir   = $(datarootdir)/perl5/Vyatta/vpnprof

share_perl5_DATA = lib/OPMode.pm
share_perl5_vpnprof_DATA = lib/vpnprof/OPMode.pm

bin_sudo_users_SCRIPTS = scripts/gen_local_rsa_key.pl
bin_sudo_users_SCRIPTS += scripts/vyatta-show-vpn.pl
bin_sudo_users_SCRIPTS += scripts/vyatta-vpn-op.pl
bin_sudo_users_SCRIPTS += scripts/vyatta-op-vpn.pl
bin_sudo_users_SCRIPTS += scripts/vyatta-op-vpnprof.pl
bin_sudo_users_SCRIPTS += scripts/vyatta-show-ipsec-status.pl

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
	cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)/opt/vyatta/etc/
	mkdir -p $(DESTDIR)/opt/vyatta/sbin/
	cp scripts/vyatta-gen-x509-keypair.sh $(DESTDIR)/opt/vyatta/sbin
	cp scripts/key-pair.template $(DESTDIR)/opt/vyatta/etc
	mkdir -p $(DESTDIR)$(opdir)
	cd templates; $(cpiop) $(DESTDIR)$(opdir)


