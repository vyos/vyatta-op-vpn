#!/usr/bin/perl -w

use strict;
use lib "/opt/vyatta/share/perl5/";

use Getopt::Long;
my $op='';
GetOptions("op=s" => \$op);

if ($op eq '') {
	die 'No op specified';
}

if ($op eq 'clear-vpn-ipsec-process') {
	system '/usr/sbin/ipsec setup restart';
	exit 0;
}
if ($op eq 'show-vpn-debug') {
	system '/usr/sbin/ipsec auto --status';
	exit 0;
}
if ($op eq 'show-vpn-debug-detail') {
	system '/usr/sbin/ipsec barf';
	exit 0;
}

die "Unknown op: $op";

