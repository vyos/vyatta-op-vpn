#!/usr/bin/perl -w
#
# Module: vyatta_show_vpn.pl
# 
# **** License ****
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
# 
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2006, 2007 Vyatta, Inc.
# All Rights Reserved.
# 
# Author: Stig Thormodsrud
# Date: 2007
# Description: Utility to show various vpn values
# 
# **** End License ****
# 

use strict;
use warnings;

use lib "/opt/vyatta/share/perl5/";

my $arg0 = $ARGV[0];
if (!defined($arg0)) {
    die "Please specify either 'secrets' or 'rsa-keys'.\n";
}

if ($arg0 eq 'secrets') {
    my $secret_file = '/etc/ipsec.secrets';
    unless ( -r $secret_file) {
	die "No secrets file $secret_file\n";
    }
    open(DAT, $secret_file);
    my @raw_data=<DAT>;
    close(DAT);
    print "Local             Peer              Secret\n";
    print "--------          -------           ------\n";
    foreach my $line (@raw_data) {
	if ($line =~ /PSK/) {
	    my ($lip, $pip, $secret) = $line =~ /^(\S+)\s+(\S+)\s+\:\s+PSK\s+(\"\S+\")/;
	    printf "%-15s   %-15s   %s\n", $lip, $pip, $secret;
	}
    }
    exit 0;
}



if ($arg0 eq 'rsa-keys') {
    use Vyatta::VPNUtil;
    my $key_file = Vyatta::VPNUtil::rsa_get_local_key_file();
    unless ( -r $key_file) {
        die "No key file $key_file found.\n";
    }
    my $pubkey = Vyatta::VPNUtil::rsa_get_local_pubkey($key_file);
    if ($pubkey eq 0) {
	die "No local pubkey found.\n";
    }
    print "\nLocal public key ($key_file):\n\n$pubkey\n\n";

    use Vyatta::Config;
    my $vc = new Vyatta::Config();
    $vc->setLevel('vpn');

    my @peers = $vc->listOrigNodes('ipsec site-to-site peer');
    foreach my $peer (@peers) {
        my $mode = $vc->returnOrigValue("ipsec site-to-site peer $peer authentication mode");
        if ($mode eq 'rsa') {
            my $rsa_key_name = $vc->returnOrigValue("ipsec site-to-site peer $peer authentication rsa-key-name");
            my $remote_key = $vc->returnOrigValue("rsa-keys rsa-key-name $rsa_key_name rsa-key");
            print "=" x 80, "\n";
            print "Peer: $peer";
            if (defined($rsa_key_name)) {
                print "  ($rsa_key_name)";
            }
            print "\n\n";
            if (defined($remote_key)) {
                print "$remote_key\n";
            }
        }
    }
}

