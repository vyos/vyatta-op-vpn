#!/usr/bin/perl
#
# Module: vyatta-show-ipsec-status.pl
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
# Portions created by Vyatta are Copyright (C) 2010 Vyatta, Inc.
# All Rights Reserved.
#
# Author: Mohit Mehta
# Date: March 2010
# Description: vpn ipsec status
#
# **** End License ****
#

use Getopt::Long;
use POSIX;

use lib "/opt/vyatta/share/perl5";
use Vyatta::Config;
use Vyatta::Misc;

use warnings;
use strict;

sub get_vpn_intfs {
  my $config = new Vyatta::Config;
  $config->setLevel('vpn ipsec');
  my @vpn_intfs = ();
  @vpn_intfs  = $config->returnOrigValues('ipsec-interfaces interface');
  my @return = sort(@vpn_intfs);
  return @return;
}

sub get_vpn_all_localips {
  my $config = new Vyatta::Config;
  $config->setLevel('vpn ipsec site-to-site');
  my @local_ips = ();
  my @vpn_peers = ();
  @vpn_peers = $config->listOrigNodes('peer');
  foreach my $peer (@vpn_peers) {
    my $local_ip = $config->returnOrigValue("peer $peer local-address");
    if (!defined($local_ip)){
      my $dhcpif =  $config->returnOrigValue("peer $peer dhcp-interface");
      if (defined($dhcpif)){
        $local_ip = (Vyatta::Misc::getIP($dhcpif, 4))[0];
        if (defined($local_ip)){
          $local_ip = (split(/\//,$local_ip))[0];
        }
      }
      $local_ip = ' ' if !defined($local_ip);
    }
    push @local_ips, $local_ip;
  }
  return @local_ips;
}

sub relate_intfs_with_localips {
  my @vpn_intfs = get_vpn_intfs();
  my @peer_localips = get_vpn_all_localips();

  if ((scalar @vpn_intfs) > 0) {
    foreach my $intf (@vpn_intfs) {
      print "\t$intf\t";
      my @intf_ips = Vyatta::Misc::getIP($intf, 4);
      if ((scalar @intf_ips) > 0) {
        my $ip_found = 0;
        foreach my $local_ip (@peer_localips) {
          if (scalar(grep(/^$local_ip/, @intf_ips)) > 0) {
            print "($local_ip)";
            $ip_found = 1;
            last;
          }
        }
        if ($ip_found == 0) {
          print "(no IP on interface statically configured as local-ip for any VPN peer)";
        }
        print "\n";
      } else {
        print "( )";
      }
    }
  }
}

#
# main
#

my $process_id = `sudo cat /var/run/charon.pid`;
my $active_tunnels = `sudo ipsec status 2>/dev/null | grep 'newest IPsec SA: #' | grep -v 'newest IPsec SA: #0' | wc -l`;
chomp $process_id;
chomp $active_tunnels;
my @vpn_interfaces = get_vpn_intfs();
my @peer_local_ips = get_vpn_all_localips();

print "IPSec Process Running PID: $process_id\n";
print "\n$active_tunnels Active IPsec Tunnels\n";
print "\nIPsec Interfaces :\n";
relate_intfs_with_localips();

exit 0;

# end of file
