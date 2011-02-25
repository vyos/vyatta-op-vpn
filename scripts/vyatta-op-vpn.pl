#!/usr/bin/perl
#
# Module: vyatta-op-vpn.pl
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
# Portions created by Vyatta are Copyright (C) 2008 Vyatta, Inc.
# All Rights Reserved.
#
# Author: John Southworth
# Date: January 2011
# Description: Script to execute op-mode commands for IPSEC VPN
#
# **** End License ****
#
use Getopt::Long;
use Data::Dumper;
use lib "/opt/vyatta/share/perl5/";
use Vyatta::VPN::OPMode;

use strict;

my ($get_peers_for_cli, $get_conn_for_cli, $show_ipsec_sa, $show_ipsec_sa_detail,
    $show_ipsec_sa_peer, $show_ipsec_sa_peer_detail, $show_ipsec_sa_natt, 
    $show_ipsec_sa_stats, $show_ipsec_sa_stats_peer, $show_ike_sa, 
    $show_ike_sa_peer, $show_ike_sa_natt, $show_ike_secrets, $show_ike_status);
my @show_ipsec_sa_stats_conn;
my @show_ipsec_sa_conn_detail;
my @show_ipsec_sa_conn;

GetOptions("show-ipsec-sa!"                 => \$show_ipsec_sa,
           "show-ipsec-sa-detail!"          => \$show_ipsec_sa_detail,
           "get-peers-for-cli!"             => \$get_peers_for_cli,
           "get-conn-for-cli=s"             => \$get_conn_for_cli,
           "show-ipsec-sa-peer=s"           => \$show_ipsec_sa_peer,
           "show-ipsec-sa-peer-detail=s"    => \$show_ipsec_sa_peer_detail,
           "show-ipsec-sa-natt!"            => \$show_ipsec_sa_natt,
           "show-ipsec-sa-stats!"           => \$show_ipsec_sa_stats,
           "show-ipsec-sa-stats-peer=s"     => \$show_ipsec_sa_stats_peer,
           "show-ipsec-sa-stats-conn=s{2}"  => \@show_ipsec_sa_stats_conn,
           "show-ipsec-sa-conn-detail=s{2}" => \@show_ipsec_sa_conn_detail,
           "show-ipsec-sa-conn=s{2}"        => \@show_ipsec_sa_conn,
           "show-ike-sa!"                   => \$show_ike_sa,
           "show-ike-sa-peer=s"             => \$show_ike_sa_peer,
           "show-ike-sa-natt!"              => \$show_ike_sa_natt,
           "show-ike-status!"               => \$show_ike_status,
           "show-ike-secrets!"              => \$show_ike_secrets);

if (defined $get_peers_for_cli) {
  Vyatta::VPN::OPMode::get_peers_for_cli;
}
if (defined $get_conn_for_cli) {
  Vyatta::VPN::OPMode::get_conn_for_cli($get_conn_for_cli);
}
if (defined $show_ipsec_sa) {
  Vyatta::VPN::OPMode::show_ipsec_sa;
}
if (defined $show_ipsec_sa_detail) {
  Vyatta::VPN::OPMode::show_ipsec_sa_detail;
}
if (defined $show_ipsec_sa_peer) {
  Vyatta::VPN::OPMode::show_ipsec_sa_peer($show_ipsec_sa_peer);
}
if (defined $show_ipsec_sa_peer_detail) {
  Vyatta::VPN::OPMode::show_ipsec_sa_peer_detail($show_ipsec_sa_peer_detail);
}
if (defined @show_ipsec_sa_conn_detail) {
  Vyatta::VPN::OPMode::show_ipsec_sa_conn_detail(@show_ipsec_sa_conn_detail);
}
if (defined @show_ipsec_sa_conn) {
  Vyatta::VPN::OPMode::show_ipsec_sa_conn(@show_ipsec_sa_conn);
}
if (defined $show_ipsec_sa_natt) {
  Vyatta::VPN::OPMode::show_ipsec_sa_natt;
}
if (defined $show_ipsec_sa_stats) {
  Vyatta::VPN::OPMode::show_ipsec_sa_stats;
}
if (defined $show_ipsec_sa_stats_peer) {
  Vyatta::VPN::OPMode::show_ipsec_sa_stats_peer($show_ipsec_sa_stats_peer);
}
if (defined @show_ipsec_sa_stats_conn) {
  Vyatta::VPN::OPMode::show_ipsec_sa_stats_conn(@show_ipsec_sa_stats_conn);
}
if (defined $show_ike_sa) {
  Vyatta::VPN::OPMode::show_ike_sa;
}
if (defined $show_ike_status) {
  Vyatta::VPN::OPMode::show_ike_status;
}
if (defined $show_ike_sa_peer) {
  Vyatta::VPN::OPMode::show_ike_sa_peer($show_ike_sa_peer);
}
if (defined $show_ike_sa_natt) {
  Vyatta::VPN::OPMode::show_ike_sa_natt;
}
if (defined $show_ike_secrets) {
  Vyatta::VPN::OPMode::show_ike_secrets;
}
