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
use lib "/opt/vyatta/share/perl5";
use Data::Dumper;
use Vyatta::Config;
use Getopt::Long;

use strict;

my $statusall = $ARGV[0];
sub get_tunnel_info {
  my $cmd = "sudo ipsec statusall |";
  open(IPSECSTATUS, $cmd);
  my @ipsecstatus = [];
  while(<IPSECSTATUS>){
    push (@ipsecstatus, $_);
  }
  my %tunnel_hash = ();
  foreach my $line (@ipsecstatus) {
    if (($line =~ /\"(peer-.*-tunnel-.*?)\"/)){
      my $connectid = $1;
      $connectid =~ /peer-(.*)-tunnel-(.*)/;
      if (not exists $tunnel_hash{$connectid}){
        $tunnel_hash{$connectid} = {
                  _peerid      => $1,
                  _tunnelnum   => $2,
                  _newestspi   => undef,
                  _newestike   => undef,
                  _encryption  => undef,
                  _hash        => undef,
                  _leftid      => undef,
                  _rightid     => undef,
                  _leftip      => undef,
                  _rightip     => undef,
                  _inspi       => undef,
                  _outspi      => undef,
                  _srcnet      => undef,
                  _dstnet      => undef,
                  _pfsgrp      => undef,
                  _ikeencrypt  => undef,
                  _ikehash     => undef,
                  _dhgrp       => undef,
                  _state       => "down",
                  _inbytes     => undef,
                  _outbytes    => undef,
                  _natt        => 0,
                  _natsrc      => undef,
                  _natdst      => undef,
                  _ikelife     => undef,
                  _ikeexpire   => undef,
                  _lifetime    => undef,
                  _expire      => undef };
      }
      if ($line =~ /IKE.proposal:(.*?)\/(.*?)\/(.*)/){
        $tunnel_hash{$connectid}->{_ikeencrypt} = $1;
        $tunnel_hash{$connectid}->{_ikehash} = $2;
        $tunnel_hash{$connectid}->{_dhgrp} = $3;
      }
      elsif ($line =~ /ESP.proposal:(.*?)\/(.*?)\/(.*)/){
        $tunnel_hash{$connectid}->{_encryption} = $1;
        $tunnel_hash{$connectid}->{_hash} = $2;
        $tunnel_hash{$connectid}->{_pfsgrp} = $3;
        if ($tunnel_hash{$connectid}->{_pfsgrp} eq "<Phase1>"){
          $tunnel_hash{$connectid}->{_pfsgrp} = $tunnel_hash{$connectid}->{_dhgrp};
        }
      }
      elsif ($line =~ /IKE.proposal:(.*)\/(.*)\/(.*)/){
        $tunnel_hash{$connectid}->{_ikeencrypt} = $1;
        $tunnel_hash{$connectid}->{_ikehash} = $2;
        $tunnel_hash{$connectid}->{_dhgrp} = $3;
      }
      elsif ($line =~ /newest ISAKMP SA: (.*); newest IPsec SA: (.*);/){
        $tunnel_hash{$connectid}->{_newestike} = $1;
        $tunnel_hash{$connectid}->{_newestspi} = $2;
      }
      elsif ($line =~ /ike_life: (.*?)s; ipsec_life: (.*?)s;/){
        $tunnel_hash{$connectid}->{_ikelife} = $1;
        $tunnel_hash{$connectid}->{_lifetime} = $2;
      }
      my $ike = $tunnel_hash{$connectid}->{_newestike};
      if (defined($ike)){
        if ($line =~ /$ike:.*ISAKMP.SA.established.*EVENT_SA_REPLACE.in.(.*?)s;/){
          $tunnel_hash{$connectid}->{_ikeexpire} = $1;
          my $atime = $tunnel_hash{$connectid}->{_ikelife} - $tunnel_hash{$connectid}->{_ikeexpire};
          if ($atime >= 0){
            $tunnel_hash{$connectid}->{_state} = "up";
          }
        }
      }
      my $spi = $tunnel_hash{$connectid}->{_newestspi};
      if (defined($spi)){
        if ($line =~ /$spi:.*esp.(.*)\@.*\((.*bytes).*esp.(.*)\@.*\((.*bytes)/)
        {
          $tunnel_hash{$connectid}->{_inspi} = $1;
          $tunnel_hash{$connectid}->{_inbytes} = $2;
          $tunnel_hash{$connectid}->{_outspi} = $3;
          $tunnel_hash{$connectid}->{_outbytes} = $4;
        }
        if ($line =~ /$spi:.*?EVENT_SA_REPLACE in (.*?)s;/){
          $tunnel_hash{$connectid}->{_expire} = $1;
          my $atime = $tunnel_hash{$connectid}->{_lifetime} - $tunnel_hash{$connectid}->{_expire};
          if ($atime >= 0){
            $tunnel_hash{$connectid}->{_state} = "up";
          } 
        }
      }
    }
  }
  for my $connectid ( keys %tunnel_hash) {
    (my $peer, my $tunid) = ($connectid =~ /peer-(.*)-tunnel-(.*)/);
    my $config = new Vyatta::Config;
    my $peerip = $peer;
    $config->setLevel('vpn ipsec site-to-site');
    $tunnel_hash{$connectid}->{_leftid}  = $config->returnValue("peer $peer authentication id");
    $tunnel_hash{$connectid}->{_rightid} = $config->returnValue("peer $peer authentication remote-id");
    $tunnel_hash{$connectid}->{_leftip}  = $config->returnValue("peer $peer local-ip");
    $tunnel_hash{$connectid}->{_srcnet}  = $config->returnValue("peer $peer tunnel $tunid local-subnet");
    $tunnel_hash{$connectid}->{_dstnet}  = $config->returnValue("peer $peer tunnel $tunid remote-subnet");
    if ($peerip =~ /\@.*/){
      $peerip = "0.0.0.0";
    } elsif ($peerip =~ /"any"/){
      $peerip = "0.0.0.0";
    }
    my $cmd = "sudo setkey -D |";
    open(SETKEY, $cmd);
    my @setkey = [];
    while(<SETKEY>){
      push (@setkey, $_);
    }
    foreach my $line (@setkey){
      if ($line =~ /$tunnel_hash{$connectid}->{_leftip}\[(.*?)\].*?$peerip\[(.*?)\]/){
        $tunnel_hash{$connectid}->{_natt} = 1;
        $tunnel_hash{$connectid}->{_natsrc} = $1;
        $tunnel_hash{$connectid}->{_natdst} = $2;
      }
    }
  }
  for my $peer ( keys %tunnel_hash ) {
    for my $key ( keys %{$tunnel_hash{$peer}} ) {
      if (!defined %{$tunnel_hash{$peer}}->{$key}){
         %{$tunnel_hash{$peer}}->{$key}= "N/A";
      }
    }
  }
  return %tunnel_hash;
}
#print Dumper \%tunnel_hash;

sub get_peers_for_cli
{
    my %tunnel_hash = get_tunnel_info();
    my %tmphash = ();
    my $peerid = pop(@_);
    for my $peer ( keys %tunnel_hash ) {
      for my $key ( keys %{$tunnel_hash{$peer}} ) {
        if ($key eq "_rightid"){
          print %{$tunnel_hash{$peer}}->{$key}."\n"
        }
      }
    }
}

sub show_ipsec_sa
{
    my %tunnel_hash = get_tunnel_info();
    display_ipsec_sa_brief(\%tunnel_hash);
}
sub show_ipsec_sa_detail
{
    my %tunnel_hash = get_tunnel_info();
    display_ipsec_sa_detail(\%tunnel_hash);
}

sub show_ipsec_sa_peer
{
    my %tunnel_hash = get_tunnel_info();
    my %tmphash = ();
    my $peerid = pop(@_);
    for my $peer ( keys %tunnel_hash ) {
      for my $key ( keys %{$tunnel_hash{$peer}} ) {
        if ($key eq "_rightid"){
          if (%{$tunnel_hash{$peer}}->{$key} eq $peerid){
             $tmphash{$peer} = \%{$tunnel_hash{$peer}};
          }
        }
      }
    }
    display_ipsec_sa_brief(\%tmphash);

}
sub show_ipsec_sa_stats_peer
{
    my %tunnel_hash = get_tunnel_info();
    my %tmphash = ();
    my $peerid = pop(@_);
    for my $peer ( keys %tunnel_hash ) {
      for my $key ( keys %{$tunnel_hash{$peer}} ) {
        if ($key eq "_rightid"){
          if (%{$tunnel_hash{$peer}}->{$key} eq $peerid){
             $tmphash{$peer} = \%{$tunnel_hash{$peer}};
          }
        }
      }
    }
    display_ipsec_sa_stats(\%tmphash);

}

sub show_ipsec_sa_peer_detail
{
    my %tunnel_hash = get_tunnel_info();
    my %tmphash = ();
    my $peerid = pop(@_);
    for my $peer ( keys %tunnel_hash ) {
      for my $key ( keys %{$tunnel_hash{$peer}} ) {
        if ($key eq "_rightid"){
          if (%{$tunnel_hash{$peer}}->{$key} eq $peerid){
             $tmphash{$peer} = \%{$tunnel_hash{$peer}};
          }
        }
      }
    }
    display_ipsec_sa_detail(\%tmphash);

}

sub show_ipsec_sa_natt
{
    my %tunnel_hash = get_tunnel_info();
    my %tmphash = ();
    for my $peer ( keys %tunnel_hash ) {
      for my $key ( keys %{$tunnel_hash{$peer}} ) {
        if ($key eq "_natt"){
          if (%{$tunnel_hash{$peer}}->{$key} == 1 ){
             $tmphash{$peer} = \%{$tunnel_hash{$peer}};
          }
        }
      }
    }
    display_ipsec_sa_brief(\%tmphash);

}

sub show_ike_sa
{
    my %tunnel_hash = get_tunnel_info();
    display_ike_sa_brief(\%tunnel_hash);
}

sub show_ipsec_sa_stats
{
     my %tunnel_hash = get_tunnel_info();
     display_ipsec_sa_stats(\%tunnel_hash);
}

sub show_ike_sa_peer
{
    my %tunnel_hash = get_tunnel_info();
    my %tmphash = ();
    my $peerid = pop(@_);
    for my $peer ( keys %tunnel_hash ) {
      for my $key ( keys %{$tunnel_hash{$peer}} ) {
        if ($key eq "_rightid"){
          if (%{$tunnel_hash{$peer}}->{$key} eq $peerid ){
             $tmphash{$peer} = \%{$tunnel_hash{$peer}};
          }
        }
      }
    }
    display_ike_sa_brief(\%tmphash);

}

sub show_ike_sa_natt
{
    my %tunnel_hash = get_tunnel_info();
    my %tmphash = ();
    for my $peer ( keys %tunnel_hash ) {
      for my $key ( keys %{$tunnel_hash{$peer}} ) {
        if ($key eq "_natt"){
          if (%{$tunnel_hash{$peer}}->{$key} == 1 ){
             $tmphash{$peer} = \%{$tunnel_hash{$peer}};
          }
        }
      }
    }
    display_ike_sa_brief(\%tmphash);

}

sub show_ike_secrets
{
    print "show ike secrets\n";
}


sub display_ipsec_sa_brief
{
    my %tunnel_hash = %{pop(@_)};
    #print Dumper \@_;
    print <<EOH;
Peer            Tunnel# Dir SPI       Encrypt   Hash      NAT-T A-Time L-Time
-------         ------- --- --------  -------   ----      ----- ------ ------
EOH
    for my $peer ( keys %tunnel_hash){
      my $peerid = "";
      if ($tunnel_hash{$peer}->{_rightid} ne "N/A"){
        $peerid = $tunnel_hash{$peer}->{_rightid};
      } else {
        $peerid = $tunnel_hash{$peer}->{_peerid};
      }
      my $tunnum = $tunnel_hash{$peer}->{_tunnelnum};
      my $io =  "in";
      my $inspi = $tunnel_hash{$peer}->{_inspi};
      my $outspi = $tunnel_hash{$peer}->{_outspi};
      my $enc = "N/A";
      my $hash = "N/A";
      my $natt = "";
      if ($tunnel_hash{$peer}->{_encryption} =~ /(.*?)_.*?_(.*)/){
        $enc = lc($1).$2;
        $enc =~ s/^ //g;
      }
      if ($tunnel_hash{$peer}->{_hash} =~ /.*_(.*)/){
        $hash = lc($1);
      }
      if ($tunnel_hash{$peer}->{_natt} == 0){
        $natt = "no";
      } else {
        $natt = "yes";
      }
      my $lifetime = $tunnel_hash{$peer}->{_lifetime};
      my $expire = $tunnel_hash{$peer}->{_expire};
      my $atime = $lifetime - $expire;
      printf "%-15s %-7s %-3s %-9s %-9s %-9s %-5s %-6s %-6s\n",
              substr($peerid,0,14), $tunnum, $io, $inspi, $enc, $hash, $natt, $atime, $lifetime;
      $io = "out";
      printf "%-15s %-7s %-3s %-9s %-9s %-9s %-5s %-6s %-6s\n",
              substr($peerid,0,14), $tunnum, $io, $outspi, $enc, $hash, $natt, $atime, $lifetime;
    }
}

sub display_ipsec_sa_detail 
{
    my %tunnel_hash = %{pop(@_)};
    for my $peer ( keys %tunnel_hash){
      print "----------\n";
      my $peerid = "";
      if ($tunnel_hash{$peer}->{_rightid} ne "N/A"){
        $peerid = $tunnel_hash{$peer}->{_rightid};
      } else {
        $peerid = $tunnel_hash{$peer}->{_peerid};
      }
      my $enc = "N/A";
      my $hash = "N/A";
      my $natt = "";
      if ($tunnel_hash{$peer}->{_encryption} =~ /(.*?)_.*?_(.*)/){
        $enc = lc($1).$2;
        $enc =~ s/^ //g;
      }
      if ($tunnel_hash{$peer}->{_hash} =~ /.*_(.*)/){
        $hash = lc($1);
      }
      if ($tunnel_hash{$peer}->{_natt} == 0){
        $natt = "no";
      } else {
        $natt = "yes";
      }
      my $dh_group = "";
      if ($tunnel_hash{$peer}->{_dhgrp} eq "MODP_768"){
        $dh_group = 1;
      }
      elsif ($tunnel_hash{$peer}->{_dhgrp} eq "MODP_1024"){
        $dh_group = 2;
      }
      elsif ($tunnel_hash{$peer}->{_dhgrp} eq "MODP_1536"){
        $dh_group = 5;
      }
      elsif ($tunnel_hash{$peer}->{_dhgrp} eq "MODP_2048"){
        $dh_group = 7;
      }
      elsif ($tunnel_hash{$peer}->{_dhgrp} eq "<N/A>"){
        $dh_group = "N/A";
      }
      else {
        $dh_group = $tunnel_hash{$peer}->{_dhgrp};
      }
      my $pfs_group = "";
      if ($tunnel_hash{$peer}->{_pfsgrp} eq "MODP_768"){
        $pfs_group = 1;
      }
      elsif ($tunnel_hash{$peer}->{_pfsgrp} eq "MODP_1024"){
        $pfs_group = 2;
      }
      elsif ($tunnel_hash{$peer}->{_pfsgrp} eq "MODP_1536"){
        $pfs_group = 5;
      }
      elsif ($tunnel_hash{$peer}->{_pfsgrp} eq "MODP_2048"){
        $pfs_group = 7;
      }
      elsif ($tunnel_hash{$peer}->{_pfsgrp} eq "<N/A>"){
        $pfs_group = "N/A";
      }
      else {
        $pfs_group = $tunnel_hash{$peer}->{_pfsgrp};
      }
      my $lifetime = $tunnel_hash{$peer}->{_lifetime};
      my $expire = $tunnel_hash{$peer}->{_expire};
      my $atime = $lifetime - $expire;

      print "Conn Name:\t\t$peer\n";
      print "State:\t\t\t$tunnel_hash{$peer}->{_state}\n";
      print "Peer:\t\t\t$peerid\n";
      print "Direction:\t\tin\n";
      print "Source Net:\t\t$tunnel_hash{$peer}->{_dstnet}\n";
      print "Dest Net:\t\t$tunnel_hash{$peer}->{_srcnet}\n";
      print "SPI:\t\t\t$tunnel_hash{$peer}->{_inspi}\n";
      print "Encryption:\t\t$enc\n";
      print "Hash:\t\t\t$hash\n";
      print "PFS Group:\t\t$pfs_group\n";
      print "DH Group:\t\t$dh_group\n";
      print "NAT Traversal:\t\t$natt\n";
      print "NAT Source Port:\t$tunnel_hash{$peer}->{_natsrc}\n";
      print "Nat Dest Port:\t\t$tunnel_hash{$peer}->{_natdst}\n";
      print "Bytes:\t\t\t$tunnel_hash{$peer}->{_inbytes}\n";
      print "Active Time (s):\t$atime\n";
      print "Lifetime (s):\t\t$tunnel_hash{$peer}->{_lifetime}\n";
      print "\n";

      print "Conn Name:\t\t$peer\n";
      print "State:\t\t\t$tunnel_hash{$peer}->{_state}\n";
      print "Peer:\t\t\t$peerid\n";
      print "Direction:\t\tout\n";
      print "Source Net:\t\t$tunnel_hash{$peer}->{_srcnet}\n";
      print "Dest Net:\t\t$tunnel_hash{$peer}->{_dstnet}\n";
      print "SPI:\t\t\t$tunnel_hash{$peer}->{_outspi}\n";
      print "Encryption:\t\t$enc\n";
      print "Hash:\t\t\t$hash\n";
      print "PFS Group:\t\t$pfs_group\n";
      print "DH Group:\t\t$dh_group\n";
      print "NAT Traversal:\t\t$natt\n";
      print "NAT Source Port:\t$tunnel_hash{$peer}->{_natsrc}\n";
      print "Nat Dest Port:\t\t$tunnel_hash{$peer}->{_natdst}\n";
      print "Bytes:\t\t\t$tunnel_hash{$peer}->{_outbytes}\n";
      print "Active Time (s):\t$atime\n";
      print "Lifetime (s):\t\t$tunnel_hash{$peer}->{_lifetime}\n";
      print "\n";
    }
}

sub display_ipsec_sa_stats
{
    print <<EOH;
Peer            Dir SRC Network        DST Network        Bytes
-------         --- -----------        -----------        -----
EOH
    my %tunnel_hash = %{pop(@_)};
    for my $peer ( keys %tunnel_hash){
      my $peerid = "";
      my $srcnet = "";
      my $dstnet = "";
      my $inbytes = "";
      my $outbytes = "";
      my $io = "in";
      if ($tunnel_hash{$peer}->{_rightid} ne "N/A"){
        $peerid = $tunnel_hash{$peer}->{_rightid};
      } else {
        $peerid = $tunnel_hash{$peer}->{_peerid};
      }
      $srcnet = $tunnel_hash{$peer}->{_srcnet};
      $dstnet = $tunnel_hash{$peer}->{_dstnet};
      $inbytes = $tunnel_hash{$peer}->{_inbytes};
      $outbytes = $tunnel_hash{$peer}->{_outbytes};

      printf "%-15s %-3s %-18s %-18s %-5s\n",
            substr($peerid,0,14), $io, $dstnet, $srcnet, $inbytes;
      $io = "out";
      printf "%-15s %-3s %-18s %-18s %-5s\n",
            substr($peerid,0,14), $io, $srcnet, $dstnet, $outbytes;
  }
}

sub display_ike_sa_brief
{
    my %tunnel_hash = %{pop(@_)};
    print <<EOH;
Local           Peer            State     Encrypt   Hash     NAT-T A-Time L-Time
--------        -------         -----     -------   ----     ----- ------ ------
EOH
    for my $peer ( keys %tunnel_hash){
      my $peerid = "";
      my $myid = "";
      if ($tunnel_hash{$peer}->{_rightid} ne "N/A"){
        $peerid = $tunnel_hash{$peer}->{_rightid};
      } else {
        $peerid = $tunnel_hash{$peer}->{_peerid};
      }
      if ($tunnel_hash{$peer}->{_leftid} ne "N/A"){
        $myid = $tunnel_hash{$peer}->{_leftid};
      } else {
        $myid = $tunnel_hash{$peer}->{_leftip};
      }
      my $io =  "in";
      my $inspi = $tunnel_hash{$peer}->{_inspi};
      my $outspi = $tunnel_hash{$peer}->{_outspi};
      my $state = $tunnel_hash{$peer}->{_state};
      my $enc = "N/A";
      my $hash = "N/A";
      my $natt = "";
      if ($tunnel_hash{$peer}->{_ikeencrypt} =~ /(.*?)_.*?_(.*)/){
        $enc = lc($1).$2;
        $enc =~ s/^ //g;
      }
      if ($tunnel_hash{$peer}->{_ikehash} =~ /.*_(.*)/){
        $hash = lc($1);
      }
      if ($tunnel_hash{$peer}->{_natt} == 0){
        $natt = "No";
      } else {
        $natt = "Yes";
      }
      my $lifetime = $tunnel_hash{$peer}->{_ikelife};
      my $expire = $tunnel_hash{$peer}->{_ikeexpire};
      my $atime = $lifetime - $expire;
      printf "%-15s %-15s %-9s %-9s %-8s %-5s %-6s %-6s\n",
              substr($myid,0,14), substr($peerid,0,14), $state, $enc, $hash, $natt, $atime, $lifetime;

    }

}

## CLI options get processed here
my ($get_peers_for_cli, $show_ipsec_sa, $show_ipsec_sa_detail, , $show_ipsec_sa_peer, $show_ipsec_sa_peer_detail, $show_ipsec_sa_natt, $show_ipsec_sa_stats, $show_ipsec_sa_stats_peer, $show_ike_sa, $show_ike_sa_peer, $show_ike_sa_natt, $show_ike_secrets);

GetOptions("show-ipsec-sa!"             => \$show_ipsec_sa,
           "show-ipsec-sa-detail!"      => \$show_ipsec_sa_detail,
           "get-peers-for-cli!"         => \$get_peers_for_cli,
           "show-ipsec-sa-peer=s"        => \$show_ipsec_sa_peer,
           "show-ipsec-sa-peer-detail=s" => \$show_ipsec_sa_peer_detail,
           "show-ipsec-sa-natt!"        => \$show_ipsec_sa_natt,
           "show-ipsec-sa-stats!"       => \$show_ipsec_sa_stats,
           "show-ipsec-sa-stats-peer=s" => \$show_ipsec_sa_stats_peer,
           "show-ike-sa!"               => \$show_ike_sa,
           "show-ike-sa-peer=s"          => \$show_ike_sa_peer,
           "show-ike-sa-natt!"          => \$show_ike_sa_natt,
           "show-ike-secrets!"          => \$show_ike_secrets);

if (defined $get_peers_for_cli) {
  get_peers_for_cli;
}
if (defined $show_ipsec_sa) {
  show_ipsec_sa;
}
if (defined $show_ipsec_sa_detail) {
  show_ipsec_sa_detail;
}
if (defined $show_ipsec_sa_peer) {
  show_ipsec_sa_peer($show_ipsec_sa_peer);
}
if (defined $show_ipsec_sa_peer_detail) {
  show_ipsec_sa_peer_detail($show_ipsec_sa_peer_detail);
}
if (defined $show_ipsec_sa_natt) {
  show_ipsec_sa_natt;
}
if (defined $show_ipsec_sa_stats) {
  show_ipsec_sa_stats;
}
if (defined $show_ipsec_sa_stats_peer) {
  show_ipsec_sa_stats_peer($show_ipsec_sa_stats_peer);
}
if (defined $show_ike_sa) {
  show_ike_sa;
}
if (defined $show_ike_sa_peer) {
  show_ike_sa_peer($show_ike_sa_peer);
}
if (defined $show_ike_sa_natt) {
  show_ike_sa_natt;
}
if (defined $show_ike_secrets) {
  show_ike_secrets;
}
