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

use strict;

sub process_shell_api {
  my $path = pop(@_);
  my $output =  `cli-shell-api returnActiveValue $path`;
  return undef
    if $output eq "";
  return $output;
}
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
                  _ikestate    => "down",
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
      elsif ($line =~ /STATE_MAIN_I1/){
        $tunnel_hash{$connectid}->{_ikestate} = "init";
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
            $tunnel_hash{$connectid}->{_ikestate} = "up";
          }
        }
      }
      my $spi = $tunnel_hash{$connectid}->{_newestspi};
      if (defined($spi)){
        if ($line =~ /$spi:.*esp.(.*)\@.*\((.*)bytes.*esp.(.*)\@.*\((.*)bytes/)
        {
          $tunnel_hash{$connectid}->{_outspi} = $1;
          $tunnel_hash{$connectid}->{_outbytes} = $2;
          $tunnel_hash{$connectid}->{_inspi} = $3;
          $tunnel_hash{$connectid}->{_inbytes} = $4;
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
    # Get the static information from the Vyatta Configuration
    (my $peer, my $tunid) = ($connectid =~ /peer-(.*)-tunnel-(.*)/);
    my $peerip = $peer;
    $tunnel_hash{$connectid}->{_leftid}  = process_shell_api(
        "vpn ipsec site-to-site peer $peer authentication id");
    $tunnel_hash{$connectid}->{_rightid} = process_shell_api(
        "vpn ipsec site-to-site peer $peer authentication remote-id");
    $tunnel_hash{$connectid}->{_leftip}  = process_shell_api(
        "vpn ipsec site-to-site peer $peer local-ip");
    $tunnel_hash{$connectid}->{_srcnet}  = process_shell_api(
        "vpn ipsec site-to-site peer $peer tunnel $tunid local-subnet");
    $tunnel_hash{$connectid}->{_dstnet}  = process_shell_api(
        "vpn ipsec site-to-site peer $peer tunnel $tunid remote-subnet");
    if ($peerip =~ /\@.*/){
      $peerip = "0.0.0.0";
    } elsif ($peerip =~ /"any"/){
      $peerip = "0.0.0.0";
    }
    $tunnel_hash{$connectid}->{_rightip} = $peerip;

    # Detect NAT
    my $cmd = "sudo ip xfrm state get "
             ."src $tunnel_hash{$connectid}->{_leftip} "
             ."dst $peerip "
             ."proto esp "
             ."spi 0x$tunnel_hash{$connectid}->{_outspi} 2>/dev/null |";
    open(XFRM, $cmd);
    my @xfrm = [];
    while(<XFRM>){
      push (@xfrm, $_);
    }
    for my $line (@xfrm){
      if ($line =~ /type espinudp sport (.*?) dport (.*?) addr/){
        $tunnel_hash{$connectid}->{_natt} = 1;
        $tunnel_hash{$connectid}->{_natsrc} = $1;
        $tunnel_hash{$connectid}->{_natdst} = $2;
      }
    }
  }
  # Set undefined vars to "N/A" so the display will be nice
  for my $peer ( keys %tunnel_hash ) {
    for my $key ( keys %{$tunnel_hash{$peer}} ) {
      if (!defined %{$tunnel_hash{$peer}}->{$key}){
         %{$tunnel_hash{$peer}}->{$key}= "n/a";
      }
    }
  }
  #print Dumper \%tunnel_hash;
  return %tunnel_hash;
}

sub get_peers_for_cli
{
    my %tunnel_hash = get_tunnel_info();
    for my $peer ( keys %tunnel_hash ) {
      print %{$tunnel_hash{$peer}}->{_rightid}."\n";
    }
}

sub get_conn_for_cli
{
    my %tunnel_hash = get_tunnel_info();
    for my $peer ( keys %tunnel_hash ) {
      print "$peer\n";
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

sub show_ipsec_sa_stats_conn
{
    my %tunnel_hash = get_tunnel_info();
    my %tmphash = ();
    my $peerid = pop(@_);
    for my $peer ( keys %tunnel_hash ) {
          if ($peer eq $peerid){
             $tmphash{$peer} = \%{$tunnel_hash{$peer}};
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

sub show_ipsec_sa_conn_detail
{
    my %tunnel_hash = get_tunnel_info();
    my %tmphash = ();
    my $peerid = pop(@_);
    for my $peer ( keys %tunnel_hash ) {
          if ($peer eq $peerid){
             $tmphash{$peer} = \%{$tunnel_hash{$peer}};
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
    my %th = %{pop(@_)};
    my $listref = [];
    my %tunhash = ();
    my $myid = undef;
    my $peerid = undef;
    for my $connectid (keys %th){  
      if ($th{$connectid}->{_rightid} ne "n/a"){
        $peerid = "$th{$connectid}->{_rightid}";
      } else {
        $peerid = $th{$connectid}->{_peerid};
      }
      if ($th{$connectid}->{_leftid} ne "n/a"){
        $myid = "$th{$connectid}->{_leftid}";
      } else {
        $myid = $th{$connectid}->{_leftip};
      }

      my $tunnel = "$peerid-$myid";
      
      if (not exists $tunhash{$tunnel}) {
        $tunhash{$tunnel}=[];
      }
        my @tmp = ( $th{$connectid}->{_tunnelnum},
               $th{$connectid}->{_state},
               $th{$connectid}->{_inspi},
               $th{$connectid}->{_outspi},
               $th{$connectid}->{_encryption},
               $th{$connectid}->{_hash},
               $th{$connectid}->{_natt},
               $th{$connectid}->{_lifetime},
               $th{$connectid}->{_expire} );
        push (@{$tunhash{$tunnel}}, [ @tmp ]);
      
    }
    for my $connid (keys %tunhash){
    print <<EOH;
Peer ID / IP                            Local ID / IP               
--------------------------------------- ----------------------------------------
EOH
      (my $peerid, my $myid) = $connid =~ /(.*?)-(.*)/;
      printf "%-39s %-39s\n", $peerid, $myid;
      print <<EOH;
--------------------------------------- ----------------------------------------
    Tunnel  State  In SPI    Out SPI   Encrypt  Hash  NAT-T  A-Time  L-Time
    ------  -----  --------  --------  -------  ----  -----  ------  ------
EOH
      for my $tunnel (@{$tunhash{$connid}}){
        (my $tunnum, my $state, my $inspi, my $outspi, 
	 my $enc, my $hash, my $natt, my $life, my $expire) = @{$tunnel};
        my $encp = "n/a";
        my $hashp = "n/a";
        my $nattp = "";
        if ($enc =~ /(.*?)_.*?_(.*)/){
          $encp = lc($1).$2;
          $encp =~ s/^ //g;
        }
        if ($hash =~ /.*_(.*)/){
          $hashp = lc($1);
        }
        if ($natt == 0){
          $nattp = "no";
        } else {
          $nattp = "yes";
        }
        my $atime = $life - $expire;
        $atime = 0 if ($atime == $life);
	printf "    %-7s %-6s %-9s %-9s %-8s %-5s %-6s %-7s %-7s\n",
	$tunnum, $state, $inspi, $outspi, $encp, $hashp, $nattp, $atime, $life;
      }
      print <<EOH;
--------------------------------------------------------------------------------

EOH
    }
}

sub display_ipsec_sa_detail 
{
    my %tunnel_hash = %{pop(@_)};
    for my $peer ( keys %tunnel_hash){
      print "----------\n";
      my $peerid = "";
      if ($tunnel_hash{$peer}->{_rightid} ne "n/a"){
        $peerid = $tunnel_hash{$peer}->{_rightid};
      } else {
        $peerid = $tunnel_hash{$peer}->{_peerid};
      }
      my $enc = "n/a";
      my $hash = "n/a";
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
        $dh_group = "n/a";
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
        $pfs_group = "n/a";
      }
      else {
        $pfs_group = $tunnel_hash{$peer}->{_pfsgrp};
      }
      my $lifetime = $tunnel_hash{$peer}->{_lifetime};
      my $expire = $tunnel_hash{$peer}->{_expire};
      my $atime = $lifetime - $expire;
      $atime = 0 if ($atime == $lifetime);

      print "Conn Name:\t\t$peer\n";
      print "State:\t\t\t$tunnel_hash{$peer}->{_state}\n";
      print "Peer IP:\t\t$tunnel_hash{$peer}->{_rightip}\n";
      print "Peer ID:\t\t$tunnel_hash{$peer}->{_rightid}\n";
      print "Local IP:\t\t$tunnel_hash{$peer}->{_leftip}\n";
      print "Local ID:\t\t$tunnel_hash{$peer}->{_leftid}\n";
      print "Local Net:\t\t$tunnel_hash{$peer}->{_srcnet}\n";
      print "Remote Net:\t\t$tunnel_hash{$peer}->{_dstnet}\n";
      print "Inbound SPI:\t\t$tunnel_hash{$peer}->{_inspi}\n";
      print "Outbound SPI:\t\t$tunnel_hash{$peer}->{_outspi}\n";
      print "Encryption:\t\t$enc\n";
      print "Hash:\t\t\t$hash\n";
      print "PFS Group:\t\t$pfs_group\n";
      print "DH Group:\t\t$dh_group\n";
      print "NAT Traversal:\t\t$natt\n";
      print "NAT Source Port:\t$tunnel_hash{$peer}->{_natsrc}\n";
      print "NAT Dest Port:\t\t$tunnel_hash{$peer}->{_natdst}\n";
      print "Inbound Bytes:\t\t$tunnel_hash{$peer}->{_inbytes}\n";
      print "Outbound Bytes:\t\t$tunnel_hash{$peer}->{_outbytes}\n";
      print "Active Time (s):\t$atime\n";
      print "Lifetime (s):\t\t$tunnel_hash{$peer}->{_lifetime}\n";
      print "\n";
    }
}

sub display_ipsec_sa_stats
{
    my %th = %{pop(@_)};
    my $listref = [];
    my %tunhash = ();
    my $myid = undef;
    my $peerid = undef;
    for my $connectid (keys %th){  
      if ($th{$connectid}->{_rightid} ne "n/a"){
        $peerid = "$th{$connectid}->{_rightid}";
      } else {
        $peerid = $th{$connectid}->{_peerid};
      }
      if ($th{$connectid}->{_leftid} ne "n/a"){
        $myid = "$th{$connectid}->{_leftid}";
      } else {
        $myid = $th{$connectid}->{_leftip};
      }

      my $tunnel = "$peerid-$myid";
      
      if (not exists $tunhash{$tunnel}) {
        $tunhash{$tunnel}=[];
      }
        my @tmp = ( $th{$connectid}->{_tunnelnum},
               $th{$connectid}->{_srcnet},
               $th{$connectid}->{_dstnet},
               $th{$connectid}->{_inbytes},
               $th{$connectid}->{_outbytes} );
        push (@{$tunhash{$tunnel}}, [ @tmp ]);
      
    }
    for my $connid (keys %tunhash){
    print <<EOH;
Peer ID / IP                            Local ID / IP               
--------------------------------------- ----------------------------------------
EOH
      (my $peerid, my $myid) = $connid =~ /(.*?)-(.*)/;
      printf "%-39s %-39s\n", $peerid, $myid;
      print <<EOH;
--------------------------------------- ----------------------------------------
  Tunnel Dir Source Network               Destination Network          Bytes
  ------ --- ---------------------------- ---------------------------- ---------
EOH
      for my $tunnel (@{$tunhash{$connid}}){
        (my $tunnum, my $srcnet, my $dstnet, 
         my $inbytes, my $outbytes) = @{$tunnel};
        printf "  %-6s %-3s %-28s %-28s %-8s\n",
	      $tunnum, 'in', $dstnet, $srcnet, $inbytes;
        printf "  %-6s %-3s %-28s %-28s %-8s\n",
	      $tunnum, 'out', $srcnet, $dstnet, $outbytes;
      }
      print <<EOH;
--------------------------------------------------------------------------------

EOH
    }
}

sub display_ike_sa_brief {
    my %th = %{pop(@_)};
    my $listref = [];
    my %tunhash = ();
    my $myid = undef;
    my $peerid = undef;
    for my $connectid (keys %th){  
      if ($th{$connectid}->{_rightid} ne "n/a"){
        $peerid = "$th{$connectid}->{_rightid}";
      } else {
        $peerid = $th{$connectid}->{_peerid};
      }
      if ($th{$connectid}->{_leftid} ne "n/a"){
        $myid = "$th{$connectid}->{_leftid}";
      } else {
        $myid = $th{$connectid}->{_leftip};
      }

      my $tunnel = "$peerid-$myid";
      
      if (not exists $tunhash{$tunnel}) {
        $tunhash{$tunnel}=[];
      }
        my @tmp = ( $th{$connectid}->{_tunnelnum},
               $th{$connectid}->{_ikestate},
               $th{$connectid}->{_newestike},
               $th{$connectid}->{_ikeencrypt},
               $th{$connectid}->{_ikehash},
               $th{$connectid}->{_natt},
               $th{$connectid}->{_lifetime},
               $th{$connectid}->{_expire} );
        push (@{$tunhash{$tunnel}}, [ @tmp ]);
      
    }
    for my $connid (keys %tunhash){
    print <<EOH;
Peer ID / IP                            Local ID / IP               
--------------------------------------- ----------------------------------------
EOH
      (my $peerid, my $myid) = $connid =~ /(.*?)-(.*)/;
      printf "%-39s %-39s\n", $peerid, $myid;
      print <<EOH;
--------------------------------------- ----------------------------------------
    Tunnel  State  ISAKMP#  Encrypt  Hash  NAT-T  A-Time  L-Time
    ------  -----  -------  -------  ----  -----  ------  ------
EOH
      for my $tunnel (@{$tunhash{$connid}}){
        (my $tunnum, my $state, my $isakmpnum, my $enc, 
         my $hash, my $natt, my $life, my $expire) = @{$tunnel};
        my $encp = "n/a";
        my $hashp = "n/a";
        my $nattp = "";
        if ($enc =~ /(.*?)_.*?_(.*)/){
          $encp = lc($1).$2;
          $encp =~ s/^ //g;
        }
        if ($hash =~ /.*_(.*)/){
          $hashp = lc($1);
        }
        if ($natt == 0){
          $nattp = "no";
        } else {
          $nattp = "yes";
        }
        my $atime = $life - $expire;
        $atime = 0 if ($atime == $life);
	printf "    %-7s %-6s %-8s %-8s %-5s %-6s %-7s %-7s\n",
	$tunnum, $state, $isakmpnum, $encp, $hashp, $nattp, $atime, $life;
      }
      print <<EOH;
--------------------------------------------------------------------------------

EOH
    }
}

## CLI options get processed here
my ($get_peers_for_cli, $get_conn_for_cli, $show_ipsec_sa, $show_ipsec_sa_detail, , $show_ipsec_sa_peer, $show_ipsec_sa_peer_detail, $show_ipsec_sa_natt, $show_ipsec_sa_stats, $show_ipsec_sa_stats_peer, $show_ike_sa, $show_ike_sa_peer, $show_ike_sa_natt, $show_ike_secrets, $show_ipsec_sa_conn_detail, $show_ipsec_sa_stats_conn);

GetOptions("show-ipsec-sa!"             => \$show_ipsec_sa,
           "show-ipsec-sa-detail!"      => \$show_ipsec_sa_detail,
           "get-peers-for-cli!"         => \$get_peers_for_cli,
           "get-conn-for-cli!"         => \$get_conn_for_cli,
           "show-ipsec-sa-peer=s"        => \$show_ipsec_sa_peer,
           "show-ipsec-sa-peer-detail=s" => \$show_ipsec_sa_peer_detail,
           "show-ipsec-sa-natt!"        => \$show_ipsec_sa_natt,
           "show-ipsec-sa-stats!"       => \$show_ipsec_sa_stats,
           "show-ipsec-sa-stats-peer=s" => \$show_ipsec_sa_stats_peer,
           "show-ipsec-sa-stats-conn=s" => \$show_ipsec_sa_stats_conn,
           "show-ipsec-sa-conn-detail=s"=> \$show_ipsec_sa_conn_detail,
           "show-ike-sa!"               => \$show_ike_sa,
           "show-ike-sa-peer=s"          => \$show_ike_sa_peer,
           "show-ike-sa-natt!"          => \$show_ike_sa_natt,
           "show-ike-secrets!"          => \$show_ike_secrets);

if (defined $get_peers_for_cli) {
  get_peers_for_cli;
}
if (defined $get_conn_for_cli) {
  get_conn_for_cli;
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
if (defined $show_ipsec_sa_conn_detail) {
  show_ipsec_sa_conn_detail($show_ipsec_sa_conn_detail);
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
if (defined $show_ipsec_sa_stats_conn) {
  show_ipsec_sa_stats_conn($show_ipsec_sa_stats_conn);
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
