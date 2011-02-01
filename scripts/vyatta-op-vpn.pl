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
use lib "/opt/vyatta/share/perl5";
use Data::Dumper;
use Vyatta::Config;

use strict;
my $vconfig = new Vyatta::Config;

sub get_values_from_config {
    (my $peer, my $tunid) = @_; 
    # Get the static information from the Vyatta Configuration
    my @values;
    my $peerip = $peer;
    my $lid = $vconfig->returnEffectiveValue( 
        "vpn ipsec site-to-site peer $peer authentication id");
    $lid = 'n/a' if (!defined($lid));
    push (@values, $lid);
    
    my $rid = $vconfig->returnEffectiveValue( 
        "vpn ipsec site-to-site peer $peer authentication remote-id");
    $rid = 'n/a' if (!defined($rid));
    push (@values, $rid);
    
    my $lip = $vconfig->returnEffectiveValue( 
        "vpn ipsec site-to-site peer $peer local-ip");
    $lip = 'n/a' if (!defined($lip));
    push (@values, $lip);

    my $lsnet = $vconfig->returnEffectiveValue( 
        "vpn ipsec site-to-site peer $peer tunnel $tunid local-subnet");
    $lsnet = 'n/a' if (!defined($lsnet));
    push (@values, $lsnet);
    
    my $rsnet = $vconfig->returnEffectiveValue( 
        "vpn ipsec site-to-site peer $peer tunnel $tunid remote-subnet");
    $rsnet = 'n/a' if (!defined($rsnet));
    push (@values, $rsnet);

    if ($peerip =~ /\@.*/){
      $peerip = "0.0.0.0";
    } elsif ($peerip =~ /"any"/){
      $peerip = "0.0.0.0";
    }
    push (@values, $peerip);
    return @values;
}

sub get_nat_info {
    (my $srcip, my $dstip, my $spi) = @_;
    my @values = ();
    my $cmd = "sudo ip xfrm state get "
             ."src $srcip "
             ."dst $dstip "
             ."proto esp "
             ."spi 0x$spi 2>/dev/null |";
    open(XFRM, $cmd);
    while(<XFRM>){
      if ($_ =~ /type espinudp sport (.*?) dport (.*?) addr/){
        push (@values, 1);
        push (@values, $1);
        push (@values, $2);
      }
    }
    if (scalar @values <= 0){
    	@values = (0, 'n/a', 'n/a');
    }
    return @values;
}

sub get_tunnel_info {
  my $cmd = "sudo ipsec statusall |";
  my $vconfig = new Vyatta::Config;
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
      my $peer = $1;
      my $tunid = $2;
      if ( $peer =~ /\d+\.\d+\.\d+\.\d+/ ){
      	$peer = $peer;
      } elsif ($peer =~ /\d+\:\d+\:\d+\:\d+\:\d+\:\d+\:\d+\:\d+/){
      	$peer = $peer;
      } else {
      	$peer = "\@$peer";
      }
      if (not exists $tunnel_hash{$connectid}){
        $tunnel_hash{$connectid} = {
                  _peerid      => $peer,
                  _tunnelnum   => $tunid,
                  _newestspi   => undef,
                  _newestike   => undef,
                  _encryption  => undef,
                  _hash        => undef,
                  _inspi       => undef,
                  _outspi      => undef,
                  _pfsgrp      => undef,
                  _ikeencrypt  => undef,
                  _ikehash     => undef,
                  _ikestate    => "down",
                  _dhgrp       => undef,
                  _state       => "down",
                  _inbytes     => undef,
                  _outbytes    => undef,
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
  # Set undefined vars to "N/A" so the display will be nice
  for my $peer ( keys %tunnel_hash ) {
    for my $key ( keys %{$tunnel_hash{$peer}} ) {
      if (!defined %{$tunnel_hash{$peer}}->{$key}){
         %{$tunnel_hash{$peer}}->{$key}= "n/a";
      }
    }
  }
  return %tunnel_hash;
}

sub get_peers_for_cli
{
    my %tunnel_hash = get_tunnel_info();
    for my $peer ( keys %tunnel_hash ) {
      print %{$tunnel_hash{$peer}}->{_peerid}."\n";
    }
}

sub get_conn_for_cli
{
    my %tunnel_hash = get_tunnel_info();
    for my $peer ( keys %tunnel_hash ) {
      print "$peer\n";
    }
}

sub ipv4sort {
  map  { $_->[0] }
    sort { $a->[1] <=> $b->[1] }
      map { my ($conv,$addr)=(0,$_);
            $conv=$_ + ($conv << 8) for split(/\./, $addr);
	    [$addr,$conv]}
      @_;
}

sub tunSort {
  sort { 
    $a->[0] <=> $b->[0];
  } @_;
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
      if (%{$tunnel_hash{$peer}}->{_peerid} eq $peerid){
        $tmphash{$peer} = \%{$tunnel_hash{$peer}};
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
      if (%{$tunnel_hash{$peer}}->{_peerid} eq $peerid){
        $tmphash{$peer} = \%{$tunnel_hash{$peer}};
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
      if (%{$tunnel_hash{$peer}}->{_peerid} eq $peerid){
        $tmphash{$peer} = \%{$tunnel_hash{$peer}};
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
       if (%{$tunnel_hash{$peer}}->{_natt} == 1 ){
         $tmphash{$peer} = \%{$tunnel_hash{$peer}};
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
      if (%{$tunnel_hash{$peer}}->{_peerid} eq $peerid ){
        $tmphash{$peer} = \%{$tunnel_hash{$peer}};
      }
    }
    display_ike_sa_brief(\%tmphash);

}

sub show_ike_sa_natt
{
    my %tunnel_hash = get_tunnel_info();
    my %tmphash = ();
    for my $peer ( keys %tunnel_hash ) {
      if (%{$tunnel_hash{$peer}}->{_natt} == 1 ){
        $tmphash{$peer} = \%{$tunnel_hash{$peer}};
      }
    }
    display_ike_sa_brief(\%tmphash);

}

sub show_ike_secrets
{
    my $secret_file = '/etc/ipsec.secrets';
    unless ( -r $secret_file) {
      die "No secrets file $secret_file\n";
    }   
    open(DAT, $secret_file);
    my @raw_data=<DAT>;
    close(DAT);
    foreach my $line (@raw_data) {
      if ($line =~ /PSK/) {
        my ($lip, $pip, $lid, $pid, $secret) = ('', '', 'N/A', 'N/A', '');
        ($secret) = $line =~ /.*:\s+PSK\s+(\"\S+\")/;
        ($lip, $pip) = $line =~ /^(\S+)\s+(\S+)\s+\:\s+PSK\s+\"\S+\"/;
         # This processing with depend heavily on the way we write ipsec.secrets
         # lines with 3 entries are tagged by the config module so that we can tell
         # if the 3rd entry is a localid or peerid (left or right)
        if (! defined($lip)){
          if ($line =~ /^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+\:\s+PSK\s+\"\S+\"/){
            $lip = $1; 
            $pip = $2; 
            $lid = $3; 
            $pid = $4; 
          } elsif ($line =~ /^(\S+)\s+(\S+)\s+(\S+)\s+\:\s+PSK\s+\"\S+\".*\#(.*)\#/){
            $lip = $1; 
            $pip = $2; 
            if ($4 eq 'RIGHT'){
              $pid = $3
            } else {$lid = $3} 
          }   
        }   
        $lip = '0.0.0.0' if ! defined $lip;
        $pip = '0.0.0.0' if ! defined $pip;
        print <<EOH;
Local IP/ID                             Peer IP/ID                           
--------------------------------------- ---------------------------------------
EOH
        printf "%-39s %-39s\n", $lip, $pip;
        printf "%-39s %-39s\n", substr($lid,0,39), substr($pid,0,39);
        print <<EOS;
--------------------------------------- ---------------------------------------
EOS
        print "    Secret: $secret\n";
print <<EOS;
-------------------------------------------------------------------------------

EOS
      }   
    }   
    exit 0;

}

sub display_ipsec_sa_brief
{
    my %th = %{pop(@_)};
    my $listref = [];
    my %tunhash = ();
    my $myid = undef;
    my $peerid = undef;
    for my $connectid (keys %th){  
      (my $lid, my $rid, my $lip, my $lsnet, 
       my $rsnet, my $pip ) = get_values_from_config(
                               $th{$connectid}->{_peerid},
                               $th{$connectid}->{_tunnelnum});
      (my $natt, my $natsrc, my $natdst) = get_nat_info($lip, $pip, 
           $th{$connectid}->{_outspi});
      $peerid = $th{$connectid}->{_peerid};
      my $tunnel = "$peerid-$lip";
        
      if (not exists $tunhash{$tunnel}) {
        $tunhash{$tunnel}={
	  _myid => $myid,
	  _tunnels => []
	};
      }
        my @tmp = ( $th{$connectid}->{_tunnelnum},
               $th{$connectid}->{_state},
               $th{$connectid}->{_inspi},
               $th{$connectid}->{_outspi},
               $th{$connectid}->{_encryption},
               $th{$connectid}->{_hash},
               $natt,
               $th{$connectid}->{_lifetime},
               $th{$connectid}->{_expire} );
        push (@{$tunhash{"$tunnel"}->{_tunnels}}, [ @tmp ]);
      
    }
    for my $connid (ipv4sort (keys %tunhash)){
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
      for my $tunnel (tunSort(@{$tunhash{$connid}->{_tunnels}})){
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
    my %th = %{pop(@_)};
    my $listref = [];
    my %tunhash = ();
    my $myid = undef;
    my $peerid = undef;
    for my $connectid (keys %th){  
       $peerid = $th{$connectid}->{_peerid};
      (my $lid, my $rid, my $lip, my $lsnet, 
       my $rsnet, my $pip ) = get_values_from_config(
                               $th{$connectid}->{_peerid},
                               $th{$connectid}->{_tunnelnum});
      (my $natt, my $natsrc, my $natdst) = get_nat_info($lip, $pip, 
           $th{$connectid}->{_outspi});
      $peerid = $th{$connectid}->{_peerid};
      my $tunnel = "$peerid-$lip";
      
      if (not exists $tunhash{$tunnel}) {
        $tunhash{$tunnel} = {
          _peerip      => $pip,
          _peerid      => $rid,
          _localip     => $lip,
          _localid     => $lid,
          _natt        => $natt,
          _natsrc      => $natsrc,
          _natdst      => $natdst,
          _tunnels     => []
        };
      }
        my @tmp = ( $th{$connectid}->{_tunnelnum},
               $th{$connectid}->{_state},
               $th{$connectid}->{_inspi},
               $th{$connectid}->{_outspi},
               $th{$connectid}->{_encryption},
               $th{$connectid}->{_hash},
               $th{$connectid}->{_pfsgrp},
               $th{$connectid}->{_dhgrp},
               $lsnet,
               $rsnet,
               $th{$connectid}->{_inbytes},
               $th{$connectid}->{_outbytes},
               $th{$connectid}->{_lifetime},
               $th{$connectid}->{_expire} );
        push (@{$tunhash{$tunnel}->{_tunnels}}, [ @tmp ]);
    }
    for my $connid (ipv4sort(keys %tunhash)){
      my $natt = "";
      if ($tunhash{$connid}->{_natt} == 0){
        $natt = "no";
      } else {
        $natt = "yes";
      }
      print "----------\n";
      print "Peer IP:\t\t$tunhash{$connid}->{_peerip}\n";
      print "Peer ID:\t\t$tunhash{$connid}->{_peerid}\n";
      print "Local IP:\t\t$tunhash{$connid}->{_localip}\n";
      print "Local ID:\t\t$tunhash{$connid}->{_localid}\n";
      print "NAT Traversal:\t\t$natt\n";
      print "NAT Source Port:\t$tunhash{$connid}->{_natsrc}\n";
      print "NAT Dest Port:\t\t$tunhash{$connid}->{_natdst}\n";
      for my $tunnel (tunSort(@{$tunhash{$connid}->{_tunnels}})){
        (my $tunnum, my $state, my $inspi, my $outspi, my $enc,
         my $hash, my $pfsgrp, my $dhgrp, my $srcnet, my $dstnet,
         my $inbytes, my $outbytes, my $life, my $expire) = @{$tunnel};
        if ($enc =~ /(.*?)_.*?_(.*)/){
          $enc = lc($1).$2;
          $enc =~ s/^ //g;
        }
        if ($hash =~ /.*_(.*)/){
          $hash = lc($1);
        }
        my $dh_group = "";
        if ($dhgrp eq "MODP_768"){
          $dh_group = 1;
        } elsif ($dhgrp eq "MODP_1024"){
          $dh_group = 2;
        } elsif ($dhgrp eq "MODP_1536"){
          $dh_group = 5;
        } elsif ($dhgrp eq "MODP_2048"){
          $dh_group = 7;
        } elsif ($dhgrp eq "<N/A>"){
          $dh_group = "n/a";
        } else {
          $dh_group = $dhgrp;
        }
        my $pfs_group = "";
        if ($pfsgrp eq "MODP_768"){
          $pfs_group = 1;
        } elsif ($pfsgrp eq "MODP_1024"){
          $pfs_group = 2;
        } elsif ($pfsgrp eq "MODP_1536"){
          $pfs_group = 5;
        } elsif ($pfsgrp eq "MODP_2048"){
          $pfs_group = 7;
        } elsif ($pfsgrp eq "<N/A>"){
          $pfs_group = "n/a";
        } else {
          $pfs_group = $pfsgrp;
        }
        my $atime = $life - $expire;

        print "Tunnel $tunnum:\n";
        print "    State:\t\t$state\n";
        print "    Inbound SPI:\t$inspi\n";
        print "    Outbound SPI:\t$outspi\n";
        print "    Encryption:\t\t$enc\n";
        print "    Hash:\t\t$hash\n";
        print "    PFS Group:\t\t$pfs_group\n";
        print "    DH Group:\t\t$dh_group\n";
        print "    Local Net:\t\t$srcnet\n";
        print "    Remote Net:\t\t$dstnet\n";
        print "    Inbound Bytes:\t$inbytes\n";
        print "    Outbound Bytes:\t$outbytes\n";
        print "    Active Time (s):\t$atime\n";
        print "    Lifetime (s):\t$life\n";
      }
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
      (my $lid, my $rid, my $lip, my $lsnet, 
       my $rsnet, my $pip ) = get_values_from_config(
                               $th{$connectid}->{_peerid},
                               $th{$connectid}->{_tunnelnum});
      $peerid = $th{$connectid}->{_peerid};
      my $tunnel = "$peerid-$lip";
      
      if (not exists $tunhash{$tunnel}) {
        $tunhash{$tunnel}=[];
      }
        my @tmp = ( $th{$connectid}->{_tunnelnum},
               $lsnet,
               $rsnet,
               $th{$connectid}->{_inbytes},
               $th{$connectid}->{_outbytes} );
        push (@{$tunhash{$tunnel}}, [ @tmp ]);
      
    }
    for my $connid (ipv4sort(keys %tunhash)){
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
      for my $tunnel (tunSort(@{$tunhash{$connid}})){
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
      (my $lid, my $rid, my $lip, my $lsnet, 
       my $rsnet, my $pip ) = get_values_from_config(
                               $th{$connectid}->{_peerid},
                               $th{$connectid}->{_tunnelnum});
      (my $natt, my $natsrc, my $natdst) = get_nat_info($lip, $pip, 
           $th{$connectid}->{_outspi});
      $peerid = $th{$connectid}->{_peerid};
      my $tunnel = "$peerid-$lip";
      
      if (not exists $tunhash{$tunnel}) {
        $tunhash{$tunnel}=[];
      }
        my @tmp = ( $th{$connectid}->{_tunnelnum},
               $th{$connectid}->{_ikestate},
               $th{$connectid}->{_newestike},
               $th{$connectid}->{_ikeencrypt},
               $th{$connectid}->{_ikehash},
               $natt,
               $th{$connectid}->{_lifetime},
               $th{$connectid}->{_expire} );
        push (@{$tunhash{$tunnel}}, [ @tmp ]);
      
    }
    for my $connid (ipv4sort(keys %tunhash)){
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
      for my $tunnel (tunSort(@{$tunhash{$connid}})){
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
