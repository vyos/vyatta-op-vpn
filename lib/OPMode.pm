#!/usr/bin/perl
#
# Module Vyatta::VPN::OpMode.pm
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

package Vyatta::VPN::OPMode;

use lib "/opt/vyatta/share/perl5/";
use Vyatta::VPN::Util;
use strict;

sub conv_id {
  my $peer = pop(@_);
  if ( $peer =~ /\d+\.\d+\.\d+\.\d+/ ){
    $peer = $peer;
  } elsif ($peer =~ /\d+\:\d+\:\d+\:\d+\:\d+\:\d+\:\d+\:\d+/){
    $peer = $peer;
  } else {
    $peer = "\@$peer";
  }
  return $peer;
}
sub conv_id_rev
{
  my $peerid = pop(@_);
  if ($peerid =~ /@(.*)/){
     $peerid = $1;
  }
  return $peerid;
}
sub conv_bytes {
   my $bytes = pop(@_);
   my $suffix = '';
   $bytes =~ s/\s+$//;
   if ($bytes > 1024 && $bytes < 1048576){
     $bytes = $bytes/1024;
     $suffix = "K";
   } elsif ($bytes > 1048576 && $bytes < 1073741824){
     $bytes = $bytes/1048576;
     $suffix = "M";
   } elsif ($bytes > 1073741824){
     $bytes = $bytes/1073741824;
     $suffix = "G";
   }
   $bytes = sprintf("%.1f",$bytes);
   $bytes = "$bytes$suffix";
}
sub conv_ip{
  my $peerip = pop(@_);
  if ($peerip =~ /\@.*/){
    $peerip = "0.0.0.0";
  } elsif ($peerip =~ /\%any/){
    $peerip = "0.0.0.0";
  }
  return $peerip;
}
sub nat_detect {
  (my $lip, my $rip) = @_;
  my @values;
  if ($lip =~ /(\d+\.\d+\.\d+\.\d+):(\d+)/){
    push (@values, $1);
    push (@values, 1);
    push (@values, $2);
  } else {
    push (@values, $lip);
    push (@values, 0);
    push (@values, 'n/a');
  }
  if ($rip =~ /(\d+\.\d+\.\d+\.\d+):(\d+)/){
    push (@values, $1);
    push (@values, $2);
  } else {
    push (@values, $rip);
    push (@values, 'n/a');
  }
  return @values;
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
      my $peer = $1;
      my $tunid = $2;
      $peer = conv_id($peer);
      if (not exists $tunnel_hash{$connectid}){
        $tunnel_hash{$connectid} = {
                  _peerid      => $peer,
                  _tunnelnum   => $tunid,
                  _lip         => 'n/a',
                  _rip         => 'n/a',
                  _lid         => 'n/a',
                  _rid         => 'n/a',
                  _lsnet       => 'n/a',
                  _rsnet       => 'n/a',
                  _lproto      => 'all',
                  _rproto      => 'all',
                  _lport       => 'all',
                  _rport       => 'all',
                  _newestspi   => 'n/a',
                  _newestike   => 'n/a',
                  _encryption  => 'n/a',
                  _hash        => 'n/a',
                  _inspi       => 'n/a',
                  _outspi      => 'n/a',
                  _pfsgrp      => 'n/a',
                  _ikeencrypt  => 'n/a',
                  _ikehash     => 'n/a',
                  _natt        => 'n/a',
                  _natsrc      => 'n/a',
                  _natdst      => 'n/a',
                  _ikestate    => "down",
                  _dhgrp       => 'n/a',
                  _state       => "down",
                  _inbytes     => 'n/a',
                  _outbytes    => 'n/a',
                  _ikelife     => 'n/a',
                  _ikeexpire   => 'n/a',
                  _lifetime    => 'n/a',
                  _expire      => 'n/a' };
      }
      if ($line =~ /IKE.proposal:(.*?)\/(.*?)\/(.*)/){
        $tunnel_hash{$connectid}->{_ikeencrypt} = $1;
        $tunnel_hash{$connectid}->{_ikehash} = $2;
        $tunnel_hash{$connectid}->{_dhgrp} = $3;
      }
      elsif ($line =~ /: (.*?)===(.*?)\[(.*?)\]...(.*?)\[(.*?)\]===(.*?);/){
        my $lsnet = $1;
        my $lip = $2;
        my $lid = $3;
        my $rip = $4;
        my $rid = $5;
        my $rsnet = $6;
        ($lip, my $natt, my $natsrc, $rip, my $natdst) = nat_detect($lip, $rip);
        $tunnel_hash{$connectid}->{_lid} = conv_id($lid);
        $tunnel_hash{$connectid}->{_lip} = $lip;
        $tunnel_hash{$connectid}->{_lsnet} = $lsnet;
        $tunnel_hash{$connectid}->{_rid} = conv_id($rid);
        $tunnel_hash{$connectid}->{_rip} = $rip;
        $tunnel_hash{$connectid}->{_rsnet} = $rsnet;
        $tunnel_hash{$connectid}->{_natt} = $natt;
        $tunnel_hash{$connectid}->{_natsrc} = $natsrc;
        $tunnel_hash{$connectid}->{_natdst} = $natdst;
      }
      elsif ($line =~ /: (.*?)\[(.*?)\]...(.*?)\[(.*?)\];/){
        my $lip = $1;
        my $lid = $2;
        my $rip = $3;
        my $rid = $4;
        ($lip, my $natt, my $natsrc, $rip, my $natdst) = nat_detect($lip, $rip);
        $tunnel_hash{$connectid}->{_lid} = conv_id($lid);
        $tunnel_hash{$connectid}->{_lip} = $lip;
        $tunnel_hash{$connectid}->{_rid} = conv_id($rid);
        $tunnel_hash{$connectid}->{_rip} = $rip;
        $tunnel_hash{$connectid}->{_natt} = $natt;
        $tunnel_hash{$connectid}->{_natsrc} = $natsrc;
        $tunnel_hash{$connectid}->{_natdst} = $natdst;
        }
      elsif ($line =~ /: (.*?)\[(.*?)\]:(\d+)\/(\d+)...(.*?)\[(.*?)\]:(\d+)\/(\d+);/){
        my $lip = $1;
        my $lid = $2;
        my $lproto = $3;
        $lproto = conv_protocol($lproto);
        my $lport = $4;
        my $rip = $5;
        my $rid = $6;
        my $rproto = conv_protocol($7);
        my $rport = $8;
        ($lip, my $natt, my $natsrc, $rip, my $natdst) = nat_detect($lip, $rip);
        $tunnel_hash{$connectid}->{_lid} = conv_id($lid);
        $tunnel_hash{$connectid}->{_lip} = $lip;
        $tunnel_hash{$connectid}->{_rid} = conv_id($rid);
        $tunnel_hash{$connectid}->{_rip} = $rip;
        $tunnel_hash{$connectid}->{_natt} = $natt;
        $tunnel_hash{$connectid}->{_natsrc} = $natsrc;
        $tunnel_hash{$connectid}->{_natdst} = $natdst;
        $tunnel_hash{$connectid}->{_lproto} = "$lproto";
        $tunnel_hash{$connectid}->{_rproto} = "$rproto";
        $tunnel_hash{$connectid}->{_lport} = "$lport";
        $tunnel_hash{$connectid}->{_rport} = "$rport";
      } 
      elsif ($line =~ /: (.*)===(.*?)\[(.*?)\]:(\d+)\/(\d+)...(.*?)\[(.*?)\]:(\d+)\/(\d+)===(.*?);/){
        my $lsnet = $1;
        my $lip = $2;
        my $lid = $3;
        my $lproto = conv_protocol($4);
        my $lport = $5;
        my $rip = $6;
        my $rid = $7;
        my $rproto = conv_protocol($8);
        my $rport = $9;
        my $rsnet = $10;
        my $lprotoport;
        my $rprotoport;
        $lprotoport = $lproto if ($lport == 0);
        $lprotoport = "$lproto/$lport" if ($lport != 0);
        $rprotoport = $rproto if ($rport == 0);
        $rprotoport = "$rproto/$rport" if ($rport != 0);
        ($lip, my $natt, my $natsrc, $rip, my $natdst) = nat_detect($lip, $rip);
        $tunnel_hash{$connectid}->{_lid} = conv_id($lid);
        $tunnel_hash{$connectid}->{_lip} = $lip;
        $tunnel_hash{$connectid}->{_lsnet} = $lsnet;
        $tunnel_hash{$connectid}->{_rid} = conv_id($rid);
        $tunnel_hash{$connectid}->{_rip} = $rip;
        $tunnel_hash{$connectid}->{_rsnet} = $rsnet;
        $tunnel_hash{$connectid}->{_lproto} = "$lproto";
        $tunnel_hash{$connectid}->{_rproto} = "$rproto";
        $tunnel_hash{$connectid}->{_lport} = "$lport";
        $tunnel_hash{$connectid}->{_rport} = "$rport";
        $tunnel_hash{$connectid}->{_natt} = $natt;
        $tunnel_hash{$connectid}->{_natsrc} = $natsrc;
        $tunnel_hash{$connectid}->{_natdst} = $natdst;
      }
      elsif ($line =~ /ESP.proposal:(.*?)\/(.*?)\/(.*)/){
        $tunnel_hash{$connectid}->{_encryption} = $1;
        $tunnel_hash{$connectid}->{_hash} = $2;
        $tunnel_hash{$connectid}->{_pfsgrp} = $3;
        if ($tunnel_hash{$connectid}->{_pfsgrp} eq "<Phase1>"){
          $tunnel_hash{$connectid}->{_pfsgrp} = 
                            $tunnel_hash{$connectid}->{_dhgrp};
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
        if ($line =~ /$ike:.*ISAKMP.SA.established.*EVENT_SA_REPLACE.in.(.*?)s;/)
        {
          $tunnel_hash{$connectid}->{_ikeexpire} = $1;
          my $atime = $tunnel_hash{$connectid}->{_ikelife} - 
                      $tunnel_hash{$connectid}->{_ikeexpire};
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
          my $atime = $tunnel_hash{$connectid}->{_lifetime} - 
                      $tunnel_hash{$connectid}->{_expire};
          if ($atime >= 0){
            $tunnel_hash{$connectid}->{_state} = "up";
          } 
        }
      }
    }
  }
  return %tunnel_hash;
}
sub get_conns
{
  my $cmd = "sudo cat /etc/ipsec.conf |";
  open(IPSECCONF, $cmd);
  my @ipsecconf = [];
  while(<IPSECCONF>){
    push (@ipsecconf, $_);
  }
  my %th = ();
  for my $line (@ipsecconf){
    next if ($line =~/^\#/);
    if ($line =~ /peer-(.*?)-tunnel-(.*)/){
      my $peer = $1;
      my $tun = $2;
      if (not exists $th{$peer}){
        $th{$peer} = { _conns => [$tun],
                       _peerid => conv_id($peer)
                     };
      } else {
        push (@{$th{$peer}->{_conns}}, $tun);
      }
    }
  }
  return %th;
}
sub get_peers_for_cli
{
    my %tunnel_hash = get_conns();
    for my $peer (peerSort( keys %tunnel_hash )) {
      print $tunnel_hash{$peer}->{_peerid}."\n";
    }
}

sub get_conn_for_cli
{
    my $peerid = pop(@_);
    my %th = get_conns();
    for my $peer (peerSort( keys %th )) {
      next if (not ($th{$peer}->{_peerid} eq $peerid));
      for my $conn ( @{$th{$peer}->{_conns}} ){
        print "$conn\n";
      }
    }
}

sub peerSort {
  map { $_ -> [0] }
    sort {
      our @a = split(/\./, $a->[1]);
      our @b = split(/\./, $b->[1]);
      $a[0] <=> $b[0] or
      $a[1] <=> $b[1] or 
      $a[2] <=> $b[2] or
      $a[3] <=> $b[3];
    } map { my $tmp = (split (/-/,$_))[0]; 
            if ($tmp =~ /@(.*)/){
              my @tmp = split('', $1);
              my $int1 = ord(uc($tmp[0]))*256;
              my $int2 = ord(uc($tmp[1]))*256;
              my $int3 = ord(uc($tmp[2]))*256;
              my $int4 = ord(uc($tmp[3]))*256;
              $tmp = "$int1.$int2.$int3.$int4";
            }
            [ $_, $tmp ]
      }
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
    my %th = get_tunnel_info();
    my %tmphash = ();
    (my $peerid, my $tun) = @_;
    for my $peer ( keys %th ) {
      if ($th{$peer}->{_peerid} eq $peerid){
        if ($th{$peer}->{_tunnelnum} eq $tun){
          $tmphash{$peer} = \%{$th{$peer}};
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
      if (%{$tunnel_hash{$peer}}->{_peerid} eq $peerid){
        $tmphash{$peer} = \%{$tunnel_hash{$peer}};
      }
    }
    display_ipsec_sa_detail(\%tmphash);
}

sub show_ipsec_sa_conn_detail
{
    my %th = get_tunnel_info();
    my %tmphash = ();
    (my $peerid, my $tun) = @_;
    for my $peer ( keys %th ) {
      if ($th{$peer}->{_peerid} eq $peerid){
        if ($th{$peer}->{_tunnelnum} eq $tun){
          $tmphash{$peer} = \%{$th{$peer}};
        }
      }
    }
    display_ipsec_sa_detail(\%tmphash);
}

sub show_ipsec_sa_conn
{
    my %th = get_tunnel_info();
    my %tmphash = ();
    (my $peerid, my $tun) = @_;
    for my $peer ( keys %th ) {
      if ($th{$peer}->{_peerid} eq $peerid){
        if ($th{$peer}->{_tunnelnum} eq $tun){
          $tmphash{$peer} = \%{$th{$peer}};
        }
      }
    }
    display_ipsec_sa_brief(\%tmphash);
}

sub get_connection_status
{
    my %th = get_tunnel_info();
    (my $peerid, my $tun) = @_;
    for my $peer ( keys %th ) {
      if (%{$th{$peer}}->{_peerid} eq $peerid){
        if (%{$th{$peer}}->{_tunnelnum} eq $tun){
          return %{$th{$peer}}->{_state};
        }
      }
    }
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
         # lines with 3 entries are tagged by the config module so that we can 
         # tell if the 3rd entry is a localid or peerid (left or right)
        if (! defined($lip)){
          if ($line =~ /^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+\:\s+PSK\s+\"\S+\"/){
            $lip = $1; 
            $pip = $2; 
            $lid = $3; 
            $pid = $4; 
          } elsif ($line =~ 
                   /^(\S+)\s+(\S+)\s+(\S+)\s+\:\s+PSK\s+\"\S+\".*\#(.*)\#/){
            $lip = $1; 
            $pip = $2; 
            if ($4 eq 'RIGHT'){
              $pid = $3
            } else {$lid = $3} 
          }   
        }   
        $lip = '0.0.0.0' if ! defined $lip;
        $pip = '0.0.0.0' if ! defined $pip;
        $pip = '0.0.0.0' if ($pip eq '%any');
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
      $peerid = $th{$connectid}->{_peerid};
      my $lip = $th{$connectid}->{_lip};
      my $tunnel = "$peerid-$lip";
        
      if (not exists $tunhash{$tunnel}) {
        $tunhash{$tunnel} = {
          _outspi  => $th{$connectid}->{_outspi},
          _natt  => $th{$connectid}->{_natt},
          _lip  => $lip,
          _tunnels => []
        };
      }
      my @tmp = ( $th{$connectid}->{_tunnelnum},
               $th{$connectid}->{_state},
               $th{$connectid}->{_inbytes},
               $th{$connectid}->{_outbytes},
               $th{$connectid}->{_encryption},
               $th{$connectid}->{_hash},
               $th{$connectid}->{_lifetime},
               $th{$connectid}->{_expire});
      push (@{$tunhash{"$tunnel"}->{_tunnels}}, [ @tmp ]);
      
    }
    for my $connid (peerSort (keys %tunhash)){
    print <<EOH;
Peer ID / IP                            Local ID / IP               
--------------------------------------- ----------------------------------------
EOH
      (my $peerid, my $myid) = $connid =~ /(.*?)-(.*)/;
      printf "%-39s %-39s\n", $peerid, $myid;
      print <<EOH;
--------------------------------------- ----------------------------------------
    Tunnel  State  Bytes Out/In   Encrypt  Hash  NAT-T  A-Time  L-Time  
    ------  -----  -------------  -------  ----  -----  ------  ------  
EOH
      for my $tunnel (tunSort(@{$tunhash{$connid}->{_tunnels}})){
        (my $tunnum, my $state, my $inbytes, my $outbytes, 
         my $enc, my $hash, my $life, my $expire) = @{$tunnel};
        my $lip = $tunhash{$connid}->{_lip};
        my $peerip = conv_ip($peerid);
        my $natt = $tunhash{$connid}->{_natt};
        my $encp = "n/a";
        my $hashp = "n/a";
        my $nattp = "";
        my $bytesp = 'n/a';
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
        if (!($inbytes eq 'n/a' && $outbytes eq 'n/a')){
          $outbytes = conv_bytes($outbytes);
          $inbytes = conv_bytes($inbytes);
          $bytesp = "$outbytes/$inbytes";
        }
        my $atime = $life - $expire;
        $atime = 0 if ($atime == $life);
        printf "    %-7s %-6s %-14s %-8s %-5s %-6s %-7s %-7s\n",
              $tunnum, $state, $bytesp, $encp, $hashp, $nattp, 
              $atime, $life;
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
      my $lip = $th{$connectid}->{_lip};
      $peerid = $th{$connectid}->{_peerid};
      my $tunnel = "$peerid-$lip";
      
      if (not exists $tunhash{$tunnel}) {
        $tunhash{$tunnel} = {
          _peerip      => $th{$connectid}->{_rip},
          _peerid      => $th{$connectid}->{_rid},
          _localip     => $th{$connectid}->{_lip},
          _localid     => $th{$connectid}->{_lid},
          _natt        => $th{$connectid}->{_natt},
          _natsrc      => $th{$connectid}->{_natsrc},
          _natdst      => $th{$connectid}->{_natdst},
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
               $th{$connectid}->{_lsnet},
               $th{$connectid}->{_rsnet},
               $th{$connectid}->{_inbytes},
               $th{$connectid}->{_outbytes},
               $th{$connectid}->{_lifetime},
               $th{$connectid}->{_expire},
               $th{$connectid}->{_lproto},
               $th{$connectid}->{_rproto},
               $th{$connectid}->{_lport},
               $th{$connectid}->{_rport} );
      push (@{$tunhash{$tunnel}->{_tunnels}}, [ @tmp ]);
    }
    for my $connid (peerSort(keys %tunhash)){
      my $natt = "";
      if ($tunhash{$connid}->{_natt} == 0){
        $natt = "no";
      } else {
        $natt = "yes";
      }
      my $peerip = conv_ip($tunhash{$connid}->{_peerip});
      print "------------------------------------------------------------------\n";
      print "Peer IP:\t\t$peerip\n";
      print "Peer ID:\t\t$tunhash{$connid}->{_peerid}\n";
      print "Local IP:\t\t$tunhash{$connid}->{_localip}\n";
      print "Local ID:\t\t$tunhash{$connid}->{_localid}\n";
      print "NAT Traversal:\t\t$natt\n";
      print "NAT Source Port:\t$tunhash{$connid}->{_natsrc}\n";
      print "NAT Dest Port:\t\t$tunhash{$connid}->{_natdst}\n";
      print "------------------------------------------------------------------\n";
      for my $tunnel (tunSort(@{$tunhash{$connid}->{_tunnels}})){
        (my $tunnum, my $state, my $inspi, my $outspi, my $enc,
         my $hash, my $pfsgrp, my $dhgrp, my $srcnet, my $dstnet,
         my $inbytes, my $outbytes, my $life, my $expire, my $lproto,
         my $rproto, my $lport, my $rport) = @{$tunnel};
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
        $atime = 0 if ($atime == $life);
        $inbytes = conv_bytes($inbytes);
        $outbytes = conv_bytes($outbytes);

        print "    Tunnel $tunnum:\n";
        print "        State:\t\t\t$state\n";
        print "        Inbound SPI:\t\t$inspi\n";
        print "        Outbound SPI:\t\t$outspi\n";
        print "        Encryption:\t\t$enc\n";
        print "        Hash:\t\t\t$hash\n";
        print "        PFS Group:\t\t$pfs_group\n";
        print "        DH Group:\t\t$dh_group\n";
        print "        --------------------------------------------------------\n";
        print "        Local Net:\t\t$srcnet\n";
        print "        Local Protocol:\t\t$lproto\n";
        print "        Local Port: \t\t$lport\n";
        print "        --------------------------------------------------------\n";
        print "        Remote Net:\t\t$dstnet\n";
        print "        Remote Protocol:\t$rproto\n";
        print "        Remote Port: \t\t$rport\n";
        print "        --------------------------------------------------------\n";
        print "        Inbound Bytes:\t\t$inbytes\n";
        print "        Outbound Bytes:\t\t$outbytes\n";
        print "        Active Time (s):\t$atime\n";
        print "        Lifetime (s):\t\t$life\n";
        print "    ------------------------------------------------------------\n";
      }
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
      my $lip = $th{$connectid}->{_lip};
      $peerid = $th{$connectid}->{_peerid};
      my $tunnel = "$peerid-$lip";
      
      if (not exists $tunhash{$tunnel}) {
        $tunhash{$tunnel}=[];
      }
        my @tmp = ( $th{$connectid}->{_tunnelnum},
               $th{$connectid}->{_lsnet},
               $th{$connectid}->{_rsnet},
               $th{$connectid}->{_inbytes},
               $th{$connectid}->{_outbytes} );
        push (@{$tunhash{$tunnel}}, [ @tmp ]);
    }
    for my $connid (peerSort(keys %tunhash)){
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
      my $lip = $th{$connectid}->{_lip};
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
               $th{$connectid}->{_natt},
               $th{$connectid}->{_ikelife},
               $th{$connectid}->{_ikeexpire} );
        push (@{$tunhash{$tunnel}}, [ @tmp ]);
      
    }
    for my $connid (peerSort(keys %tunhash)){
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
1;
