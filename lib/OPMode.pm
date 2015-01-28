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
use Vyatta::Config;
use strict;

sub conv_id {
  my $peer = pop(@_);
  if ( $peer =~ /\d+\.\d+\.\d+\.\d+/ ){
    $peer = $peer;
  } elsif ($peer =~ /\d+\:\d+\:\d+\:\d+\:\d+\:\d+\:\d+\:\d+/){
    $peer = $peer;
  } elsif ($peer =~ /\%any/){
    $peer = "any";
  } else {
    $peer = "\@$peer";
  }
  return $peer;
}

sub conv_dh_group {
  my $dhgrp = pop(@_);
  my $dh_group = '';
  if ($dhgrp eq "MODP_768"){
    $dh_group = 1;
  } elsif ($dhgrp eq "MODP_1024"){
    $dh_group = 2;
  } elsif ($dhgrp eq "MODP_1536"){
    $dh_group = 5;
  } elsif ($dhgrp eq "MODP_2048"){
    $dh_group = 14;
  } elsif ($dhgrp eq "MODP_3072"){
    $dh_group = 15;
  } elsif ($dhgrp eq "MODP_4096"){
    $dh_group = 16;
  } elsif ($dhgrp eq "MODP_6144"){
    $dh_group = 17;
  } elsif ($dhgrp eq "MODP_8192"){
    $dh_group = 18;
  } elsif ($dhgrp eq "ECP_256"){
    $dh_group = 19;
  } elsif ($dhgrp eq "ECP_384"){
    $dh_group = 20;
  } elsif ($dhgrp eq "ECP_521"){
    $dh_group = 21;
  } elsif ($dhgrp eq "MODP_1024_160"){
    $dh_group = 22;
  } elsif ($dhgrp eq "MODP_2048_224"){
    $dh_group = 23;
  } elsif ($dhgrp eq "MODP_2048_256"){
    $dh_group = 24;
  } elsif ($dhgrp eq "ECP_192"){
    $dh_group = 25;
  } elsif ($dhgrp eq "ECP_224"){
    $dh_group = 26;
  } elsif ($dhgrp eq "<N/A>"){
    $dh_group = "n/a";
  } else {
    $dh_group = $dhgrp;
  }
  return $dh_group;
}

sub conv_hash {
  my $hash = pop(@_);
  if ($hash =~ /[^_]*_(.*)/){
    $hash = lc($1);
    if ($hash =~ /sha2_(.*)/){
      $hash = "sha".$1;
    }
  }
  return $hash;
}

sub conv_enc {
  my $enc = pop(@_);
  if ($enc =~ /(.*?)_.*?_(.*)/){
    $enc = lc($1).$2;
    $enc =~ s/^ //g;
  } elsif ($enc =~ /3DES/) {
    $enc = "3des";
  }
  return $enc;
}

sub conv_natt {
  my $natt = pop(@_);
  if ($natt == 0){
    $natt = "no";
  } else {
    $natt = "yes";
  }
  return $natt;
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
   } elsif ($bytes >= 1048576 && $bytes < 1073741824){
     $bytes = $bytes/1048576;
     $suffix = "M";
   } elsif ($bytes >= 1073741824){
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
  #my $cmd = "cat /home/vyatta/test.txt";
  my $cmd = "sudo ipsec statusall";
  open(my $IPSECSTATUS, ,'-|', $cmd);
  my @ipsecstatus = [];
  while(<$IPSECSTATUS>){
    push (@ipsecstatus, $_);
  }
  process_tunnels(\@ipsecstatus);
}

sub get_tunnel_info_peer {
  my $peer = pop(@_);
  #my $cmd = "cat /home/vyatta/test.txt | grep peer-$peer";
  my $cmd = "sudo ipsec statusall | grep peer-$peer-";
  open(my $IPSECSTATUS, ,'-|', $cmd);
  my @ipsecstatus = [];
  while(<$IPSECSTATUS>){
    push (@ipsecstatus, $_);
  }
  process_tunnels(\@ipsecstatus);
}

sub process_tunnels{
  my @ipsecstatus = @{pop(@_)};
  my %tunnel_hash = ();
  my %esp_hash = ();
  foreach my $line (@ipsecstatus) {
    if (($line =~ /\"(peer-.*-tunnel-.*?)\"/)){
      my $connectid = $1;
      if (($line =~ /\"(peer-.*-tunnel-.*?)\"(\[\d*\])/)){
        $connectid .= $2;
      }
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
                  _lca         => undef,
                  _rca         => undef,
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
      $line =~ s/---.*\.\.\./.../g; # remove the next hop router for local-ip 0.0.0.0 case
      if ($line =~ /IKE.proposal:(.*?)\/(.*?)\/(.*)/){
        $tunnel_hash{$connectid}->{_ikeencrypt} = $1;
        $tunnel_hash{$connectid}->{_ikehash} = $2;
        $tunnel_hash{$connectid}->{_dhgrp} = $3;
      }
      # both subnets
      elsif ($line =~ /: (.*?)===(.*?)\[(.*?)\]\.\.\.(.*?)\[(.*?)\]===(.*?);/){
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
      #left subnet
      elsif ($line =~ /: (.*?)\[(.*?)\]\.\.\.(.*?)\[(.*?)\];/){
        my $lip = $1;
        my $lid = $2;
        my $rip = $3;
        my $rid = $4;
        my $lsnet;
        if ($lip =~ /(.*?)===(.*)/){
          $lsnet = $1;
          $lip = $2;
        }
        ($lip, my $natt, my $natsrc, $rip, my $natdst) = nat_detect($lip, $rip);
        $tunnel_hash{$connectid}->{_lid} = conv_id($lid);
        $tunnel_hash{$connectid}->{_lip} = $lip;
        $tunnel_hash{$connectid}->{_rid} = conv_id($rid);
        $tunnel_hash{$connectid}->{_rip} = $rip;
        $tunnel_hash{$connectid}->{_natt} = $natt;
        $tunnel_hash{$connectid}->{_natsrc} = $natsrc;
        $tunnel_hash{$connectid}->{_natdst} = $natdst;
        $tunnel_hash{$connectid}->{_lsnet} = $lsnet if (defined($lsnet));
      }
      #left subnet with protocols
      elsif ($line =~ /: (.*?)\[(.*?)\]:(\d+)\/(\d+)\.\.\.(.*?)\[(.*?)\]:(\d+)\/(\d+);/){
        my $lip = $1;
        my $lsnet;
        my $lid = $2;
        my $lproto = conv_protocol($3);
        my $lport = $4;
        my $rip = $5;
        my $rid = $6;
        my $rproto = conv_protocol($7);
        my $rport = $8;
        if ($lip =~ /(.*?)===(.*)/){
          $lsnet = $1;
          $lip = $2;
        }
        ($lip, my $natt, my $natsrc, $rip, my $natdst) = nat_detect($lip, $rip);
        $tunnel_hash{$connectid}->{_lid} = conv_id($lid);
        $tunnel_hash{$connectid}->{_lip} = $lip;
        $tunnel_hash{$connectid}->{_lsnet} = $lsnet if (defined($lsnet));
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
      # both proto/port and subnets
      elsif ($line =~ /: (.*)===(.*?)\[(.*?)\]:(\d+)\/(\d+)\.\.\.(.*?)\[(.*?)\]:(\d+)\/(\d+)===(.*?);/){
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
      # right proto/port only with subnet
      elsif ($line =~ /: (.*)===(.*?)\[(.*?)\]\.\.\.(.*?)\[(.*?)\]:(\d+)\/(\d+)===(.*?);/){
        my $lsnet = $1;
        my $lip = $2;
        my $lid = $3;
        my $rip = $4;
        my $rid = $5;
        my $rproto = conv_protocol($6);
        my $rport = $7;
        my $rsnet = $8;
        my $lprotoport;
        my $rprotoport;
        $rprotoport = $rproto if ($rport == 0);
        $rprotoport = "$rproto/$rport" if ($rport != 0);
        ($lip, my $natt, my $natsrc, $rip, my $natdst) = nat_detect($lip, $rip);
        $tunnel_hash{$connectid}->{_lid} = conv_id($lid);
        $tunnel_hash{$connectid}->{_lip} = $lip;
        $tunnel_hash{$connectid}->{_lsnet} = $lsnet;
        $tunnel_hash{$connectid}->{_rid} = conv_id($rid);
        $tunnel_hash{$connectid}->{_rip} = $rip;
        $tunnel_hash{$connectid}->{_rsnet} = $rsnet;
        $tunnel_hash{$connectid}->{_rproto} = "$rproto";
        $tunnel_hash{$connectid}->{_rport} = "$rport";
        $tunnel_hash{$connectid}->{_natt} = $natt;
        $tunnel_hash{$connectid}->{_natsrc} = $natsrc;
        $tunnel_hash{$connectid}->{_natdst} = $natdst;
      }
      # left proto/port only with subnet
      elsif ($line =~ /: (.*)===(.*?)\[(.*?)\]:(\d+)\/(\d+)\.\.\.(.*?)\[(.*?)\]===(.*?);/){
        my $lsnet = $1;
        my $lip = $2;
        my $lid = $3;
        my $lproto = conv_protocol($4);
        my $lport = $5;
        my $rip = $6;
        my $rid = $7;
        my $rsnet = $8;
        my $lprotoport;
        my $rprotoport;
        $lprotoport = $lproto if ($lport == 0);
        $lprotoport = "$lproto/$lport" if ($lport != 0);
        ($lip, my $natt, my $natsrc, $rip, my $natdst) = nat_detect($lip, $rip);
        $tunnel_hash{$connectid}->{_lid} = conv_id($lid);
        $tunnel_hash{$connectid}->{_lip} = $lip;
        $tunnel_hash{$connectid}->{_lsnet} = $lsnet;
        $tunnel_hash{$connectid}->{_rid} = conv_id($rid);
        $tunnel_hash{$connectid}->{_rip} = $rip;
        $tunnel_hash{$connectid}->{_rsnet} = $rsnet;
        $tunnel_hash{$connectid}->{_lproto} = "$lproto";
        $tunnel_hash{$connectid}->{_lport} = "$lport";
        $tunnel_hash{$connectid}->{_natt} = $natt;
        $tunnel_hash{$connectid}->{_natsrc} = $natsrc;
        $tunnel_hash{$connectid}->{_natdst} = $natdst;
      }
      elsif ($line =~ /ESP.proposal:(.*?)\/(.*?)\/(.*)/){
        $tunnel_hash{$connectid}->{_encryption} = $1;
        $tunnel_hash{$connectid}->{_hash} = $2;
        $tunnel_hash{$connectid}->{_pfsgrp} = $3;
      }
      elsif ($line =~ /STATE_MAIN_I1/){
        $tunnel_hash{$connectid}->{_ikestate} = "init";
      }
      elsif ($line =~ /newest ISAKMP SA: (.*); newest IPsec SA: (.*);/){
        if ($tunnel_hash{$connectid}->{_newestike} ne 'n/a'){
          if ($tunnel_hash{$connectid}->{_newestike} lt $1){
            $tunnel_hash{$connectid}->{_newestike} = $1;
          }
        } else {
          $tunnel_hash{$connectid}->{_newestike} = $1;
        } 
        if ($tunnel_hash{$connectid}->{_newestspi} ne 'n/a'){
          if ($tunnel_hash{$connectid}->{newestspi} lt $2){
            $tunnel_hash{$connectid}->{_newestspi} = $2;
          }
        } else {
          $tunnel_hash{$connectid}->{_newestspi} = $2;
        }
      }
      elsif ($line =~ /ike_life: (.*?)s; ipsec_life: (.*?)s;/){
        $tunnel_hash{$connectid}->{_ikelife} = $1;
        $tunnel_hash{$connectid}->{_lifetime} = $2;
      }
      elsif ($line=~ /CAs: (.*?)\.\.\.(.*)/){
        $tunnel_hash{$connectid}->{_lca} = $1;
        $tunnel_hash{$connectid}->{_rca} = $2;
      }
      my $ike = $tunnel_hash{$connectid}->{_newestike};
      if ($ike ne 'n/a'){
        if ($line =~ /$ike:.*ISAKMP.SA.established.*EVENT_SA_REPLACE.in.(.*?)s;/)
        {
          $tunnel_hash{$connectid}->{_ikeexpire} = $1;
          my ($atime, $ike_lifetime, $ike_expire) = (-1, $tunnel_hash{$connectid}->{_ikelife}, $tunnel_hash{$connectid}->{_ikeexpire});
          $atime = $ike_lifetime - $ike_expire if (($ike_lifetime ne 'n/a') && ($ike_expire ne 'n/a'));

          if ($atime >= 0){
            $tunnel_hash{$connectid}->{_ikestate} = "up";
          }
        }
        if ($line =~ /$ike:.*ISAKMP.SA.established.*EVENT_SA_EXPIRE.in.(.*?)s;/)
        {
          $tunnel_hash{$connectid}->{_ikeexpire} = $1;
          my ($atime, $ike_lifetime, $ike_expire) = (-1, $tunnel_hash{$connectid}->{_ikelife}, $tunnel_hash{$connectid}->{_ikeexpire});
          $atime = $ike_lifetime - $ike_expire if (($ike_lifetime ne 'n/a') && ($ike_expire ne 'n/a'));

          if ($atime >= 0){
            $tunnel_hash{$connectid}->{_ikestate} = "up";
          }
        }
      }
      my $spi = $tunnel_hash{$connectid}->{_newestspi};
      if ($spi ne 'n/a'){
        if ($line =~ /$spi:.*esp.(.*)\@.*\((.*)bytes.*esp.(.*)\@.*/){
          $tunnel_hash{$connectid}->{_outspi} = $1;
          $tunnel_hash{$connectid}->{_outbytes} = $2;
          $tunnel_hash{$connectid}->{_inspi} = $3;
        }
        if ($line =~ /$spi:.*esp.(.*)\@.*esp.(.*)\@.*\((.*)bytes/){
          $tunnel_hash{$connectid}->{_outspi} = $1;
          $tunnel_hash{$connectid}->{_inspi} = $2;
          $tunnel_hash{$connectid}->{_inbytes} = $3;
        }
        if ($line =~ /$spi:.*esp.(.*)\@.*\((.*)bytes.*esp.(.*)\@.*\((.*)bytes/)
        {
          $tunnel_hash{$connectid}->{_outspi} = $1;
          $tunnel_hash{$connectid}->{_outbytes} = $2;
          $tunnel_hash{$connectid}->{_inspi} = $3;
          $tunnel_hash{$connectid}->{_inbytes} = $4;
        }
        if ($line =~ /$spi:.*?EVENT_SA_REPLACE.*? in (.*?)s;/){
          $tunnel_hash{$connectid}->{_expire} = $1;
          my ($atime, $esp_lifetime, $esp_expire) = (-1, $tunnel_hash{$connectid}->{_lifetime}, $tunnel_hash{$connectid}->{_expire});
          $atime = $esp_lifetime - $esp_expire if (($esp_lifetime ne 'n/a') && ($esp_expire ne 'n/a'));

          if ($atime >= 0){
            $tunnel_hash{$connectid}->{_state} = "up";
          } 
        }
        if ($line =~ /$spi:.*?EVENT_SA_EXPIRE in (.*?)s;/){
          $tunnel_hash{$connectid}->{_expire} = $1;
          my ($atime, $esp_lifetime, $esp_expire) = (-1, $tunnel_hash{$connectid}->{_lifetime}, $tunnel_hash{$connectid}->{_expire});
          $atime = $esp_lifetime - $esp_expire if (($esp_lifetime ne 'n/a') && ($esp_expire ne 'n/a'));

          if ($atime >= 0){
            $tunnel_hash{$connectid}->{_state} = "up";
          } 
        }
      }
    } elsif ($line =~ /^(peer-.*-tunnel-.*?)[{\[].*:\s+/) {
      my $connectid = $1;
      $connectid .= $2 if ($line =~ /(peer-.*-tunnel-.*?):(\[\d*\])/);
      $connectid =~ /peer-(.*)-tunnel-(.*)/;
      
      my ($peer, $tunid) = ($1, $2);
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
                  _lca         => undef,
                  _rca         => undef,
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

      $line =~ s/---.*\.\.\./.../g; # remove the next hop router for local-ip 0.0.0.0 case

      if ($line =~ /:\s+ESTABLISHED (.*), (.*?)\[(.*?)\]\.\.\.(.*?)\[(.*?)\]/) {
        my $lip = $2;
        my $lid = $3;
        my $rip = $4;
        my $rid = $5;
        ($lip, my $natt, my $natsrc, $rip, my $natdst) = nat_detect($lip, $rip);
        
        $tunnel_hash{$connectid}->{_lid} = conv_id($lid);
        $tunnel_hash{$connectid}->{_lip} = $lip;
        $tunnel_hash{$connectid}->{_rid} = conv_id($rid);
        $tunnel_hash{$connectid}->{_rip} = $rip;
        $tunnel_hash{$connectid}->{_natt} = $natt;
        $tunnel_hash{$connectid}->{_natsrc} = $natsrc;
        $tunnel_hash{$connectid}->{_natdst} = $natdst;

        # Pull stuff from running config (IKE/ESP lifetime, PFS group)
        my $vpncfg = new Vyatta::Config();
        $vpncfg->setLevel('vpn ipsec');
        my $esp_path = "default-esp-group";
        my $peer_path = "site-to-site peer $tunnel_hash{$connectid}->{_peerid}";
        if ($vpncfg->existsOrig("$peer_path tunnel $tunid esp-group")) {
          $esp_path = "tunnel $tunid esp-group";
        }
        my $esp_group = $vpncfg->returnEffectiveValue("$peer_path $esp_path");
        my $ike_group = $vpncfg->returnEffectiveValue("site-to-site peer $tunnel_hash{$connectid}->{_peerid} ike-group");
        my $pfs_group = $vpncfg->returnEffectiveValue("esp-group $esp_group pfs");
        $pfs_group = "default" if ($pfs_group eq 'enable');
        my $lifetime = $vpncfg->returnEffectiveValue("esp-group $esp_group lifetime");
        my $ikelife = $vpncfg->returnEffectiveValue("ike-group $ike_group lifetime");

        $tunnel_hash{$connectid}->{_lifetime} = $lifetime;
        $tunnel_hash{$connectid}->{_ikelife} = $ikelife;
        $tunnel_hash{$connectid}->{_pfsgrp} = $pfs_group;

      } elsif ($line =~ /\]:\s+IKE SPIs: .* (reauthentication|rekeying) (disabled|in .*)/) {
        $tunnel_hash{$connectid}->{_ikeexpire} = conv_time($2);

        my ($atime, $ike_lifetime, $ike_expire) = (-1, $tunnel_hash{$connectid}->{_ikelife}, $tunnel_hash{$connectid}->{_ikeexpire});
        $atime = $ike_lifetime - $ike_expire if (($ike_lifetime ne 'n/a') && ($ike_expire ne 'n/a'));

        $tunnel_hash{$connectid}->{_ikestate} = "up" if ($atime >= 0);

      } elsif ($line =~ /\]:\s+IKE.proposal:(.*?)\/(.*?)\/(.*?)\/(.*)/) {
        $tunnel_hash{$connectid}->{_ikeencrypt} = $1;
        $tunnel_hash{$connectid}->{_ikehash} = $2;
        $tunnel_hash{$connectid}->{_dhgrp} = $4;
      
      } elsif ($line =~ /{(\d+)}:\s+INSTALLED.*ESP.*SPIs: (.*)_i (.*)_o/) {
        $esp_hash{$connectid}{$1}->{_inspi} = $2;
        $esp_hash{$connectid}{$1}->{_outspi} = $3;

      } elsif ($line =~ /{(\d+)}:\s+(.*?)\/(.*?), (\d+) bytes_i.* (\d+) bytes_o.*rekeying (disabled|in .*)/) {
        my $esp_id = $1;
        $esp_hash{$connectid}{$esp_id}->{_encryption} = $2;
        $esp_hash{$connectid}{$esp_id}->{_hash} = $3;
        $esp_hash{$connectid}{$esp_id}->{_inbytes} = $4;
        $esp_hash{$connectid}{$esp_id}->{_outbytes} = $5;
        $esp_hash{$connectid}{$esp_id}->{_expire} = conv_time($6);

        my $last_used = 1000;
        $last_used = $1 if ($line =~ /\((\d+)s ago\)/);
        $esp_hash{$connectid}{$esp_id}->{last_used} = $last_used;

      } elsif ($line =~ /{(\d+)}:\s+(\d+\.\d+\.\d+\.\d+\/\d+(\[.*?\]){0,1}) === (\d+\.\d+\.\d+\.\d+\/\d+(\[.*?\]){0,1})/) {
        my ($esp_id, $_lsnet, $_lsproto, $_rsnet, $_rsproto) = ($1, $2, $3, $4, $5);

        if (defined($_lsproto)) {
          $_lsnet =~ s/\Q$_lsproto\E//g if ($_lsnet =~ /\Q$_lsproto\E/);
          $_lsproto =~ s/\[|\]//g;
        } else {
          $_lsproto = "all";
        }

        if (defined($_rsproto)) {
          $_rsnet =~ s/\Q$_rsproto\E//g if ($_rsnet =~ /\Q$_rsproto\E/);
          $_rsproto =~ s/\[|\]//g;
        } else {
          $_rsproto = "all";
        }

        $esp_hash{$connectid}{$esp_id}->{_lsnet} = $_lsnet;
        $esp_hash{$connectid}{$esp_id}->{_lproto} = $_lsproto;
        $esp_hash{$connectid}{$esp_id}->{_rsnet} = $_rsnet;
        $esp_hash{$connectid}{$esp_id}->{_rproto} = $_rsproto;
      }
    }
  }

  # Cleanse esp_hash
  foreach my $connectid (keys %esp_hash) {
    foreach my $esp_sa (keys %{$esp_hash{$connectid}}) {
      delete $esp_hash{$connectid}{$esp_sa} if (not defined($esp_hash{$connectid}{$esp_sa}{last_used}));
    }
  }

  # For each tunnel, loop through all ESP SA's and extract data from one most recently used
  foreach my $connectid (keys %esp_hash) {
    foreach my $esp_sa (reverse sort {$esp_hash{$a}{last_used} <=> $esp_hash{$b}{last_used}} keys %{$esp_hash{$connectid}}) {
      foreach my $data (keys %{$esp_hash{$connectid}{$esp_sa}}) {
        $tunnel_hash{$connectid}->{$data} = $esp_hash{$connectid}{$esp_sa}{$data} if ($data =~ /^_/);
      }
      my ($atime, $esp_lifetime, $esp_expire) = (-1, $tunnel_hash{$connectid}->{_lifetime}, $tunnel_hash{$connectid}->{_expire});
      $atime = $esp_lifetime - $esp_expire if (($esp_lifetime ne 'n/a') && ($esp_expire ne 'n/a'));
      $tunnel_hash{$connectid}->{_state} = "up" if ($atime >= 0);
      last;
    }
  }

  return %tunnel_hash;
}

sub conv_time {
  my @time = split(/\s+/, $_[0]);
  my ($rc, $multiply) = ("", 1);

  if ($time[0] eq 'disabled') {
    $rc = 0;
  } else {
    
    if ($time[2] =~ /minute/i) {
      $multiply = 60;
    } elsif ($time[2] =~ /hour/i) {
      $multiply = 3600;
    } elsif ($time[2] =~ /day/i) {
      $multiply = 86400;
    }

    $rc = $time[1] * $multiply;
  }
  
  return $rc;
}

sub get_conns
{
  my $cmd = "sudo cat /etc/ipsec.conf";
  open(my $IPSECCONF, '-|', $cmd);
  my @ipsecconf = [];
  while(<$IPSECCONF>){
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
    my $peerid = pop(@_);
    my %tunnel_hash = get_tunnel_info_peer($peerid);
    display_ipsec_sa_brief(\%tunnel_hash);
}

sub show_ipsec_sa_stats_peer
{
    my $peerid = pop(@_);
    my %tunnel_hash = get_tunnel_info_peer($peerid);
    display_ipsec_sa_stats(\%tunnel_hash);
}

sub show_ipsec_sa_stats_conn
{
    my %tmphash = ();
    (my $peerid, my $tun) = @_;
    my %th = get_tunnel_info_peer($peerid);
    for my $peer ( keys %th ) {
      if ($th{$peer}->{_tunnelnum} eq $tun){
        $tmphash{$peer} = \%{$th{$peer}};
      }
    }
    display_ipsec_sa_stats(\%tmphash);
}

sub show_ipsec_sa_peer_detail
{
    my $peerid = pop(@_);
    my %tunnel_hash = get_tunnel_info_peer($peerid);
    display_ipsec_sa_detail(\%tunnel_hash);
}

sub show_ipsec_sa_conn_detail
{
    my %tmphash = ();
    (my $peerid, my $tun) = @_;
    my %th = get_tunnel_info_peer($peerid);
    for my $peer ( keys %th ) {
      if ($th{$peer}->{_tunnelnum} eq $tun){
        $tmphash{$peer} = \%{$th{$peer}};
      }
    }
    display_ipsec_sa_detail(\%tmphash);
}

sub show_ipsec_sa_conn
{
    my %tmphash = ();
    (my $peerid, my $tun) = @_;
    my %th = get_tunnel_info_peer($peerid);
    for my $peer ( keys %th ) {
      if ($th{$peer}->{_tunnelnum} eq $tun){
        $tmphash{$peer} = \%{$th{$peer}};
      }
    }
    display_ipsec_sa_brief(\%tmphash);
}

sub get_connection_status
{
    (my $peerid, my $tun) = @_;
    my %th = get_tunnel_info_peer($peerid);
    for my $peer ( keys %th ) {
      if (%{$th{$peer}}->{_tunnelnum} eq $tun){
        return %{$th{$peer}}->{_state};
      }
    }
}
sub get_peer_ike_status
{
    my ($peerid) = @_;
    my %th = get_tunnel_info_peer($peerid);
    for my $peer ( keys %th ) {
      if (%{$th{$peer}}->{_ikestate} eq 'up'){
        return 'up';    
      }
      if (%{$th{$peer}}->{_ikestate} eq 'init'){
        return 'init';    
      }
    }
    return 'down';
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
sub show_ike_status{
  my $process_id = `sudo cat /var/run/charon.pid`;
  chomp $process_id;

  print <<EOS;
IKE Process Running 

PID: $process_id

EOS
  exit 0;
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
    my $peerid = pop(@_);
    my %tunnel_hash = get_tunnel_info_peer($peerid);
    display_ike_sa_brief(\%tunnel_hash);
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
    open(my $DAT, '<', $secret_file);
    my @raw_data=<$DAT>;
    close($DAT);
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
-----------                             -----------
EOH
        printf "%-39s %-39s\n", $lip, $pip;
        printf "%-39s %-39s\n\n", substr($lid,0,39), substr($pid,0,39);
        print "    Secret: $secret\n";
        print "\n \n";
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
    my $vpncfg = new Vyatta::Config();
    $vpncfg->setLevel('vpn ipsec site-to-site');
    for my $connectid (keys %th){  
      $peerid = conv_ip($th{$connectid}->{_rip});
      my $lip = conv_ip($th{$connectid}->{_lip});
      my $tunnel = "$peerid-$lip";
      my $peer_configured = conv_id_rev($th{$connectid}->{_peerid});
      if (not exists $tunhash{$tunnel}) {
        $tunhash{$tunnel} = {
          _outspi  => $th{$connectid}->{_outspi},
          _natt  => $th{$connectid}->{_natt},
          _lip  => $lip,
          _peerid => $peer_configured,
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
               $th{$connectid}->{_lproto},
               $th{$connectid}->{_expire});
      push (@{$tunhash{"$tunnel"}->{_tunnels}}, [ @tmp ]);
      
    }
    for my $connid (peerSort (keys %tunhash)){
    print <<EOH;
Peer ID / IP                            Local ID / IP               
------------                            -------------
EOH
      (my $peerid, my $myid) = $connid =~ /(.*?)-(.*)/;
      printf "%-39s %-39s\n", $peerid, $myid;
      my $desc = $vpncfg->returnEffectiveValue("peer $tunhash{$connid}->{_peerid} description");
      print "\n    Description: $desc\n" if (defined($desc));
      print <<EOH;

    Tunnel  State  Bytes Out/In   Encrypt  Hash    NAT-T  A-Time  L-Time  Proto
    ------  -----  -------------  -------  ----    -----  ------  ------  -----
EOH
      for my $tunnel (tunSort(@{$tunhash{$connid}->{_tunnels}})){
        (my $tunnum, my $state, my $inbytes, my $outbytes, 
         my $enc, my $hash, my $life, my $proto, my $expire) = @{$tunnel};
        my $lip = $tunhash{$connid}->{_lip};
        my $peerip = conv_ip($peerid);
        my $natt = $tunhash{$connid}->{_natt};
        my $bytesp = 'n/a';
        $enc = conv_enc($enc);
        $hash = conv_hash($hash);
        $natt = conv_natt($natt);
        if (!($inbytes eq 'n/a' && $outbytes eq 'n/a')){
          $outbytes = conv_bytes($outbytes);
          $inbytes = conv_bytes($inbytes);
          $bytesp = "$outbytes/$inbytes";
        }
        my $atime = $life - $expire;
        $atime = 0 if ($atime == $life);
        printf "    %-7s %-6s %-14s %-8s %-7s %-6s %-7s %-7s %-2s\n",
              $tunnum, $state, $bytesp, $enc, $hash, $natt, 
              $atime, $life, $proto;
      }
    print "\n \n";
    }
}
sub display_ipsec_sa_detail
{
    my %th = %{pop(@_)};
    my $listref = [];
    my %tunhash = ();
    my $myid = undef;
    my $peerid = undef;
    my $vpncfg = new Vyatta::Config();
    $vpncfg->setLevel('vpn ipsec site-to-site');
    for my $connectid (keys %th){  
      my $lip = conv_ip($th{$connectid}->{_lip});
      $peerid = conv_ip($th{$connectid}->{_rip});
      my $tunnel = "$peerid-$lip";
      
      if (not exists $tunhash{$tunnel}) {
        $tunhash{$tunnel} = {
          _peerip      => $th{$connectid}->{_rip},
          _peerid      => $th{$connectid}->{_rid},
          _configpeer  => conv_id_rev($th{$connectid}->{_peerid}),
          _localip     => $th{$connectid}->{_lip},
          _localid     => $th{$connectid}->{_lid},
          _dhgrp       => $th{$connectid}->{_dhgrp},
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
               $th{$connectid}->{_lsnet},
               $th{$connectid}->{_rsnet},
               $th{$connectid}->{_inbytes},
               $th{$connectid}->{_outbytes},
               $th{$connectid}->{_lifetime},
               $th{$connectid}->{_expire},
               $th{$connectid}->{_lca},
               $th{$connectid}->{_rca},
               $th{$connectid}->{_lproto},
               $th{$connectid}->{_rproto},
               $th{$connectid}->{_lport},
               $th{$connectid}->{_rport} );
      push (@{$tunhash{$tunnel}->{_tunnels}}, [ @tmp ]);
    }
    for my $connid (peerSort(keys %tunhash)){
      my $natt = conv_natt($tunhash{$connid}->{_natt});
      my $peerip = conv_ip($tunhash{$connid}->{_peerip});
      my $localid = $tunhash{$connid}->{_localid};
      if ($localid =~ /CN=(.*?),/){
        $localid = $1;
      }
      my $peerid = $tunhash{$connid}->{_peerid};
      if ($peerid =~ /CN=(.*?),/){
        $peerid = $1;
      }
      my $desc = $vpncfg->returnEffectiveValue("peer $tunhash{$connid}->{_configpeer} description");
      print "------------------------------------------------------------------\n";
      print "Peer IP:\t\t$peerip\n";
      print "Peer ID:\t\t$peerid\n";
      print "Local IP:\t\t$tunhash{$connid}->{_localip}\n";
      print "Local ID:\t\t$localid\n";
      print "NAT Traversal:\t\t$natt\n";
      print "NAT Source Port:\t$tunhash{$connid}->{_natsrc}\n";
      print "NAT Dest Port:\t\t$tunhash{$connid}->{_natdst}\n";
      print "\nDescription:\t\t$desc\n" if (defined($desc));
      print "\n";
      for my $tunnel (tunSort(@{$tunhash{$connid}->{_tunnels}})){
        (my $tunnum, my $state, my $inspi, my $outspi, my $enc,
         my $hash, my $pfsgrp, my $srcnet, my $dstnet,
         my $inbytes, my $outbytes, my $life, my $expire, my $lca, 
         my $rca, my $lproto, my $rproto, my $lport, my $rport) = @{$tunnel};
        $enc = conv_enc($enc);
        $hash = conv_hash($hash);
        $lport = 'all' if ($lport eq '0');
        $rport = 'all' if ($rport eq '0');
        $pfsgrp = conv_dh_group($pfsgrp);
        
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
        print "        PFS Group:\t\t$pfsgrp\n";
        if (defined $lca){
        print "        \n";
          print "        CA:\n";
          foreach my $field (split(', ', $lca)){
            $field=~s/\"//g;
            print "            $field\n";
          }
        }
        #print "        Local CA:\t\t$lca\n" if defined($lca);
        #print "        Right CA:\t\t$rca\n" if defined($rca);
        print "        \n";
        print "        Local Net:\t\t$srcnet\n";
        print "        Local Protocol:\t\t$lproto\n";
        print "        Local Port: \t\t$lport\n";
        print "        \n";
        print "        Remote Net:\t\t$dstnet\n";
        print "        Remote Protocol:\t$rproto\n";
        print "        Remote Port: \t\t$rport\n";
        print "        \n";
        print "        Inbound Bytes:\t\t$inbytes\n";
        print "        Outbound Bytes:\t\t$outbytes\n";
        print "        Active Time (s):\t$atime\n";
        print "        Lifetime (s):\t\t$life\n";
        print "    \n";
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
    my $vpncfg = new Vyatta::Config();
    $vpncfg->setLevel('vpn ipsec site-to-site');
    for my $connectid (keys %th){  
      my $lip = conv_ip($th{$connectid}->{_lip});
      $peerid = conv_ip($th{$connectid}->{_rip});
      my $tunnel = "$peerid-$lip";
      
      if (not exists $tunhash{$tunnel}) {
        $tunhash{$tunnel}={
          _configpeer  => conv_id_rev($th{$connectid}->{_peerid}),
          _tunnels     => []
        };
      }
        my @tmp = ( $th{$connectid}->{_tunnelnum},
               $th{$connectid}->{_lsnet},
               $th{$connectid}->{_rsnet},
               $th{$connectid}->{_inbytes},
               $th{$connectid}->{_outbytes} );
        push (@{$tunhash{$tunnel}->{_tunnels}}, [ @tmp ]);
    }
    for my $connid (peerSort(keys %tunhash)){
    print <<EOH;
Peer ID / IP                            Local ID / IP               
------------                            -------------
EOH
      (my $peerid, my $myid) = $connid =~ /(.*?)-(.*)/;
      printf "%-39s %-39s\n", $peerid, $myid;
      my $desc = $vpncfg->returnEffectiveValue("peer $tunhash{$connid}->{_configpeer} description");
      print "\n  Description: $desc\n" if (defined($desc));
      print <<EOH;

  Tunnel Dir Source Network               Destination Network          Bytes
  ------ --- --------------               -------------------          -----
EOH
      for my $tunnel (tunSort(@{$tunhash{$connid}->{_tunnels}})){
        (my $tunnum, my $srcnet, my $dstnet, 
         my $inbytes, my $outbytes) = @{$tunnel};
        printf "  %-6s %-3s %-28s %-28s %-8s\n",
	      $tunnum, 'in', $dstnet, $srcnet, $inbytes;
        printf "  %-6s %-3s %-28s %-28s %-8s\n",
	      $tunnum, 'out', $srcnet, $dstnet, $outbytes;
      }
      print "\n \n";
    }
}

sub display_ike_sa_brief {
    my %th = %{pop(@_)};
    my $listref = [];
    my %tunhash = ();
    my $myid = undef;
    my $peerid = undef;
    my $vpncfg = new Vyatta::Config();
    $vpncfg->setLevel('vpn ipsec site-to-site');
    for my $connectid (keys %th){  
      my $lip = $th{$connectid}->{_lip};
      $peerid = $th{$connectid}->{_rip};
      my $tunnel = "$peerid-$lip";
      next if ($th{$connectid}->{_ikestate} eq 'down');
      if (not exists $tunhash{$tunnel}) {
        $tunhash{$tunnel}={
          _configpeer => conv_id_rev($th{$connectid}->{_peerid}),
          _tunnels => []
        };
      }
        my @tmp = ( $th{$connectid}->{_tunnelnum},
               $th{$connectid}->{_ikestate},
               $th{$connectid}->{_newestike},
               $th{$connectid}->{_ikeencrypt},
               $th{$connectid}->{_ikehash},
               $th{$connectid}->{_dhgrp},
               $th{$connectid}->{_natt},
               $th{$connectid}->{_ikelife},
               $th{$connectid}->{_ikeexpire} );
        push (@{$tunhash{$tunnel}->{_tunnels}}, [ @tmp ]);
      
    }
    for my $connid (peerSort(keys %tunhash)){
    print <<EOH;
Peer ID / IP                            Local ID / IP               
------------                            -------------
EOH
      (my $peerid, my $myid) = $connid =~ /(.*?)-(.*)/;
      printf "%-39s %-39s\n", $peerid, $myid;
      my $desc = $vpncfg->returnEffectiveValue("peer $tunhash{$connid}->{_configpeer} description");
      print "\n    Description: $desc\n" if (defined($desc));
      print <<EOH;

    State  Encrypt  Hash    D-H Grp  NAT-T  A-Time  L-Time
    -----  -------  ----    -------  -----  ------  ------
EOH
      for my $tunnel (tunSort(@{$tunhash{$connid}->{_tunnels}})){
        (my $tunnum, my $state, my $isakmpnum, my $enc, 
         my $hash, my $dhgrp, my $natt, my $life, my $expire) = @{$tunnel};
        $enc = conv_enc($enc);
        $hash = conv_hash($hash);
        $natt = conv_natt($natt);
        $dhgrp = conv_dh_group($dhgrp);
        my $atime = $life - $expire;
        $atime = 0 if ($atime == $life);
        printf "    %-6s %-8s %-7s %-8s %-6s %-7s %-7s\n",
               $state, $enc, $hash, $dhgrp, $natt, $atime, $life;
      }
      print "\n \n";
    }
}
1;
