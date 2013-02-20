#!/usr/bin/perl
#
# Module Vyatta::vpnprof::OpMode.pm
#

package Vyatta::vpnprof::OPMode;

use lib "/opt/vyatta/share/perl5/";
use Vyatta::VPN::Util;
use Vyatta::Config;
use strict;

sub conv_id {
    my $peer = pop(@_);
    if ( $peer =~ /\d+\.\d+\.\d+\.\d+/ ) {
        $peer = $peer;
    }
    elsif ( $peer =~ /\d+\:\d+\:\d+\:\d+\:\d+\:\d+\:\d+\:\d+/ ) {
        $peer = $peer;
    }
    elsif ( $peer =~ /\%any/ ) {
        $peer = "any";
    }
    else {
        $peer = "\@$peer";
    }
    return $peer;
}

sub conv_dh_group {
    my $dhgrp    = pop(@_);
    my $dh_group = '';
    if ( $dhgrp eq "MODP_768" ) {
        $dh_group = 1;
    }
    elsif ( $dhgrp eq "MODP_1024" ) {
        $dh_group = 2;
    }
    elsif ( $dhgrp eq "MODP_1536" ) {
        $dh_group = 5;
    }
    elsif ( $dhgrp eq "MODP_2048" ) {
        $dh_group = 7;
    }
    elsif ( $dhgrp eq "<N/A>" ) {
        $dh_group = "n/a";
    }
    else {
        $dh_group = $dhgrp;
    }
    return $dh_group;
}

sub conv_hash {
    my $hash = pop(@_);
    if ( $hash =~ /.*_(.*)/ ) {
        $hash = lc($1);
    }
    return $hash;
}

sub conv_enc {
    my $enc = pop(@_);
    if ( $enc =~ /(.*?)_.*?_(.*)/ ) {
        $enc = lc($1) . $2;
        $enc =~ s/^ //g;
    }
    elsif ( $enc =~ /3DES/ ) {
        $enc = "3des";
    }
    return $enc;
}

sub conv_natt {
    my $natt = pop(@_);
    if ( $natt == 0 ) {
        $natt = "no";
    }
    else {
        $natt = "yes";
    }
    return $natt;
}

sub conv_id_rev {
    my $peerid = pop(@_);
    if ( $peerid =~ /@(.*)/ ) {
        $peerid = $1;
    }
    return $peerid;
}

sub conv_bytes {
    my $bytes  = pop(@_);
    my $suffix = '';
    $bytes =~ s/\s+$//;
    if ( $bytes > 1024 && $bytes < 1048576 ) {
        $bytes  = $bytes / 1024;
        $suffix = "K";
    }
    elsif ( $bytes >= 1048576 && $bytes < 1073741824 ) {
        $bytes  = $bytes / 1048576;
        $suffix = "M";
    }
    elsif ( $bytes >= 1073741824 ) {
        $bytes  = $bytes / 1073741824;
        $suffix = "G";
    }
    $bytes = sprintf( "%.1f", $bytes );
    $bytes = "$bytes$suffix";
}

sub conv_ip {
    my $peerip = pop(@_);
    if ( $peerip =~ /\@.*/ ) {
        $peerip = "0.0.0.0";
    }
    elsif ( $peerip =~ /\%any/ ) {
        $peerip = "0.0.0.0";
    }
    return $peerip;
}

sub nat_detect {
    ( my $lip, my $rip ) = @_;
    my @values;
    if ( $lip =~ /(\d+\.\d+\.\d+\.\d+):(\d+)/ ) {
        push( @values, $1 );
        push( @values, 1 );
        push( @values, $2 );
    }
    else {
        push( @values, $lip );
        push( @values, 0 );
        push( @values, 'n/a' );
    }
    if ( $rip =~ /(\d+\.\d+\.\d+\.\d+):(\d+)/ ) {
        push( @values, $1 );
        push( @values, $2 );
    }
    else {
        push( @values, $rip );
        push( @values, 'n/a' );
    }
    return @values;
}

sub get_tunnel_info {
    my $cmd = "sudo ipsec statusall";
    open( my $IPSECSTATUS,, '-|', $cmd );
    my @ipsecstatus = [];
    while (<$IPSECSTATUS>) {
        push( @ipsecstatus, $_ );
    }
    process_tunnels( \@ipsecstatus );
}

sub get_tunnel_info_profile {
    my $profile = pop(@_);
    my @tunnels = split(
        ' ',
        `cli-shell-api listActiveNodes vpn ipsec profile $profile bind tunnel`
    );

    my $static_conn_str = "vpnprof-tunnel-\\(";
    my $first_tun       = 1;
    for my $tun (@tunnels) {
        if ($first_tun) {
        }
        else {
            $static_conn_str .= "\\|";
        }
        $static_conn_str .= substr $tun, 1, -1;
        $first_tun = 0;
    }
    $static_conn_str .= "\\)";

    my $dyn_conn_str = "\\(";
    my $first_addr   = 1;
    for my $tun (@tunnels) {
        my @addresses = split( ' ',
            `cli-shell-api returnActiveValues interfaces tunnel $tun address` );
        for my $addr (@addresses) {
            if ($first_addr) {
            }
            else {
                $dyn_conn_str .= "\\|";
            }
            $dyn_conn_str .= substr $addr, 1, -4;
            $first_addr = 0;
        }
    }

    $dyn_conn_str .= "\\)-to-";

    my $search_str = "\\($static_conn_str\\)\\|\\($dyn_conn_str\\)";
    my $cmd        = "sudo ipsec statusall | grep \"$search_str\"";
    open( my $IPSECSTATUS,, '-|', $cmd );
    my @ipsecstatus = [];
    while (<$IPSECSTATUS>) {
        push( @ipsecstatus, $_ );
    }
    process_tunnels( \@ipsecstatus );
}

sub process_tunnels {
    my @ipsecstatus = @{ pop(@_) };
    my %tunnel_hash = ();
    foreach my $line (@ipsecstatus) {
        if (   ( $line =~ /\"(vpnprof-tunnel-.*?)\"/ )
            || ( $line =~ /\"(.*-to-.*)\"/ ) )
        {
            my $connectid = $1;
            if ( ( $line =~ /\"(vpnprof-tunnel-.*?)\"(\[\d*\])/ ) ) {
                $connectid .= $2;
            }
            my $tunid = "";
            if ( ( $connectid =~ /vpnprof-tunnel-(.*)/ ) ) {
                $tunid = $1;
            }
            else {

                # this is for whack connection, we are to find tunid for it.
                $line =~ /\"(.*)-to-(.*)\"/;
                my $lip = $1;

                my @tunnels = split( ' ',
                    `cli-shell-api listActiveNodes interfaces tunnel` );
                for my $tun (@tunnels) {
                    my @addresses = split(
                        ' ',
`cli-shell-api returnActiveValues interfaces tunnel $tun address`
                    );
                    for my $addr (@addresses) {
                        my $tst = index $addr, $lip;
                        if ( $tst > -1 ) {
                            $tunid = substr $tun, 1, -1;
                        }
                    }
                }
            }
            if ( not exists $tunnel_hash{$connectid} ) {
                $tunnel_hash{$connectid} = {
                    _peerid     => undef,
                    _tunnelnum  => $tunid,
                    _lip        => 'n/a',
                    _rip        => 'n/a',
                    _lid        => 'n/a',
                    _rid        => 'n/a',
                    _lsnet      => 'n/a',
                    _rsnet      => 'n/a',
                    _lproto     => 'all',
                    _rproto     => 'all',
                    _lport      => 'all',
                    _rport      => 'all',
                    _lca        => undef,
                    _rca        => undef,
                    _newestspi  => 'n/a',
                    _newestike  => 'n/a',
                    _encryption => 'n/a',
                    _hash       => 'n/a',
                    _inspi      => 'n/a',
                    _outspi     => 'n/a',
                    _pfsgrp     => 'n/a',
                    _ikeencrypt => 'n/a',
                    _ikehash    => 'n/a',
                    _natt       => 'n/a',
                    _natsrc     => 'n/a',
                    _natdst     => 'n/a',
                    _ikestate   => "down",
                    _dhgrp      => 'n/a',
                    _state      => "down",
                    _inbytes    => 'n/a',
                    _outbytes   => 'n/a',
                    _ikelife    => 'n/a',
                    _ikeexpire  => 'n/a',
                    _lifetime   => 'n/a',
                    _expire     => 'n/a'
                };
            }
            $line =~ s/---.*\.\.\./.../g
              ;    # remove the next hop router for local-ip 0.0.0.0 case
            if ( $line =~ /IKE.proposal:(.*?)\/(.*?)\/(.*)/ ) {
                $tunnel_hash{$connectid}->{_ikeencrypt} = $1;
                $tunnel_hash{$connectid}->{_ikehash}    = $2;
                $tunnel_hash{$connectid}->{_dhgrp}      = $3;
            }

            # both subnets
            elsif ( $line =~
                /: (.*?)===(.*?)\[(.*?)\]\.\.\.(.*?)\[(.*?)\]===(.*?);/ )
            {
                my $lsnet = $1;
                my $lip   = $2;
                my $lid   = $3;
                my $rip   = $4;
                my $rid   = $5;
                my $rsnet = $6;
                ( $lip, my $natt, my $natsrc, $rip, my $natdst ) =
                  nat_detect( $lip, $rip );
                $tunnel_hash{$connectid}->{_lid}    = conv_id($lid);
                $tunnel_hash{$connectid}->{_lip}    = $lip;
                $tunnel_hash{$connectid}->{_lsnet}  = $lsnet;
                $tunnel_hash{$connectid}->{_rid}    = conv_id($rid);
                $tunnel_hash{$connectid}->{_rip}    = $rip;
                $tunnel_hash{$connectid}->{_rsnet}  = $rsnet;
                $tunnel_hash{$connectid}->{_natt}   = $natt;
                $tunnel_hash{$connectid}->{_natsrc} = $natsrc;
                $tunnel_hash{$connectid}->{_natdst} = $natdst;
            }

            #left subnet
            elsif ( $line =~ /: (.*?)\[(.*?)\]\.\.\.(.*?)\[(.*?)\];/ ) {
                my $lip = $1;
                my $lid = $2;
                my $rip = $3;
                my $rid = $4;
                my $lsnet;
                if ( $lip =~ /(.*?)===(.*)/ ) {
                    $lsnet = $1;
                    $lip   = $2;
                }
                ( $lip, my $natt, my $natsrc, $rip, my $natdst ) =
                  nat_detect( $lip, $rip );
                $tunnel_hash{$connectid}->{_lid}    = conv_id($lid);
                $tunnel_hash{$connectid}->{_lip}    = $lip;
                $tunnel_hash{$connectid}->{_rid}    = conv_id($rid);
                $tunnel_hash{$connectid}->{_rip}    = $rip;
                $tunnel_hash{$connectid}->{_natt}   = $natt;
                $tunnel_hash{$connectid}->{_natsrc} = $natsrc;
                $tunnel_hash{$connectid}->{_natdst} = $natdst;
                $tunnel_hash{$connectid}->{_lsnet}  = $lsnet
                  if ( defined($lsnet) );
            }

            #left subnet with protocols
            elsif ( $line =~
/: (.*?)\[(.*?)\]:(\d+)\/(\d+)\.\.\.(.*?)\[(.*?)\]:(\d+)\/(\d+);/
              )
            {
                my $lip = $1;
                my $lsnet;
                my $lid    = $2;
                my $lproto = conv_protocol($3);
                my $lport  = $4;
                my $rip    = $5;
                my $rid    = $6;
                my $rproto = conv_protocol($7);
                my $rport  = $8;
                if ( $lip =~ /(.*?)===(.*)/ ) {
                    $lsnet = $1;
                    $lip   = $2;
                }
                ( $lip, my $natt, my $natsrc, $rip, my $natdst ) =
                  nat_detect( $lip, $rip );
                $tunnel_hash{$connectid}->{_lid}   = conv_id($lid);
                $tunnel_hash{$connectid}->{_lip}   = $lip;
                $tunnel_hash{$connectid}->{_lsnet} = $lsnet
                  if ( defined($lsnet) );
                $tunnel_hash{$connectid}->{_rid}    = conv_id($rid);
                $tunnel_hash{$connectid}->{_rip}    = $rip;
                $tunnel_hash{$connectid}->{_natt}   = $natt;
                $tunnel_hash{$connectid}->{_natsrc} = $natsrc;
                $tunnel_hash{$connectid}->{_natdst} = $natdst;
                $tunnel_hash{$connectid}->{_lproto} = "$lproto";
                $tunnel_hash{$connectid}->{_rproto} = "$rproto";
                $tunnel_hash{$connectid}->{_lport}  = "$lport";
                $tunnel_hash{$connectid}->{_rport}  = "$rport";
            }

            # both proto/port and subnets
            elsif ( $line =~
/: (.*)===(.*?)\[(.*?)\]:(\d+)\/(\d+)\.\.\.(.*?)\[(.*?)\]:(\d+)\/(\d+)===(.*?);/
              )
            {
                my $lsnet  = $1;
                my $lip    = $2;
                my $lid    = $3;
                my $lproto = conv_protocol($4);
                my $lport  = $5;
                my $rip    = $6;
                my $rid    = $7;
                my $rproto = conv_protocol($8);
                my $rport  = $9;
                my $rsnet  = $10;
                my $lprotoport;
                my $rprotoport;
                $lprotoport = $lproto          if ( $lport == 0 );
                $lprotoport = "$lproto/$lport" if ( $lport != 0 );
                $rprotoport = $rproto          if ( $rport == 0 );
                $rprotoport = "$rproto/$rport" if ( $rport != 0 );
                ( $lip, my $natt, my $natsrc, $rip, my $natdst ) =
                  nat_detect( $lip, $rip );
                $tunnel_hash{$connectid}->{_lid}    = conv_id($lid);
                $tunnel_hash{$connectid}->{_lip}    = $lip;
                $tunnel_hash{$connectid}->{_lsnet}  = $lsnet;
                $tunnel_hash{$connectid}->{_rid}    = conv_id($rid);
                $tunnel_hash{$connectid}->{_rip}    = $rip;
                $tunnel_hash{$connectid}->{_rsnet}  = $rsnet;
                $tunnel_hash{$connectid}->{_lproto} = "$lproto";
                $tunnel_hash{$connectid}->{_rproto} = "$rproto";
                $tunnel_hash{$connectid}->{_lport}  = "$lport";
                $tunnel_hash{$connectid}->{_rport}  = "$rport";
                $tunnel_hash{$connectid}->{_natt}   = $natt;
                $tunnel_hash{$connectid}->{_natsrc} = $natsrc;
                $tunnel_hash{$connectid}->{_natdst} = $natdst;
            }

            # right proto/port only with subnet
            elsif ( $line =~
/: (.*)===(.*?)\[(.*?)\]\.\.\.(.*?)\[(.*?)\]:(\d+)\/(\d+)===(.*?);/
              )
            {
                my $lsnet  = $1;
                my $lip    = $2;
                my $lid    = $3;
                my $rip    = $4;
                my $rid    = $5;
                my $rproto = conv_protocol($6);
                my $rport  = $7;
                my $rsnet  = $8;
                my $lprotoport;
                my $rprotoport;
                $rprotoport = $rproto          if ( $rport == 0 );
                $rprotoport = "$rproto/$rport" if ( $rport != 0 );
                ( $lip, my $natt, my $natsrc, $rip, my $natdst ) =
                  nat_detect( $lip, $rip );
                $tunnel_hash{$connectid}->{_lid}    = conv_id($lid);
                $tunnel_hash{$connectid}->{_lip}    = $lip;
                $tunnel_hash{$connectid}->{_lsnet}  = $lsnet;
                $tunnel_hash{$connectid}->{_rid}    = conv_id($rid);
                $tunnel_hash{$connectid}->{_rip}    = $rip;
                $tunnel_hash{$connectid}->{_rsnet}  = $rsnet;
                $tunnel_hash{$connectid}->{_rproto} = "$rproto";
                $tunnel_hash{$connectid}->{_rport}  = "$rport";
                $tunnel_hash{$connectid}->{_natt}   = $natt;
                $tunnel_hash{$connectid}->{_natsrc} = $natsrc;
                $tunnel_hash{$connectid}->{_natdst} = $natdst;
            }

            # left proto/port only with subnet
            elsif ( $line =~
/: (.*)===(.*?)\[(.*?)\]:(\d+)\/(\d+)\.\.\.(.*?)\[(.*?)\]===(.*?);/
              )
            {
                my $lsnet  = $1;
                my $lip    = $2;
                my $lid    = $3;
                my $lproto = conv_protocol($4);
                my $lport  = $5;
                my $rip    = $6;
                my $rid    = $7;
                my $rsnet  = $8;
                my $lprotoport;
                my $rprotoport;
                $lprotoport = $lproto          if ( $lport == 0 );
                $lprotoport = "$lproto/$lport" if ( $lport != 0 );
                ( $lip, my $natt, my $natsrc, $rip, my $natdst ) =
                  nat_detect( $lip, $rip );
                $tunnel_hash{$connectid}->{_lid}    = conv_id($lid);
                $tunnel_hash{$connectid}->{_lip}    = $lip;
                $tunnel_hash{$connectid}->{_lsnet}  = $lsnet;
                $tunnel_hash{$connectid}->{_rid}    = conv_id($rid);
                $tunnel_hash{$connectid}->{_rip}    = $rip;
                $tunnel_hash{$connectid}->{_rsnet}  = $rsnet;
                $tunnel_hash{$connectid}->{_lproto} = "$lproto";
                $tunnel_hash{$connectid}->{_lport}  = "$lport";
                $tunnel_hash{$connectid}->{_natt}   = $natt;
                $tunnel_hash{$connectid}->{_natsrc} = $natsrc;
                $tunnel_hash{$connectid}->{_natdst} = $natdst;
            }
            elsif ( $line =~ /ESP.proposal:(.*?)\/(.*?)\/(.*)/ ) {
                $tunnel_hash{$connectid}->{_encryption} = $1;
                $tunnel_hash{$connectid}->{_hash}       = $2;
                $tunnel_hash{$connectid}->{_pfsgrp}     = $3;
            }
            elsif ( $line =~ /STATE_MAIN_I1/ ) {
                $tunnel_hash{$connectid}->{_ikestate} = "init";
            }
            elsif ( $line =~ /newest ISAKMP SA: (.*); newest IPsec SA: (.*);/ )
            {
                if ( $tunnel_hash{$connectid}->{_newestike} ne 'n/a' ) {
                    if ( $tunnel_hash{$connectid}->{_newestike} lt $1 ) {
                        $tunnel_hash{$connectid}->{_newestike} = $1;
                    }
                }
                else {
                    $tunnel_hash{$connectid}->{_newestike} = $1;
                }
                if ( $tunnel_hash{$connectid}->{_newestspi} ne 'n/a' ) {
                    if ( $tunnel_hash{$connectid}->{newestspi} lt $2 ) {
                        $tunnel_hash{$connectid}->{_newestspi} = $2;
                    }
                }
                else {
                    $tunnel_hash{$connectid}->{_newestspi} = $2;
                }
            }
            elsif ( $line =~ /ike_life: (.*?)s; ipsec_life: (.*?)s;/ ) {
                $tunnel_hash{$connectid}->{_ikelife}  = $1;
                $tunnel_hash{$connectid}->{_lifetime} = $2;
            }
            elsif ( $line =~ /CAs: (.*?)\.\.\.(.*)/ ) {
                $tunnel_hash{$connectid}->{_lca} = $1;
                $tunnel_hash{$connectid}->{_rca} = $2;
            }
            my $ike = $tunnel_hash{$connectid}->{_newestike};
            if ( $ike ne 'n/a' ) {
                if ( $line =~
                    /$ike:.*ISAKMP.SA.established.*EVENT_SA_REPLACE.in.(.*?)s;/
                  )
                {
                    $tunnel_hash{$connectid}->{_ikeexpire} = $1;
                    my $atime =
                      $tunnel_hash{$connectid}->{_ikelife} -
                      $tunnel_hash{$connectid}->{_ikeexpire};
                    if ( $atime >= 0 ) {
                        $tunnel_hash{$connectid}->{_ikestate} = "up";
                    }
                }
                if ( $line =~
                    /$ike:.*ISAKMP.SA.established.*EVENT_SA_EXPIRE.in.(.*?)s;/ )
                {
                    $tunnel_hash{$connectid}->{_ikeexpire} = $1;
                    my $atime =
                      $tunnel_hash{$connectid}->{_ikelife} -
                      $tunnel_hash{$connectid}->{_ikeexpire};
                    if ( $atime >= 0 ) {
                        $tunnel_hash{$connectid}->{_ikestate} = "up";
                    }
                }
            }
            my $spi = $tunnel_hash{$connectid}->{_newestspi};
            if ( $spi ne 'n/a' ) {
                if ( $line =~ /$spi:.*esp.(.*)\@.*\((.*)bytes.*esp.(.*)\@.*/ ) {
                    $tunnel_hash{$connectid}->{_outspi}   = $1;
                    $tunnel_hash{$connectid}->{_outbytes} = $2;
                    $tunnel_hash{$connectid}->{_inspi}    = $3;
                }
                if ( $line =~ /$spi:.*esp.(.*)\@.*esp.(.*)\@.*\((.*)bytes/ ) {
                    $tunnel_hash{$connectid}->{_outspi}  = $1;
                    $tunnel_hash{$connectid}->{_inspi}   = $2;
                    $tunnel_hash{$connectid}->{_inbytes} = $3;
                }
                if ( $line =~
                    /$spi:.*esp.(.*)\@.*\((.*)bytes.*esp.(.*)\@.*\((.*)bytes/ )
                {
                    $tunnel_hash{$connectid}->{_outspi}   = $1;
                    $tunnel_hash{$connectid}->{_outbytes} = $2;
                    $tunnel_hash{$connectid}->{_inspi}    = $3;
                    $tunnel_hash{$connectid}->{_inbytes}  = $4;
                }
                if ( $line =~ /$spi:.*?EVENT_SA_REPLACE.*? in (.*?)s;/ ) {
                    $tunnel_hash{$connectid}->{_expire} = $1;
                    my $atime =
                      $tunnel_hash{$connectid}->{_lifetime} -
                      $tunnel_hash{$connectid}->{_expire};
                    if ( $atime >= 0 ) {
                        $tunnel_hash{$connectid}->{_state} = "up";
                    }
                }
                if ( $line =~ /$spi:.*?EVENT_SA_EXPIRE in (.*?)s;/ ) {
                    $tunnel_hash{$connectid}->{_expire} = $1;
                    my $atime =
                      $tunnel_hash{$connectid}->{_lifetime} -
                      $tunnel_hash{$connectid}->{_expire};
                    if ( $atime >= 0 ) {
                        $tunnel_hash{$connectid}->{_state} = "up";
                    }
                }
            }
        }
    }
    return %tunnel_hash;
}

sub get_conns {
    my $cmd = "sudo cat /etc/dmvpn.conf";
    open( my $IPSECCONF, '-|', $cmd );
    my @ipsecconf = [];
    while (<$IPSECCONF>) {
        push( @ipsecconf, $_ );
    }
    my %th = ();
    for my $line (@ipsecconf) {
        next if ( $line =~ /^\#/ );
        if ( $line =~ /vpnprof-tunnel-(.*)/ ) {
            my $tun = $1;
            if ( not exists $th{$tun} ) {
                $th{$tun} = {
                    _conns => [$tun],
                    _tunid => $tun
                };
            }
            else {
                push( @{ $th{$tun}->{_conns} }, $tun );
            }
        }
    }
    return %th;
}

sub get_profiles_for_cli {
    my @profiles =
      split( ' ', `cli-shell-api listActiveNodes vpn ipsec profile` );
    for my $prof (@profiles) {
        print substr $prof, 1, -1;
        print "\n";
    }
}

sub get_conn_for_cli {
    my $profileid = pop(@_);
    my %th        = get_conns();
    for my $tun ( keys %th ) {
        for my $conn ( @{ $th{$tun}->{_conns} } ) {
            print "$conn\n";
        }
    }
}

sub profileSort {

  #TODO: It's not used now. Should implement smth meaningfull or delete this sub
    sort { $a->[0] <=> $b->[0]; } @_;
}

sub tunSort {

#TODO: not used now. Early it was sorting tun ids as numbers, but now we have 'tunX' as tunid.
    sort { $a->[0] <=> $b->[0]; } @_;
}

sub show_ipsec_sa {
    my %tunnel_hash = get_tunnel_info();
    display_ipsec_sa_brief( \%tunnel_hash );
}

sub show_ipsec_sa_detail {
    my %tunnel_hash = get_tunnel_info();
    display_ipsec_sa_detail( \%tunnel_hash );
}

sub show_ipsec_sa_stats {
    my %tunnel_hash = get_tunnel_info();
    display_ipsec_sa_stats( \%tunnel_hash );
}

sub show_ipsec_sa_profile {
    my $profile     = pop(@_);
    my %tunnel_hash = get_tunnel_info_profile($profile);
    display_ipsec_sa_brief( \%tunnel_hash );
}

sub show_ipsec_sa_stats_profile {
    my $profile     = pop(@_);
    my %tunnel_hash = get_tunnel_info_profile($profile);
    display_ipsec_sa_stats( \%tunnel_hash );
}

sub show_ipsec_sa_stats_conn {
    my %tmphash = ();
    ( my $profileid, my $tun ) = @_;
    my %th = get_tunnel_info_profile($profileid);
    for my $profile ( keys %th ) {
        if ( $th{$profile}->{_tunnelnum} eq $tun ) {
            $tmphash{$profile} = \%{ $th{$profile} };
        }
    }
    display_ipsec_sa_stats( \%tmphash );
}

sub show_ipsec_sa_profile_detail {
    my $profileid   = pop(@_);
    my %tunnel_hash = get_tunnel_info_profile($profileid);
    display_ipsec_sa_detail( \%tunnel_hash );
}

sub show_ipsec_sa_conn_detail {
    my %tmphash = ();
    ( my $profileid, my $tun ) = @_;
    my %th = get_tunnel_info_profile($profileid);
    for my $profile ( keys %th ) {
        if ( $th{$profile}->{_tunnelnum} eq $tun ) {
            $tmphash{$profile} = \%{ $th{$profile} };
        }
    }
    display_ipsec_sa_detail( \%tmphash );
}

sub show_ipsec_sa_conn {
    my %tmphash = ();
    ( my $profileid, my $tun ) = @_;
    my %th = get_tunnel_info_profile($profileid);
    for my $profile ( keys %th ) {
        if ( $th{$profile}->{_tunnelnum} eq $tun ) {
            $tmphash{$profile} = \%{ $th{$profile} };
        }
    }
    display_ipsec_sa_brief( \%tmphash );
}

sub display_ipsec_sa_brief {
    my %th      = %{ pop(@_) };
    my $listref = [];
    my %tunhash = ();
    my $myid    = undef;
    my $peerid  = undef;
    for my $connectid ( keys %th ) {
        $peerid = conv_ip( $th{$connectid}->{_rip} );
        my $lip             = conv_ip( $th{$connectid}->{_lip} );
        my $tunnel          = "$peerid-$lip";
        my $peer_configured = conv_id_rev( $th{$connectid}->{_peerid} );
        if ( not exists $tunhash{$tunnel} ) {
            $tunhash{$tunnel} = {
                _outspi  => $th{$connectid}->{_outspi},
                _natt    => $th{$connectid}->{_natt},
                _lip     => $lip,
                _peerid  => $peer_configured,
                _tunnels => []
            };
        }
        my @tmp = (
            $th{$connectid}->{_tunnelnum},  $th{$connectid}->{_state},
            $th{$connectid}->{_inbytes},    $th{$connectid}->{_outbytes},
            $th{$connectid}->{_encryption}, $th{$connectid}->{_hash},
            $th{$connectid}->{_lifetime},   $th{$connectid}->{_lproto},
            $th{$connectid}->{_expire}
        );
        push( @{ $tunhash{"$tunnel"}->{_tunnels} }, [@tmp] );

    }
    for my $connid ( keys %tunhash ) {
        print <<EOH;
Peer ID / IP                            Local ID / IP
------------                            -------------
EOH
        ( my $peerid, my $myid ) = $connid =~ /(.*?)-(.*)/;
        printf "%-39s %-39s\n", $peerid, $myid;
        print <<EOH;

    Tunnel  State  Bytes Out/In   Encrypt  Hash  NAT-T  A-Time  L-Time  Proto
    ------  -----  -------------  -------  ----  -----  ------  ------  -----
EOH
        for my $tunnel ( @{ $tunhash{$connid}->{_tunnels} } ) {
            (
                my $tunnum,
                my $state,
                my $inbytes,
                my $outbytes,
                my $enc,
                my $hash,
                my $life,
                my $proto,
                my $expire
            ) = @{$tunnel};
            my $lip    = $tunhash{$connid}->{_lip};
            my $peerip = conv_ip($peerid);
            my $natt   = $tunhash{$connid}->{_natt};
            my $bytesp = 'n/a';
            $enc  = conv_enc($enc);
            $hash = conv_hash($hash);
            $natt = conv_natt($natt);

            if ( !( $inbytes eq 'n/a' && $outbytes eq 'n/a' ) ) {
                $outbytes = conv_bytes($outbytes);
                $inbytes  = conv_bytes($inbytes);
                $bytesp   = "$outbytes/$inbytes";
            }
            my $atime = $life - $expire;
            $atime = 0 if ( $atime == $life );
            printf "    %-7s %-6s %-14s %-8s %-5s %-6s %-7s %-7s %-2s\n",
              $tunnum, $state, $bytesp, $enc, $hash, $natt,
              $atime, $life, $proto;
        }
        print "\n \n";
    }
}

sub display_ipsec_sa_detail {
    my %th      = %{ pop(@_) };
    my $listref = [];
    my %tunhash = ();
    my $myid    = undef;
    my $peerid  = undef;
    for my $connectid ( keys %th ) {
        my $lip = conv_ip( $th{$connectid}->{_lip} );
        $peerid = conv_ip( $th{$connectid}->{_rip} );
        my $tunnel = "$peerid-$lip";

        if ( not exists $tunhash{$tunnel} ) {
            $tunhash{$tunnel} = {
                _peerip     => $th{$connectid}->{_rip},
                _peerid     => $th{$connectid}->{_rid},
                _configpeer => conv_id_rev( $th{$connectid}->{_peerid} ),
                _localip    => $th{$connectid}->{_lip},
                _localid    => $th{$connectid}->{_lid},
                _dhgrp      => $th{$connectid}->{_dhgrp},
                _natt       => $th{$connectid}->{_natt},
                _natsrc     => $th{$connectid}->{_natsrc},
                _natdst     => $th{$connectid}->{_natdst},
                _tunnels    => []
            };
        }
        my @tmp = (
            $th{$connectid}->{_tunnelnum},  $th{$connectid}->{_state},
            $th{$connectid}->{_inspi},      $th{$connectid}->{_outspi},
            $th{$connectid}->{_encryption}, $th{$connectid}->{_hash},
            $th{$connectid}->{_pfsgrp},     $th{$connectid}->{_lsnet},
            $th{$connectid}->{_rsnet},      $th{$connectid}->{_inbytes},
            $th{$connectid}->{_outbytes},   $th{$connectid}->{_lifetime},
            $th{$connectid}->{_expire},     $th{$connectid}->{_lca},
            $th{$connectid}->{_rca},        $th{$connectid}->{_lproto},
            $th{$connectid}->{_rproto},     $th{$connectid}->{_lport},
            $th{$connectid}->{_rport}
        );
        push( @{ $tunhash{$tunnel}->{_tunnels} }, [@tmp] );
    }
    for my $connid ( keys %tunhash ) {
        my $natt    = conv_natt( $tunhash{$connid}->{_natt} );
        my $peerip  = conv_ip( $tunhash{$connid}->{_peerip} );
        my $localid = $tunhash{$connid}->{_localid};
        if ( $localid =~ /CN=(.*?),/ ) {
            $localid = $1;
        }
        my $peerid = $tunhash{$connid}->{_peerid};
        if ( $peerid =~ /CN=(.*?),/ ) {
            $peerid = $1;
        }
        print
"------------------------------------------------------------------\n";
        print "Peer IP:\t\t$peerip\n";
        print "Peer ID:\t\t$peerid\n";
        print "Local IP:\t\t$tunhash{$connid}->{_localip}\n";
        print "Local ID:\t\t$localid\n";
        print "NAT Traversal:\t\t$natt\n";
        print "NAT Source Port:\t$tunhash{$connid}->{_natsrc}\n";
        print "NAT Dest Port:\t\t$tunhash{$connid}->{_natdst}\n";
        print "\n";

        for my $tunnel ( tunSort( @{ $tunhash{$connid}->{_tunnels} } ) ) {
            (
                my $tunnum,
                my $state,
                my $inspi,
                my $outspi,
                my $enc,
                my $hash,
                my $pfsgrp,
                my $srcnet,
                my $dstnet,
                my $inbytes,
                my $outbytes,
                my $life,
                my $expire,
                my $lca,
                my $rca,
                my $lproto,
                my $rproto,
                my $lport,
                my $rport
            ) = @{$tunnel};
            $enc    = conv_enc($enc);
            $hash   = conv_hash($hash);
            $lport  = 'all' if ( $lport eq '0' );
            $rport  = 'all' if ( $rport eq '0' );
            $pfsgrp = conv_dh_group($pfsgrp);

            my $atime = $life - $expire;
            $atime    = 0 if ( $atime == $life );
            $inbytes  = conv_bytes($inbytes);
            $outbytes = conv_bytes($outbytes);

            print "    Tunnel $tunnum:\n";
            print "        State:\t\t\t$state\n";
            print "        Inbound SPI:\t\t$inspi\n";
            print "        Outbound SPI:\t\t$outspi\n";
            print "        Encryption:\t\t$enc\n";
            print "        Hash:\t\t\t$hash\n";
            print "        PFS Group:\t\t$pfsgrp\n";
            if ( defined $lca ) {
                print "        \n";
                print "        CA:\n";
                foreach my $field ( split( ', ', $lca ) ) {
                    $field =~ s/\"//g;
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

sub display_ipsec_sa_stats {
    my %th      = %{ pop(@_) };
    my $listref = [];
    my %tunhash = ();
    my $myid    = undef;
    my $peerid  = undef;
    for my $connectid ( keys %th ) {
        my $lip = conv_ip( $th{$connectid}->{_lip} );
        $peerid = conv_ip( $th{$connectid}->{_rip} );
        my $tunnel = "$peerid-$lip";

        if ( not exists $tunhash{$tunnel} ) {
            $tunhash{$tunnel} = {
                _configpeer => conv_id_rev( $th{$connectid}->{_peerid} ),
                _tunnels    => []
            };
        }
        my @tmp = (
            $th{$connectid}->{_tunnelnum}, $th{$connectid}->{_lsnet},
            $th{$connectid}->{_rsnet},     $th{$connectid}->{_inbytes},
            $th{$connectid}->{_outbytes}
        );
        push( @{ $tunhash{$tunnel}->{_tunnels} }, [@tmp] );
    }
    for my $connid ( keys %tunhash ) {
        print <<EOH;
Peer ID / IP                            Local ID / IP
------------                            -------------
EOH
        ( my $peerid, my $myid ) = $connid =~ /(.*?)-(.*)/;
        printf "%-39s %-39s\n", $peerid, $myid;
        print <<EOH;

  Tunnel Dir Source Network               Destination Network          Bytes
  ------ --- --------------               -------------------          -----
EOH
        for my $tunnel ( tunSort( @{ $tunhash{$connid}->{_tunnels} } ) ) {
            ( my $tunnum, my $srcnet, my $dstnet, my $inbytes, my $outbytes ) =
              @{$tunnel};
            printf "  %-6s %-3s %-28s %-28s %-8s\n",
              $tunnum, 'in', $dstnet, $srcnet, $inbytes;
            printf "  %-6s %-3s %-28s %-28s %-8s\n",
              $tunnum, 'out', $srcnet, $dstnet, $outbytes;
        }
        print "\n \n";
    }
}
1;
