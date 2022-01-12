#!/usr/bin/perl -w

use strict;
use warnings;
use lib "/opt/vyatta/share/perl5/";
use Vyatta::Config;
use Getopt::Long;
my $op='';
my $peer=undef;
my $tunnel=undef;
my $s2s_peer_path='vpn ipsec site-to-site peer';

GetOptions( "op=s"      => \$op,
            "peer=s"    => \$peer,
            "tunnel=s"  => \$tunnel);

sub numerically { $a <=> $b; }

sub get_tunnels {
  my $s2s_peer = undef;
  $s2s_peer = shift;
  my @peer_tunnels = ();
  if (defined $s2s_peer) {
    my $config = new Vyatta::Config;
    @peer_tunnels = $config->listOrigNodes("$s2s_peer_path $s2s_peer tunnel");
  }
  return @peer_tunnels;
}

sub get_vtis {
  my $s2s_peer = undef;
  $s2s_peer = shift;
  my @peer_tunnels = ();
  if (defined $s2s_peer) {
    my $config = new Vyatta::Config;
    @peer_tunnels = $config->listOrigNodes("$s2s_peer_path $s2s_peer vti");
  }
  return @peer_tunnels;
}

sub clear_tunnel {
  my ($peer, $tunnel) = @_;
  my $error = undef;
  my $cmd = undef;

  $peer =~ s/@//;
  
  print "Resetting tunnel $tunnel with peer $peer...\n";
  
  # bring down the tunnel
  `sudo /usr/sbin/ipsec down peer-$peer-tunnel-$tunnel\{\*\}`;
  # bring up the tunnel
  `sudo /usr/sbin/ipsec up peer-$peer-tunnel-$tunnel`;
}

if ($op eq '') {
	die 'No op specified';
}

if ($op eq 'clear-vpn-ipsec-process') {
	print "Restarting IPsec process...\n";
  my $update_interval = `cli-shell-api returnActiveValue vpn ipsec auto-update`;
  if ($update_interval eq ''){
	  system 'sudo /usr/sbin/ipsec restart >&/dev/null';
          # Check if nhrp configuration exists, exit code
          # As 'restart vpn' doesn't load nhrp configuration T3846
          if (system('cli-shell-api existsActive protocols nhrp') == 0) {
              # Set a small timeout for waiting for charon will be loaded
              # 0 => process not found, 1 => process found
              my $timeout = 7;
              if (system("pgrep charon | wc -l" eq 0)) {
                  while ($timeout >= 1){
                    sleep(1);
                    if (system("pgrep charon | wc -l" eq 1)){
                      last;
                    }
                    $timeout--;
                  }
              }
              system 'sudo swanctl --load-all';
          }
  } else {
    system 'sudo /usr/sbin/ipsec restart --auto-update '.$update_interval.' >&/dev/null';
  }

} elsif ($op eq 'show-vpn-debug') {
	system 'sudo /usr/sbin/ipsec statusall';

} elsif ($op eq 'show-vpn-debug-detail') {
	system 'sudo /usr/lib/ipsec/barf';

} elsif ($op eq 'get-all-peers') {
  # get all site-to-site peers
  my $config = new Vyatta::Config;
  my @peers = ();
  @peers = $config->listOrigNodes("$s2s_peer_path");
  print "@peers\n";

} elsif ($op eq 'get-tunnels-for-peer') {
  # get all tunnels for a specific site-to-site peer
  die 'Undefined peer to get list of tunnels for' if ! defined $peer;
  my @peer_tunnels = get_tunnels("$peer");
  print "@peer_tunnels\n";

} elsif ($op eq 'clear-tunnels-for-peer') {
  # clear all tunnels for a given site-to-site peer
  die 'Undefined peer to clear tunnels for' if ! defined $peer;
  my @peer_tunnels = get_tunnels("$peer");
  if (scalar(@peer_tunnels)>0) {
    foreach my $tun (sort numerically @peer_tunnels) {
      clear_tunnel($peer, $tun);
    }
  } else {
    my @peer_vtis = get_vtis("$peer");
    if (scalar(@peer_vtis)>0) {
        clear_tunnel($peer, 'vti');
    } else {
        die "No tunnel defined for peer $peer\n";
    }
  }

} elsif ($op eq 'clear-specific-tunnel-for-peer') {
  # clear a specific tunnel for a given site-to-site peer
  die 'Undefined peer to clear tunnel for' if ! defined $peer;
  die 'Undefined tunnel for peer $peer' if ! defined $tunnel;
  my @peer_tunnels = get_tunnels("$peer");
  if (scalar(grep(/^$tunnel$/,@peer_tunnels))>0) {
    clear_tunnel($peer, $tunnel);
  } else {
    die "Undefined tunnel $tunnel for peer $peer\n";
  }

} elsif ($op eq 'clear-vtis-for-peer') {
  # clear all vti for a given site-to-site peer
  die 'Undefined peer to clear vti for' if ! defined $peer;
  my @peer_vtis = get_vtis("$peer");
  if (scalar(@peer_vtis)>0) {
      clear_tunnel($peer, 'vti');
  } else {
    die "No vti defined for peer $peer\n";
  }

} else { 
  die "Unknown op: $op";
}
 
exit 0;
