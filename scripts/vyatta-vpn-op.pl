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

sub clear_tunnel {
  my ($peer, $tunnel) = @_;
  my $error = undef;
  my $cmd = undef;
  
  print "Clearing tunnel $tunnel with peer $peer...\n";

  # back-up ipsec.conf
  `sudo cp /etc/ipsec.conf /etc/ipsec.conf.bak.\$PPID`;

  # remove specific connection from ipsec.conf
  `sudo sed -i -e '/conn peer-$peer-tunnel-$tunnel/,/#conn peer-$peer-tunnel-$tunnel/d' /etc/ipsec.conf`;

  # update ipsec connections
  `sudo /usr/sbin/ipsec update >&/dev/null`;

  # sleep for 1/4th of a second for connection to go down
  `sudo sleep 0.25`;

  # move original ipsec.conf back
  `sudo mv /etc/ipsec.conf.bak.\$PPID /etc/ipsec.conf`;

  # update ipsec connections
  `sudo /usr/sbin/ipsec update >&/dev/null`;

  # sleep for 3/4th of a second for connection to come up
  # this gives us sometime before bringing clearing another tunnel
  `sudo sleep 0.75`;
}

if ($op eq '') {
	die 'No op specified';
}

if ($op eq 'clear-vpn-ipsec-process') {
	system 'sudo /usr/sbin/ipsec restart';

} elsif ($op eq 'show-vpn-debug') {
	system 'sudo /usr/sbin/ipsec status';

} elsif ($op eq 'show-vpn-debug-detail') {
	system 'sudo /usr/sbin/ipsec statusall';

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
    die "No tunnel defined for peer $peer\n";
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

} else { 
  die "Unknown op: $op";
}
 
exit 0;
