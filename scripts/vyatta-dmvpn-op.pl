#!/usr/bin/perl -w

use strict;
use warnings;
use lib "/opt/vyatta/share/perl5/";
use Vyatta::Config;
use Getopt::Long;
my $op           = '';
my $profile      = undef;
my $tunnel       = undef;
my $profile_path = 'vpn ipsec profile';

GetOptions(
    "op=s"      => \$op,
    "profile=s" => \$profile,
    "tunnel=s"  => \$tunnel
);

sub get_tunnels {
    my $profile = undef;
    $profile = shift;
    my @profile_tunnels = ();
    if ( defined $profile ) {
        my $config = new Vyatta::Config;
        @profile_tunnels =
          $config->listOrigNodes("$profile_path $profile bind tunnel");
    }
    return @profile_tunnels;
}

sub clear_tunnel {
    my ( $profile, $tunnel ) = @_;
    my $error = undef;
    my $cmd   = undef;

    print "Resetting tunnel $tunnel with profile $profile...\n";

    # turn down the connection
    `sudo ipsec down vpnprof-tunnel-$tunnel`;

    # sleep for 1/4th of a second for connection to go down
    `sudo sleep 0.25`;

# turn connection up. For conns with 'right=%any' it's useless to up, so commented it
#`sudo ipsec up vpnprof-tunnel-$tunnel`;

    # sleep for 3/4th of a second for connection to come up
    #`sudo sleep 0.75`;

    my @addresses = split( ' ',
        `cli-shell-api returnActiveValues interfaces tunnel $tunnel address` );
    for my $addr (@addresses) {
        $addr =~ /'(.*)\.(.*)\.(.*)\.(.*)\//;
        my $pattern = "$1.$2.$3.$4-to-";
        my $line    = `sudo ipsec statusall | grep $pattern | head -n 1`;
        if ( $line =~ /\"(.*-to-.*)\"/ ) {
            my $conn = $1;
            `sudo ipsec down $conn`;

#Actually, we don't need timeouts here cause this script will wait child process to be finished.
            `sudo ipsec up $conn`;
        }
    }

}

if ( $op eq '' ) {
    die 'No op specified';
}

if ( $op eq 'get-all-profiles' ) {

    # get all ipsec profiles
    my $config   = new Vyatta::Config;
    my @profiles = ();
    @profiles = $config->listOrigNodes("$profile_path");
    print "@profiles\n";

}
elsif ( $op eq 'get-tunnels-for-profile' ) {

    # get all tunnels for a specific profile
    die 'Undefined profile to get list of tunnels for' if !defined $profile;
    my @profile_tunnels = get_tunnels("$profile");
    print "@profile_tunnels\n";

}
elsif ( $op eq 'clear-tunnels-for-profile' ) {

    # clear all tunnels for a given profile
    die 'Undefined profile to clear tunnels for' if !defined $profile;
    my @profile_tunnels = get_tunnels("$profile");
    if ( scalar(@profile_tunnels) > 0 ) {
        foreach my $tun ( sort @profile_tunnels ) {
            clear_tunnel( $profile, $tun );
        }
    }

}
elsif ( $op eq 'clear-specific-tunnel-for-profile' ) {

    # clear a specific tunnel for a given profile
    die 'Undefined profile to clear tunnel for' if !defined $profile;
    die 'Undefined tunnel for profile $profile' if !defined $tunnel;
    my @profile_tunnels = get_tunnels("$profile");
    if ( scalar( grep( /^$tunnel$/, @profile_tunnels ) ) > 0 ) {
        clear_tunnel( $profile, $tunnel );
    }
    else {
        die "Undefined tunnel $tunnel for profile $profile\n";
    }

}
else {
    die "Unknown op: $op";
}

exit 0;
