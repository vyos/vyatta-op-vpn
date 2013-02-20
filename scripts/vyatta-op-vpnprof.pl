#!/usr/bin/perl
#
# Module: vyatta-op-vpnprof.pl
#
use Getopt::Long;
use Data::Dumper;
use lib "/opt/vyatta/share/perl5/";
use Vyatta::vpnprof::OPMode;

use strict;

my (
    $get_profiles_for_cli,  $get_conn_for_cli,
    $show_ipsec_sa,         $show_ipsec_sa_detail,
    $show_ipsec_sa_profile, $show_ipsec_sa_profile_detail,
    $show_ipsec_sa_stats,   $show_ipsec_sa_stats_profile
);
my @show_ipsec_sa_stats_conn;
my @show_ipsec_sa_conn_detail;
my @show_ipsec_sa_conn;

GetOptions(
    "show-ipsec-sa!"                 => \$show_ipsec_sa,
    "show-ipsec-sa-detail!"          => \$show_ipsec_sa_detail,
    "get-profiles-for-cli!"          => \$get_profiles_for_cli,
    "get-conn-for-cli=s"             => \$get_conn_for_cli,
    "show-ipsec-sa-profile=s"        => \$show_ipsec_sa_profile,
    "show-ipsec-sa-profile-detail=s" => \$show_ipsec_sa_profile_detail,
    "show-ipsec-sa-stats!"           => \$show_ipsec_sa_stats,
    "show-ipsec-sa-stats-profile=s"  => \$show_ipsec_sa_stats_profile,
    "show-ipsec-sa-stats-conn=s{2}"  => \@show_ipsec_sa_stats_conn,
    "show-ipsec-sa-conn-detail=s{2}" => \@show_ipsec_sa_conn_detail,
    "show-ipsec-sa-conn=s{2}"        => \@show_ipsec_sa_conn
);

if ( defined $get_profiles_for_cli ) {
    Vyatta::vpnprof::OPMode::get_profiles_for_cli();
}
if ( defined $get_conn_for_cli ) {
    Vyatta::vpnprof::OPMode::get_conn_for_cli($get_conn_for_cli);
}
if ( defined $show_ipsec_sa ) {
    Vyatta::vpnprof::OPMode::show_ipsec_sa();
}
if ( defined $show_ipsec_sa_detail ) {
    Vyatta::vpnprof::OPMode::show_ipsec_sa_detail();
}
if ( defined $show_ipsec_sa_profile ) {
    Vyatta::vpnprof::OPMode::show_ipsec_sa_profile($show_ipsec_sa_profile);
}
if ( defined $show_ipsec_sa_profile_detail ) {
    Vyatta::vpnprof::OPMode::show_ipsec_sa_profile_detail(
        $show_ipsec_sa_profile_detail);
}
if ( defined @show_ipsec_sa_conn_detail ) {
    Vyatta::vpnprof::OPMode::show_ipsec_sa_conn_detail(
        @show_ipsec_sa_conn_detail);
}
if ( defined @show_ipsec_sa_conn ) {
    Vyatta::vpnprof::OPMode::show_ipsec_sa_conn(@show_ipsec_sa_conn);
}
if ( defined $show_ipsec_sa_stats ) {
    Vyatta::vpnprof::OPMode::show_ipsec_sa_stats();
}
if ( defined $show_ipsec_sa_stats_profile ) {
    Vyatta::vpnprof::OPMode::show_ipsec_sa_stats_profile(
        $show_ipsec_sa_stats_profile);
}
if ( defined @show_ipsec_sa_stats_conn ) {
    Vyatta::vpnprof::OPMode::show_ipsec_sa_stats_conn(
        @show_ipsec_sa_stats_conn);
}

