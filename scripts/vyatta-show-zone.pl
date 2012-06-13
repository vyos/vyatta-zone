#!/usr/bin/env perl
use lib "/opt/vyatta/share/perl5/";
use Vyatta::Zone;
use Getopt::Long;
my $zone_in;
GetOptions("zone=s" => \$zone_in);

my $zone_hash = Vyatta::Zone::get_zone_hash();
my $format = "  %-40s%-40s\n";
for my $zone (sort(keys %{$zone_hash})) {
   if (defined $zone_in){
     next unless $zone eq $zone_in;
   }
   print "-------------------\n";
   print "Name: $zone" . 
     (defined($zone_hash->{$zone}{'description'}) 
       ? " [$zone_hash->{$zone}{'description'}]\n" : "\n");
   print "\n";
   print "Interfaces: @{$zone_hash->{$zone}{'interfaces'}}\n";
   print "\n";
   print "From Zone:\n";
   printf($format, "name", "firewall");
   printf($format, "----", "--------");
   for my $from_zone (sort(keys(%{$zone_hash->{$zone}{'from'}}))){
     my ($firewall, $ipv6_firewall, $ci);
     $firewall = $zone_hash->{$zone}{'from'}->{$from_zone}{'firewall'}->{'ipv4'}
       if (defined($zone_hash->{$zone}{'from'}->{$from_zone}{'firewall'}->{'ipv4'}));
     $ipv6_firewall = $zone_hash->{$zone}{'from'}->{$from_zone}{'firewall'}->{'ipv6'}
       if (defined($zone_hash->{$zone}{'from'}->{$from_zone}{'firewall'}->{'ipv6'}));
     if (defined($firewall)){
       printf($format, "$from_zone", "$firewall");
       if (defined($ipv6_firewall)){
         printf($format, "", "$ipv6_firewall [v6]");
       }
     } elsif (defined($ipv6_firewall)){
       printf($format, "$from_zone", "$ipv6_firewall [v6]");
     } else {
       printf($format, "$from_zone", "-");
     }
   }
   print "\n";
}
