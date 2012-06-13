# Module: Zone.pm
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
# Portions created by Vyatta are Copyright (C) 2009 Vyatta, Inc.
# All Rights Reserved.
#
# Author: Mohit Mehta
# Date: 2009
# Description: vyatta zone management
#
# **** End License ****
#

package Vyatta::Zone;

use Vyatta::Config;
use Vyatta::Misc;
use Vyatta::Interface;
use Vyatta::IpTables::Mgr;

use strict;
use warnings;

use base 'Exporter';

# mapping from config node to iptables command
our %cmd_hash = ( 'name'        => '/sbin/iptables',
                  'ipv6-name'   => '/sbin/ip6tables');

# mapping from config node to iptables/ip6tables table
our %table_hash = ( 'name'        => 'filter',
                    'ipv6-name'   => 'filter');

# mapping from zone default action to iptables jump target
our %policy_hash = ( 'drop'    => 'DROP',
                     'reject'  => 'REJECT',
                     'accept'  => 'RETURN');

our @EXPORT_OK = qw(%cmd_hash %table_hash %policy_hash);

my %get_zone_chain_hash = (
    get_zone_chain     => \&get_zone_chain,
);

my $debug="false";
my $syslog="false";
my $logger = 'sudo logger -t zone.pm -p local0.warn --';

my %script_to_feature_hash = (
        'vyatta-zone.pl'        => 'ZONE-FW');

sub run_cmd {
    my $cmd = shift;
    my $error = system("$cmd");

    if ($syslog eq "true") {
        my $func = (caller(1))[3];
        my $feature = zone_feature((caller(1))[1]);
        system("$logger [$feature] [$func] [$cmd] = [$error]");
    }
    if ($debug eq "true") {
        my $func = (caller(1))[3];
        my $feature = zone_feature((caller(1))[1]);
        print "[$feature] [$func] [$cmd] = [$error]\n";
    }
    return $error;
}

sub zone_feature {
  my ($script) = @_;
  $script =~ s/\/opt\/vyatta\/sbin\///;
  return $script_to_feature_hash{$script};
}

sub is_fwruleset_active {
    my ($value_func, $ruleset_type, $fw_ruleset) = @_;
    my $config = new Vyatta::Config;
    return $config->$value_func("firewall $ruleset_type $fw_ruleset");
}

sub get_all_zones {
    my $value_func = shift;
    my $config = new Vyatta::Config;
    return $config->$value_func("zone-policy zone");
}

sub get_zone_interfaces {
    my ($value_func, $zone_name) = @_;
    my $config = new Vyatta::Config;
    return $config->$value_func("zone-policy zone $zone_name interface");
}

sub get_from_zones {
    my ($value_func, $zone_name) = @_;
    my $config = new Vyatta::Config;
    return $config->$value_func("zone-policy zone $zone_name from");
}

sub get_firewall_ruleset {
    my ($value_func, $zone_name, $from_zone, $firewall_type) = @_;
    my $config = new Vyatta::Config;
    return $config->$value_func("zone-policy zone $zone_name from $from_zone
        firewall $firewall_type");
}

sub is_local_zone {
    my ($value_func, $zone_name) = @_;
    my $config = new Vyatta::Config;
    return $config->$value_func("zone-policy zone $zone_name local-zone");
}

sub get_zone_default_policy {
    my ($value_func, $zone_name) = @_;
    my $config = new Vyatta::Config;
    return $config->$value_func("zone-policy zone $zone_name default-action");
}

sub rule_exists {
    my ($command, $table, $chain_name, $target, $interface) = @_;
    my $cmd =
        "sudo $command -t $table -L " .
        "$chain_name -v 2>/dev/null | grep \" $target \" ";
    if (defined $interface) {
      $cmd .= "| grep \" $interface \" ";
    }
    $cmd .= "| wc -l";
    my $result = `$cmd`;
    return $result;
}

sub get_zone_chain {
    my ($value_func, $zone, $localout) = @_;
    my $chain_prefix = "VZONE_$zone"; # should be same length as ips_zone_chain
    return get_zone_chain_name($value_func, $zone, $localout, $chain_prefix);
}

sub get_zone_chain_name {
    my ($value_func, $zone, $localout, $chain_prefix) = @_;
    my $chain = $chain_prefix;
    if (defined(is_local_zone($value_func, $zone))) {
      # local zone
      if (defined $localout) {
        # local zone out chain
        $chain .= "_OUT";
      } else {
        # local zone in chain
        $chain .= "_IN";
      }
    }
    return $chain;
}

sub validity_checks {
    my @all_zones = get_all_zones("listNodes");
    my @all_interfaces = ();
    my $num_local_zones = 0;
    my $returnstring;
    foreach my $zone (@all_zones) {
      # get all from zones, see if they exist in config, if not display error
      my @from_zones = get_from_zones("listNodes", $zone);
      foreach my $from_zone (@from_zones) {
        if (scalar(grep(/^$from_zone$/, @all_zones)) == 0) {
          $returnstring = "$from_zone is a from zone under zone $zone\n" . 
		"It is either not defined or deleted from config";
          return ($returnstring, );
        }
      }
      my @zone_intfs = get_zone_interfaces("returnValues", $zone);
      if (scalar(@zone_intfs) == 0) {
        # no interfaces defined for this zone
        if (!defined(is_local_zone("exists", $zone))) {
          $returnstring = "Zone $zone has no interfaces defined " .  
				"and it's not a local-zone";
          return($returnstring, );
        }
        # zone defined as a local-zone
        my @zone_intfs_orig = get_zone_interfaces("returnOrigValues", $zone);
        if (scalar(@zone_intfs_orig) != 0) {
          # can't change change transit zone to local-zone on the fly
          $returnstring = "Zone $zone is a transit zone. " .
                "Cannot convert it to local-zone.\n" .
                "Please define another zone to create local-zone";
          return($returnstring, );
        }
        $num_local_zones++;
        # make sure only one zone is a local-zone
        if ($num_local_zones > 1) {
          return ("Only one zone can be defined as a local-zone", );
        }
      } else {
        # zone has interfaces, make sure it is not set as a local-zone
        if (defined(is_local_zone("exists", $zone))) {
          $returnstring = "local-zone cannot have interfaces defined";
          return($returnstring, );
        }
        # make sure you're not converting local-zone to transit zone either
        if (defined(is_local_zone("existsOrig", $zone))) {
          $returnstring = "Cannot convert local-zone $zone to transit zone" .  
				"\nPlease define another zone for it";
          return($returnstring, );
        }
        foreach my $interface (@zone_intfs) {
          # make sure zone features are not being used on zone interface
          my $intf = new Vyatta::Interface($interface);
          if ($intf) {
            my $config = new Vyatta::Config;
            $config->setLevel($intf->path());
            # make sure firewall is not applied to this interface
            if ($config->exists("firewall in name") ||
                $config->exists("firewall out name") ||
                $config->exists("firewall local name") ||
                $config->exists("firewall in ipv6-name") ||
                $config->exists("firewall out ipv6-name") ||
                $config->exists("firewall local ipv6-name")) {
              $returnstring =
                        "interface $interface has firewall rule-set " .
                        "configured, cannot be defined under a zone";
              return($returnstring, );
            }
          }
          # make sure an interface is not defined under two zones
          if (scalar(grep(/^$interface$/, @all_interfaces)) > 0) {
            return ("$interface defined under two zones", );
          } else {
            push(@all_interfaces, $interface);
          }
        }
      }
    }
    return;
}

sub create_zone_chain {
    my ($feature_func, $zone_name, $localoutchain) = @_;
    my ($cmd, $error);
    my $zone_chain=$get_zone_chain_hash{$feature_func}->("exists",
                        $zone_name, $localoutchain);

    # create zone chains in filter, ip6filter tables
    foreach my $tree (keys %cmd_hash) {
     $cmd = "sudo $cmd_hash{$tree} -t $table_hash{$tree} " .
                "-L $zone_chain >&/dev/null";
     $error = run_cmd($cmd);
     if ($error) {
       # chain does not exist, go ahead create it
       $cmd = "sudo $cmd_hash{$tree} -t $table_hash{$tree} -N $zone_chain";
       $error = run_cmd($cmd);
       return "create $zone_name chain with failed [$error]" if $error;
     }
    }

    return;
}

sub delete_zone_chain {
    my ($feature_func, $zone_name, $localoutchain) = @_;
    my ($cmd, $error);
    my $zone_chain=$get_zone_chain_hash{$feature_func}->("existsOrig",
                        $zone_name, $localoutchain);
    # delete zone chains from filter, ip6filter tables
    foreach my $tree (keys %cmd_hash) {
     # flush all rules from zone chain
     $cmd = "sudo $cmd_hash{$tree} -t $table_hash{$tree} -F $zone_chain";
     $error = run_cmd($cmd);
     return "flush all rules in $zone_name chain failed [$error]" if $error;

     # delete zone chain
     $cmd = "sudo $cmd_hash{$tree} -t $table_hash{$tree} -X $zone_chain";
     $error = run_cmd($cmd);
     return "delete $zone_name chain failed [$error]" if $error;
    }
    return;
}

sub add_intf_to_zonechain {
    my ($zone_chain_func, $zone_name, $interface, $feature_chain) = @_;
    my $zone_chain=
	$get_zone_chain_hash{$zone_chain_func}->("exists", $zone_name);
    my ($cmd, $error);
    foreach my $tree (keys %cmd_hash) {

     my $result = rule_exists ($cmd_hash{$tree}, $table_hash{$tree},
                                "$zone_chain", "RETURN", $interface);
     if ($result < 1) {
      # add rule to allow same zone to same zone traffic
      $cmd = "sudo $cmd_hash{$tree} -t $table_hash{$tree} -I $zone_chain " .
        "-i $interface -j RETURN";
      $error = run_cmd($cmd);
      return "call to add $interface to its zone-chain $zone_chain
failed [$error]" if $error;
     }

     # add jump rule to zone chain for this interface before last rule
     my $rule_cnt =
	Vyatta::IpTables::Mgr::count_iptables_rules($cmd_hash{$tree},
				$table_hash{$tree}, "$feature_chain");
     my $insert_at_rule_num=1;
     if ( $rule_cnt > 1 ) {
        $insert_at_rule_num=$rule_cnt;
     }
     $result = rule_exists ($cmd_hash{$tree}, $table_hash{$tree},
                "$feature_chain", "$zone_chain", $interface);
     if ($result < 1) {
      $cmd = "sudo $cmd_hash{$tree} -t $table_hash{$tree} -I " .
	"$feature_chain $insert_at_rule_num -o $interface -j $zone_chain";
      $error = run_cmd($cmd);
      return "call to add jump rule for outgoing interface $interface
to its $zone_chain chain failed [$error]" if $error;
     }
    }

    # success
    return;
}

sub delete_intf_from_zonechain {
    my ($zone_chain_func, $zone_name, $interface, $feature_chain) = @_;
    my $zone_chain=
	$get_zone_chain_hash{$zone_chain_func}->("existsOrig", $zone_name);
    my ($cmd, $error);

    foreach my $tree (keys %cmd_hash) {

     # delete rule to jump to zone chain for this interface
     $cmd = "sudo $cmd_hash{$tree} -t $table_hash{$tree} -D $feature_chain " .
        "-o $interface -j $zone_chain";
     $error = run_cmd($cmd);
     return "call to delete jump rule for outgoing interface $interface
to $zone_chain chain failed [$error]" if $error;

     # delete rule to allow same zone to same zone traffic
     $cmd = "sudo $cmd_hash{$tree} -t $table_hash{$tree} -D $zone_chain " .
	"-i $interface -j RETURN";
     $error = run_cmd($cmd);
     return "call to delete interface $interface from zone-chain
$zone_chain with failed [$error]" if $error;
    }

    # success
    return;
}

sub add_jump_to_localin_zonechain {
    my ($zone_chain_func, $zone_name, $feature_chain) = @_;
    my ($cmd, $error);
    my $zone_chain=
        $get_zone_chain_hash{$zone_chain_func}->("exists", $zone_name);

    foreach my $tree (keys %cmd_hash) {

      my $rule_cnt =
        Vyatta::IpTables::Mgr::count_iptables_rules($cmd_hash{$tree},
                                $table_hash{$tree}, $feature_chain);
      my $insert_at_rule_num=1;
      if ( $rule_cnt > 1 ) {
        $insert_at_rule_num=$rule_cnt;
      }
      my $result = rule_exists ($cmd_hash{$tree}, $table_hash{$tree},
                                        $feature_chain, $zone_chain);

      if ($result < 1) {
        # insert rule to filter local traffic from interface per ruleset
        $cmd = "sudo $cmd_hash{$tree} -t $table_hash{$tree} -I " .
                "$feature_chain $insert_at_rule_num -j $zone_chain";
        $error = run_cmd($cmd);
        return "call to add jump rule for local zone
$zone_chain chain failed [$error]" if $error;
      }
    }

    # success
    return;
}

sub remove_jump_to_localin_zonechain {
    my ($zone_chain_func, $zone_name, $feature_chain) = @_;
    my ($cmd, $error);
    my $zone_chain=
        $get_zone_chain_hash{$zone_chain_func}->("existsOrig", $zone_name);

    foreach my $tree (keys %cmd_hash) {

     # delete rule to filter traffic destined for system
     $cmd = "sudo $cmd_hash{$tree} -t $table_hash{$tree} -D $feature_chain " .
        "-j $zone_chain";
     $error = run_cmd($cmd);
     return "call to delete local zone
$zone_chain chain failed [$error]" if $error;

    }

    # success
    return;
}

sub add_jump_to_localout_zonechain {
    my ($zone_chain_func, $zone_name, $feature_chain) = @_;
    my ($cmd, $error);

    my $zone_chain=$get_zone_chain_hash{$zone_chain_func}->("exists",
                                $zone_name, 'localout');
    # add jump to local-zone-out chain
    foreach my $tree (keys %cmd_hash) {
      # if jump to localzoneout chain not inserted, then insert rule
      my $rule_cnt =
	Vyatta::IpTables::Mgr::count_iptables_rules($cmd_hash{$tree},
				$table_hash{$tree}, $feature_chain);
      my $insert_at_rule_num=1;
      if ( $rule_cnt > 1 ) {
        $insert_at_rule_num=$rule_cnt;
      }
      my $result = rule_exists ($cmd_hash{$tree}, $table_hash{$tree},
                                        $feature_chain, $zone_chain);
      if ($result < 1) {
        my $cmd = "sudo $cmd_hash{$tree} -t $table_hash{$tree} " .
           "-I $feature_chain $insert_at_rule_num -j $zone_chain";
        $error = run_cmd($cmd);
        return "call to add jump rule for local zone out
$zone_chain chain failed [$error]" if $error;
      }
    }

    # success
    return;
}

sub remove_jump_to_localout_zonechain {
    my ($zone_chain_func, $zone_name, $feature_chain) = @_;
    my ($cmd, $error);

    my $zone_chain=
	$get_zone_chain_hash{$zone_chain_func}->("existsOrig",
					$zone_name, 'localout');

    # if only two rules then delete jump from OUTPUT chain in both
    foreach my $tree (keys %cmd_hash) {
      my $rule_cnt =
	Vyatta::IpTables::Mgr::count_iptables_rules($cmd_hash{$tree},
					$table_hash{$tree}, $zone_chain);
      if ($rule_cnt > 2) {
        # atleast one of [ip or ip6]tables has local-zone as a from zone
        return;
      }
    }

    foreach my $tree (keys %cmd_hash) {
      $cmd = "sudo $cmd_hash{$tree} -t $table_hash{$tree} " .
            "-D $feature_chain -j $zone_chain";
      $error = run_cmd($cmd);
      return "call to delete jump rule for local zone out
$zone_chain chain failed [$error]" if $error;
     }

    # success
    return;
}

sub get_zone_hash {
  #### Return a hash containing zone policy for use in operational/gui commands
  my $zone_hash = ();
  my @zones = get_all_zones("listOrigNodes");
  for my $zone (@zones){
    my @from_zones = get_from_zones("listOrigNodes", $zone);
    for my $from_zone (@from_zones){
      $zone_hash->{$zone}{'from'}->{$from_zone}{'firewall'}->{'ipv4'} =
        get_firewall_ruleset("returnOrigValue", $zone, $from_zone, "name");
      $zone_hash->{$zone}{'from'}->{$from_zone}{'firewall'}->{'ipv6'} =
        get_firewall_ruleset("returnOrigValue", $zone, $from_zone, "ipv6-name");
    }
    if (is_local_zone("existsOrig", $zone)){
      $zone_hash->{$zone}{'interfaces'} = ['local-zone'];
    } else {
      my @interfaces = get_zone_interfaces("returnOrigValues", $zone);
      $zone_hash->{$zone}{'interfaces'} = [@interfaces];
    }
    my $config = new Vyatta::Config;
    my $desc = $config->returnOrigValue("zone-policy zone $zone description");
    $zone_hash->{$zone}{'description'} = $desc;
  }
  return $zone_hash;
}

1;
