#!/usr/bin/perl
###############################################################################
#
#    Skudonet Software License
#    This file is part of the Skudonet Load Balancer software package.
#
#    Copyright (C) 2014-today SKUDONET SL, Sevilla (Spain)
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
###############################################################################

use strict;
use feature 'state';


my $ip_bin = &getGlobalConfiguration( 'ip_bin' );

sub getInterfaceConfigFile
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $if_name   = shift;
	my $configdir = &getGlobalConfiguration( 'configdir' );
	return "$configdir/if_${if_name}_conf";
}

=begin nd
Variable: $if_ref

	Reference to a hash representation of a network interface.
	It can be found dereferenced and used as a (%iface or %interface) hash.

	$if_ref->{ name }     - Interface name.
	$if_ref->{ addr }     - IP address. Empty if not configured.
	$if_ref->{ mask }     - Network mask. Empty if not configured.
	$if_ref->{ gateway }  - Interface gateway. Empty if not configured.
	$if_ref->{ status }   - 'up' for enabled, or 'down' for disabled.
	$if_ref->{ ip_v }     - IP version, 4 or 6.
	$if_ref->{ dev }      - Name without VLAN or Virtual part (same as NIC or Bonding)
	$if_ref->{ vini }     - Part of the name corresponding to a Virtual interface. Can be empty.
	$if_ref->{ vlan }     - Part of the name corresponding to a VLAN interface. Can be empty.
	$if_ref->{ mac }      - Interface hardware address.
	$if_ref->{ type }     - Interface type: nic, bond, vlan, virtual.
	$if_ref->{ parent }   - Interface which this interface is based/depends on.
	$if_ref->{ float }    - Floating interface selected for this interface. For routing interfaces only.
	$if_ref->{ is_slave } - Whether the NIC interface is a member of a Bonding interface. For NIC interfaces only.
	$if_ref->{ dhcp }     - The DHCP service is enabled or not for the current interface.

See also:
	<getInterfaceConfig>, <setInterfaceConfig>, <getSystemInterface>
=cut

=begin nd
Function: getInterfaceConfig

	Get a hash reference with the stored configuration of a network interface.

Parameters:
	if_name - Interface name.

Returns:
	Hash ref - Reference to a network interface hash ($if_ref). undef if the network interface was not found.

Bugs:
	The configuration file exists but there isn't the requested stack.

See Also:
	<$if_ref>

	zcluster-manager, zenbui.pl, zapi/v?/interface.cgi, zcluster_functions.cgi, networking_functions_ext
=cut

sub getInterfaceConfig    # \%iface ($if_name, $ip_version)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $if_name ) = @_;

	unless ( defined $if_name )
	{
		&zenlog( 'getInterfaceConfig got undefined interface name',
				 'debug2', 'network' );
	}

	#~ &zenlog( "[CALL] getInterfaceConfig( $if_name )" );

	my $configdir       = &getGlobalConfiguration( 'configdir' );
	my $config_filename = "$configdir/if_${if_name}_conf";

	require Config::Tiny;
	my $fileHandler = Config::Tiny->new();
	$fileHandler = Config::Tiny->read( $config_filename )
	  if ( -f $config_filename );

	#Return undef if the file doesn't exists and the iface is not a NIC
	return undef
	  if ( !-f $config_filename and $if_name =~ /\.|\:/ );

	#Return undef if the file doesn't exists and the iface is a gre Tunnel
	return undef
	  if ( !-f $config_filename and &getInterfaceType( $if_name ) eq 'gre' );

	require IO::Socket;
	my $socket = IO::Socket::INET->new( Proto => 'udp' );

	my $iface = {};

	$iface->{ name } = $fileHandler->{ $if_name }->{ name } // $if_name;
	$iface->{ addr } = $fileHandler->{ $if_name }->{ addr }
	  if ( length $fileHandler->{ $if_name }->{ addr } );
	$iface->{ mask } = $fileHandler->{ $if_name }->{ mask }
	  if ( length $fileHandler->{ $if_name }->{ mask } );
	$iface->{ gateway } = $fileHandler->{ $if_name }->{ gateway }
	  if ( length $fileHandler->{ $if_name }->{ gateway } );    # optional
	$iface->{ status } = $fileHandler->{ $if_name }->{ status };
	$iface->{ dev }    = $if_name;
	$iface->{ vini }   = undef;
	$iface->{ vlan }   = undef;
	$iface->{ mac }    = $fileHandler->{ $if_name }->{ mac } // undef;
	$iface->{ type }   = &getInterfaceType( $if_name );
	$iface->{ parent } = &getParentInterfaceName( $iface->{ name } );
	$iface->{ ip_v } =
	  ( $iface->{ addr } =~ /:/ ) ? '6' : ( $iface->{ addr } =~ /\./ ) ? '4' : 0;
	$iface->{ net } =
	  &getAddressNetwork( $iface->{ addr }, $iface->{ mask }, $iface->{ ip_v } );
	$iface->{ dhcp }    = $fileHandler->{ $if_name }->{ dhcp }    // 'false';


	if ( $iface->{ dev } =~ /:/ )
	{
		( $iface->{ dev }, $iface->{ vini } ) = split ':', $iface->{ dev };
	}

	if ( !$iface->{ name } )
	{
		$iface->{ name } = $if_name;
	}

	if ( $iface->{ dev } =~ /./ )
	{
		# dot must be escaped
		( $iface->{ dev }, $iface->{ vlan } ) = split '\.', $iface->{ dev };
	}

	$iface->{ mac } = $socket->if_hwaddr( $iface->{ dev } )
	  if ( !defined $iface->{ mac } );

	# Interfaces without ip do not get HW addr via socket,
	# in those cases get the MAC from the OS.
	unless ( $iface->{ mac } )
	{
		open my $fh, '<', "/sys/class/net/$if_name/address";
		chomp ( $iface->{ mac } = <$fh> );
		close $fh;
	}


	# for virtual interface, overwrite mask and gw with parent values
	if ( $iface->{ type } eq 'vini' )
	{
		my $if_parent = &getInterfaceConfig( $iface->{ parent } );
		$iface->{ mask }    = $if_parent->{ mask };
		$iface->{ gateway } = $if_parent->{ gateway };
	}

	#~ &zenlog(
	#~ "getInterfaceConfig( $if_name ) returns " . Dumper \%iface );

	return $iface;
}

=begin nd
Function: getInterfaceConfigParam

	Gets a hash reference of configuration params of a network interface.

Parameters:
	if_name - Interface name.
	params_ref - Array ref of params

Returns:
	config_ref - Hash ref - Reference to a network interface config params hash ($config_ref).

=cut

sub getInterfaceConfigParam    # ($if_name, $params_ref)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $if_name, $params_ref ) = @_;
	my $config_ref;

	my $config_filename = &getInterfaceConfigFile( $if_name );

	#Return undef if the file doesn't exists and the iface is not a NIC
	return undef if ( !-f $config_filename and $if_name =~ /\.|\:/ );

	#Return undef if the file doesn't exists and the iface is a gre Tunnel
	return undef
	  if ( !-f $config_filename and &getInterfaceType( $if_name ) eq 'gre' );

	require Skudonet::Config;
	my $if_config = &getTiny( $config_filename );

	foreach my $param ( @{ $params_ref } )
	{
		if ( defined $if_config->{ $if_name }->{ $param } )
		{
			$config_ref->{ $param } = $if_config->{ $if_name }->{ $param };
		}
		else
		{
			$config_ref->{ $param } = undef;
		}
	}
	$config_ref->{ name } = $if_name if not $config_ref->{ name };
	return $config_ref;
}

=begin nd
Function: setInterfaceConfig

	Store a network interface configuration.

Parameters:
	if_ref - Reference to a network interface hash.

Returns:
	boolean - 1 on success, or 0 on failure.

See Also:
	<getInterfaceConfig>, <setInterfaceUp>, skudonet, zenbui.pl, zapi/v?/interface.cgi
=cut

# returns 1 if it was successful
# returns 0 if it wasn't successful

sub setInterfaceConfig    # $bool ($if_ref)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $if_ref = shift;
	require Config::Tiny;
	my $fileHandle = Config::Tiny->new;
	if ( ref $if_ref ne 'HASH' )
	{
		&zenlog( "Input parameter is not a hash reference", "warning", "NETWORK" );
		return;
	}
	use Data::Dumper;
	&zenlog( "setInterfaceConfig: " . Dumper( $if_ref ), "debug", "NETWORK" )
	  if &debug() > 2;
	my @if_params = ( 'status', 'name', 'addr', 'mask', 'gateway', 'mac', 'dhcp' );

	my $configdir       = &getGlobalConfiguration( 'configdir' );
	my $config_filename = "$configdir/if_$$if_ref{ name }_conf";

	# create file if it is not exist
	if ( !-f $config_filename )
	{
		require Skudonet::File;
		return 0 if ( &createFile( $config_filename ) );
	}

	$fileHandle = Config::Tiny->read( $config_filename );

	foreach my $field ( @if_params )
	{
		$fileHandle->{ $if_ref->{ name } }->{ $field } = $if_ref->{ $field };
	}

	if ( !exists $fileHandle->{ status } )
	{
		$fileHandle->{ $if_ref->{ name } }->{ status } = $if_ref->{ status } // "up";
	}

	return 0
	  unless ( $fileHandle->write( $config_filename ) );

	# returns a true value on success
	return 1;
}

=begin nd
Function: cleanInterfaceConfig

	remove the configuration information of a interface from its config file

Parameters:
	if_ref - Reference to a network interface hash.

Returns:
	Integer - 0 on success, or another value on failure.

=cut

sub cleanInterfaceConfig
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $if_ref    = shift;
	my $configdir = &getGlobalConfiguration( 'configdir' );
	my $file      = "$configdir/if_$$if_ref{name}\_conf";
	my $err       = 0;

	if ( !-f $file )
	{
		&zenlog( "The file $file has not been found", "info", "NETWORK" );
		return 1;
	}

	require Config::Tiny;
	my $fileHandler = Config::Tiny->new();
	$fileHandler = Config::Tiny->read( $file );
	$fileHandler->{ $if_ref->{ name } } = {
							  mask   => "",
							  status => $fileHandler->{ $if_ref->{ name } }->{ status },
							  dhcp   => "false",
							  addr   => "",
							  mac    => $if_ref->{ mac },
							  gateway => "",
	};

	$fileHandler->write( "$file" );
	if ( ( $$if_ref{ name } ne $$if_ref{ dev } ) or ( $$if_ref{ type } eq 'gre' ) )
	{
		unlink ( $file ) or return 1;
	}

	return $err;
}

=begin nd
Function: getDevVlanVini

	Get a hash reference with the interface name divided into: dev, vlan, vini.

Parameters:
	if_name - Interface name.

Returns:
	Reference to a hash with:
	dev - NIC or Bonding part of the interface name.
	vlan - VLAN part of the interface name.
	vini - Virtual interface part of the interface name.

See Also:
	<getParentInterfaceName>, <getSystemInterfaceList>, <getSystemInterface>, zapi/v2/interface.cgi
=cut

sub getDevVlanVini    # ($if_name)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my %if;
	$if{ dev } = shift;

	if ( $if{ dev } =~ /:/ )
	{
		( $if{ dev }, $if{ vini } ) = split ':', $if{ dev };
	}

	if ( $if{ dev } =~ /\./ )    # dot must be escaped
	{
		( $if{ dev }, $if{ vlan } ) = split '\.', $if{ dev };
	}

	return \%if;
}

=begin nd
Function: getConfigInterfaceList

	Get a reference to an array of all the interfaces saved in files.

Parameters:
	params_ref - Array ref of params. undef means all params

Returns:
	scalar - reference to array of configured interfaces.

See Also:
	zenloadbalanacer, zcluster-manager, <getIfacesFromIf>,
	<getActiveInterfaceList>, <getSystemInterfaceList>, <getFloatInterfaceForAddress>
=cut

sub getConfigInterfaceList
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $params_ref ) = @_;
	my @configured_interfaces;
	my $configdir = &getGlobalConfiguration( 'configdir' );

	if ( opendir my $dir, "$configdir" )
	{
		for my $filename ( readdir $dir )
		{
			if ( $filename =~ /if_(.+)_conf/ )
			{
				my $if_name = $1;
				my $if_ref;

				if ( defined $params_ref )
				{
					$if_ref = &getInterfaceConfigParam( $if_name, $params_ref );
				}
				else
				{
					$if_ref = &getInterfaceConfig( $if_name );
				}
				if ( defined $if_ref )
				{
					push @configured_interfaces, $if_ref;
				}
			}
		}

		closedir $dir;
	}
	else
	{
		&zenlog( "Error reading directory $configdir: $!", "error", "NETWORK" );
	}

	return \@configured_interfaces;
}

=begin nd
Function: getInterfaceSystemStatus

	Get the status of an network interface in the system.

Parameters:
	if_ref - Reference to a network interface hash.

Returns:
	scalar - 'up' or 'down'.

See Also:
	<getActiveInterfaceList>, <getSystemInterfaceList>, <getInterfaceTypeList>, zapi/v?/interface.cgi,
=cut

sub getInterfaceSystemStatus    # ($if_ref)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $if_ref = shift;

	my $parent_if_name = &getParentInterfaceName( $if_ref->{ name } );
	my $status_if_name = $if_ref->{ name };

	if ( $if_ref->{ vini } ne '' )    # vini
	{
		$status_if_name = $parent_if_name;
	}

	my $ip_bin    = &getGlobalConfiguration( 'ip_bin' );
	my $ip_output = &logAndGet( "$ip_bin link show $status_if_name" );
	$ip_output =~ / state (\w+) /;
	my $if_status = lc $1;

	if ( $if_status !~ /^(?:up|down)$/ )    # if not up or down, ex: UNKNOWN
	{
		my ( $flags ) = $ip_output =~ /<(.+)>/;
		my @flags = split ( ',', $flags );

		my $flag_up   = 0;
		my $flag_down = 0;
		foreach my $flag ( @flags )
		{
			$flag_up++   if ( $flag eq "UP" );
			$flag_down++ if ( $flag eq "NO-CARRIER" );
		}
		if ( $flag_up and not $flag_down )
		{
			$if_status = 'up';
		}
		else
		{
			$if_status = 'down';
		}

	}

	# Set as down vinis not available
	if ( $if_ref->{ vini } ne '' )
	{
		$ip_output = &logAndGet( "$ip_bin addr show $status_if_name" );
		if ( $ip_output !~ /$if_ref->{ addr }/ )
		{
			return "down";
		}
	}

	# if it is not a virtual in down
	unless ( $if_ref->{ vini } ne '' && $if_ref->{ status } eq 'down' )
	{
		$if_ref->{ status } = $if_status;
	}

	return $if_ref->{ status } if $if_ref->{ status } eq 'down';
	return $if_ref->{ status } if !$parent_if_name;

	my $params        = ["name", "addr", "status"];
	my $parent_if_ref = &getInterfaceConfigParam( $parent_if_name, $params );

	# vlans do not require the parent interface to be configured
	return $if_ref->{ status } if !$parent_if_ref;

	return &getInterfaceSystemStatus( $parent_if_ref );
}

=begin nd
Function: getInterfaceSystemStatusAll

	Get a hash of the status of all network interfaces in the system.

Parameters:

Returns:
	Hash ref - Hash with name and status values.

=cut

sub getInterfaceSystemStatusAll    # ()
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $ip_bin    = &getGlobalConfiguration( 'ip_bin' );
	my $ip_output = &logAndGet( "$ip_bin -o link", "array" );
	my $links_ref;
	foreach my $link ( @{ $ip_output } )
	{
		if ( $link =~
			/^\d+: ([a-zA-Z0-9\-]+(?:\.\d{1,4})?)(?:@[a-zA-Z0-9\-]+)?: <(.+)> .+ state (\w+) /
		  )
		{
			my $interface = $1;
			my $flag      = $2;
			my $status    = lc $3;

			if ( $status ne "up" and $status ne "down" )
			{
				my @flags     = split ( ',', $flag );
				my $flag_up   = 0;
				my $flag_down = 0;
				foreach my $flag ( @flags )
				{
					$flag_up++   if ( $flag eq "UP" );
					$flag_down++ if ( $flag eq "NO-CARRIER" );
				}
				if ( $flag_up and not $flag_down )
				{
					$status = 'up';
				}
				else
				{
					$status = 'down';
				}
			}
			$links_ref->{ $interface } = $status;
		}
	}

	$ip_output = &logAndGet( "$ip_bin -o addr", "array" );
	my $addr_ref;
	foreach my $addr ( @{ $ip_output } )
	{
		if ( $addr =~
			/^\d+: ([a-zA-Z0-9\-]+)(?:\.\d{1,4})?\s+(inet(?:\d)? (.*) (?:brd .*)?) scope .+ ([a-zA-Z0-9\-]+(?:\.\d{1,4})?:[a-zA-Z0-9\-]+)\\ /
		  )
		{
			my $parent  = $1;
			my $virtual = $4;
			$addr_ref->{ $virtual } = $links_ref->{ $parent };
		}

	}
	$links_ref = { %{ $links_ref }, %{ $addr_ref } } if $addr_ref;
	return $links_ref;
}

=begin nd
Function: getParentInterfaceName

	Get the parent interface name.

Parameters:
	if_name - Interface name.

Returns:
	string - Parent interface name or undef if there is no parent interface (NIC and Bonding).

See Also:
	<getInterfaceConfig>, <getSystemInterface>, skudonet, zapi/v?/interface.cgi
=cut

sub getParentInterfaceName    # ($if_name)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $if_name = shift;

	my $if_ref = &getDevVlanVini( $if_name );
	my $parent_if_name;

	my $is_vlan    = defined $if_ref->{ vlan } && length $if_ref->{ vlan };
	my $is_virtual = defined $if_ref->{ vini } && length $if_ref->{ vini };

	# child interface: eth0.100:virtual => eth0.100
	if ( $is_virtual && $is_vlan )
	{
		$parent_if_name = "$$if_ref{dev}.$$if_ref{vlan}";
	}

	# child interface: eth0:virtual => eth0
	elsif ( $is_virtual && !$is_vlan )
	{
		$parent_if_name = $if_ref->{ dev };
	}

	# child interface: eth0.100 => eth0
	elsif ( !$is_virtual && $is_vlan )
	{
		$parent_if_name = $if_ref->{ dev };
	}

	# child interface: eth0 => undef
	elsif ( !$is_virtual && !$is_vlan )
	{
		$parent_if_name = undef;
	}

	return $parent_if_name;
}

=begin nd
Function: getActiveInterfaceList

	Get a reference to a list of all running (up) and configured network interfaces.

Parameters:
	none - .

Returns:
	scalar - reference to an array of network interface hashrefs.

See Also:
	Zapi v3: post.cgi, put.cgi, system.cgi
=cut

sub getActiveInterfaceList
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my @configured_interfaces = @{ &getConfigInterfaceList() };

	# sort list
	@configured_interfaces =
	  sort { $a->{ name } cmp $b->{ name } } @configured_interfaces;

	# apply device status heritage
	$_->{ status } = &getInterfaceSystemStatus( $_ ) for @configured_interfaces;

	# discard interfaces down
	@configured_interfaces = grep { $_->{ status } eq 'up' } @configured_interfaces;

	# find maximun lengths for padding
	my $max_dev_length;
	my $max_ip_length;

	for my $iface ( @configured_interfaces )
	{
		if ( $iface->{ status } == 'up' )
		{
			my $dev_length = length $iface->{ name };
			$max_dev_length = $dev_length if $dev_length > $max_dev_length;

			my $ip_length = length $iface->{ addr };
			$max_ip_length = $ip_length if $ip_length > $max_ip_length;
		}
	}

	# make padding
	for my $iface ( @configured_interfaces )
	{
		my $dev_ip_padded = sprintf ( "%-${max_dev_length}s -> %-${max_ip_length}s",
									  $$iface{ name }, $$iface{ addr } );
		$dev_ip_padded =~ s/ +$//;
		$dev_ip_padded =~ s/ /&nbsp;/g;

		$iface->{ dev_ip_padded } = $dev_ip_padded;
	}

	return \@configured_interfaces;
}

=begin nd
Function: getSystemInterfaceList

	Get a reference to a list with all the interfaces, configured and not configured.

Parameters:
	none - .

Returns:
	scalar - reference to an array with configured and system network interfaces.

See Also:
	zapi/v?/interface.cgi, zapi/v3/cluster.cgi
=cut

sub getSystemInterfaceList
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	use IO::Interface qw(:flags);

	my @interfaces;    # output

	my @configured_interfaces;
	my $interface_ref = &getInterfaceNameStruct( "vlan", "array" );
	foreach my $vlan ( @{ $interface_ref } )
	{
		my $if_ref = &getInterfaceConfig( $vlan );
		push @configured_interfaces, $if_ref if $if_ref;
	}
	$interface_ref = &getInterfaceNameStruct( "virtual", "array" );
	foreach my $virtual ( @{ $interface_ref } )
	{
		my $if_ref = &getInterfaceConfig( $virtual );
		push @configured_interfaces, $if_ref if $if_ref;
	}

	my $socket            = IO::Socket::INET->new( Proto => 'udp' );
	my @system_interfaces = &getInterfaceList();

	my $all_status = &getInterfaceSystemStatusAll();

	## Build system device "tree"
	for my $if_name ( @system_interfaces )    # list of interface names
	{
		# ignore vlans and vinis
		next if $if_name =~ /\./;
		next if $if_name =~ /:/;

		# ignore loopback device
		next if $if_name =~ /^lo$/;

		# ignore fallback device from ip_gre module
		next if $if_name =~ /^gre0$|^gretap0$|^erspan0$/;

		# ignore fallback device from ip6_gre module
		next if $if_name =~ /^ip6gre0$|^ip6tnl0$/;

		# ignore fallback device from sit module
		next if $if_name =~ /^sit0$/;

		# ignore fallback device from ip_vti module
		#next if $if_name =~ /^ip_vti0$/;
		# ignore fallback device from ipip module
		#next if $if_name =~ /^tunl0$/;

		my $if_ref;
		my $if_flags = $socket->if_flags( $if_name );

		my %if_parts = %{ &getDevVlanVini( $if_name ) };

		# run for IPv4 and IPv6
		$if_ref = &getInterfaceConfig( $if_name );

		if ( !$$if_ref{ addr } )
		{
			# populate not configured interface
			$$if_ref{ status } = ( $if_flags & IFF_UP ) ? "up" : "down";
			$$if_ref{ mac }    = $socket->if_hwaddr( $if_name );
			$$if_ref{ name }   = $if_name;
			$$if_ref{ addr }   = '';
			$$if_ref{ mask }   = '';
			$$if_ref{ dev }    = $if_parts{ dev };
			$$if_ref{ vlan }   = $if_parts{ vlan };
			$$if_ref{ vini }   = $if_parts{ vini };
			$$if_ref{ ip_v }   = '';
			$$if_ref{ type }   = &getInterfaceType( $if_name );
		}

		if ( !( $if_flags & IFF_RUNNING ) && ( $if_flags & IFF_UP ) )
		{
			$$if_ref{ link } = "off";
		}

		$if_ref->{ status } = $all_status->{ $if_ref->{ name } };

		# add interface to the list
		push ( @interfaces, $if_ref );

		# add vlans and virtuals belonging the dev
		for my $if_conf ( @configured_interfaces )
		{
			next if $if_conf->{ dev } ne $if_ref->{ dev };
			next if not $if_conf->{ parent };

			$if_conf->{ status } = $all_status->{ $if_conf->{ name } };
			push ( @interfaces, $if_conf );
		}
	}

	return \@interfaces;
}

=begin nd
Function: getSystemInterface

	Get a reference to a network interface hash from the system configuration, not the stored configuration.

Parameters:
	if_name - Interface name.

Returns:
	scalar - reference to a network interface hash as is on the system or undef if not found.

See Also:
	<getInterfaceConfig>, <setInterfaceConfig>
=cut

sub getSystemInterface    # ($if_name)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $if_ref = {};
	$$if_ref{ name } = shift;

	use IO::Interface qw(:flags);

	my %if_parts = %{ &getDevVlanVini( $$if_ref{ name } ) };
	my $socket   = IO::Socket::INET->new( Proto => 'udp' );
	my $if_flags = $socket->if_flags( $$if_ref{ name } );

	$$if_ref{ mac } = $socket->if_hwaddr( $$if_ref{ name } );

	return if not $$if_ref{ mac };
	$$if_ref{ status } = ( $if_flags & IFF_UP ) ? "up" : "down";
	$$if_ref{ addr }   = '';
	$$if_ref{ mask }   = '';
	$$if_ref{ dev }    = $if_parts{ dev };
	$$if_ref{ vlan }   = $if_parts{ vlan };
	$$if_ref{ vini }   = $if_parts{ vini };
	$$if_ref{ type }   = &getInterfaceType( $$if_ref{ name } );
	$$if_ref{ parent } = &getParentInterfaceName( $$if_ref{ name } );


	return $if_ref;
}

=begin nd
Function: getInterfaceType

	Get the type of a network interface from its name using linux 'hints'.

	Original source code in bash:
	http://stackoverflow.com/questions/4475420/detect-network-connection-type-in-linux

	Translated to perl and adapted by Skudonet

	Interface types: nic, virtual, vlan, bond, dummy or lo.

Parameters:
	if_name - Interface name.

Returns:
	scalar - Interface type: nic, virtual, vlan, bond, dummy or lo.

See Also:

=cut

# Source in bash translated to perl:
# http://stackoverflow.com/questions/4475420/detect-network-connection-type-in-linux
#
# Interface types: nic, virtual, vlan, bond
sub getInterfaceType
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $if_name = shift;

	my $type;

	return if $if_name eq '' || !defined $if_name;


	if ( !-d "/sys/class/net/$if_name" )
	{
		my $configdir = &getGlobalConfiguration( 'configdir' );
		my $found = ( -f "$configdir/if_${if_name}_conf" && $if_name =~ /^.+\:.+$/ );

		if ( !$found )
		{
			my ( $parent_if ) = split ( ':', $if_name );
			my $quoted_if     = quotemeta $if_name;
			my $ip_bin        = &getGlobalConfiguration( 'ip_bin' );
			my @out           = @{ &logAndGet( "$ip_bin addr show $parent_if", "array" ) };
			$found =
			  grep ( /inet .+ $quoted_if$/, @out );
		}

		if ( $found )
		{
			return 'virtual';
		}
		else
		{
			return;
		}
	}

	my $code;    # read type code
	{
		my $if_type_filename = "/sys/class/net/$if_name/type";

		open ( my $type_file, '<', $if_type_filename )
		  or die "Could not open file $if_type_filename: $!";
		chomp ( $code = <$type_file> );
		close $type_file;
	}

	if ( $code == 1 )
	{
		$type = 'nic';

		# Ethernet, may also be wireless, ...
		if ( -f "/proc/net/vlan/$if_name" )
		{
			$type = 'vlan';
		}

#elsif ( -d "/sys/class/net/$if_name/wireless" || -l "/sys/class/net/$if_name/phy80211" )
#{
#	$type = 'wlan';
#}
#elsif ( -d "/sys/class/net/$if_name/bridge" )
#{
#	$type = 'bridge';
#}
#elsif ( -f "/sys/class/net/$if_name/tun_flags" )
#{
#	$type = 'tap';
#}
#elsif ( -d "/sys/devices/virtual/net/$if_name" )
#{
#	$type = 'dummy' if $if_name =~ /^dummy/;
#}
	}
	elsif ( $code == 24 )
	{
		$type = 'nic';    # firewire ;; # IEEE 1394 IPv4 - RFC 2734
	}
	elsif ( $code == 32 )
	{

		#elsif ( -d "/sys/class/net/$if_name/create_child" )
		#{
		#	$type = 'ib';
		#}
		#else
		#{
		#	$type = 'ibchild';
		#}
	}


	#elsif ( $code == 768 )
	#{
	#	$type = 'ipip';    # IPIP tunnel
	#}
	#elsif ( $code == 769 )
	#{
	#	$type = 'ip6tnl';    # IP6IP6 tunnel
	#}
	elsif ( $code == 772 ) { $type = 'lo'; }

	#elsif ( $code == 776 )
	#{
	#	$type = 'sit';       # sit0 device - IPv6-in-IPv4
	#}

	#elsif ( $code == 783 )
	#{
	#	$type = 'irda';      # Linux-IrDA
	#}
	#elsif ( $code == 801 )   { $type = 'wlan_aux'; }
	#elsif ( $code == 65534 ) { $type = 'tun'; }

	# The following case statement still has to be replaced by something
	# which does not rely on the interface names.
	# case $if_name in
	# 	ippp*|isdn*) type=isdn;;
	# 	mip6mnha*)   type=mip6mnha;;
	# esac

	return $type if defined $type;

	my $msg = "Could not recognize the type of the interface $if_name.";

	&zenlog( $msg, "error", "NETWORK" );
	die ( $msg );    # This should not happen
}

=begin nd
Function: getInterfaceTypeList

	Get a list of hashrefs with interfaces of a single type.

	Types supported are: nic, bond, vlan, virtual and gre.

Parameters:
	list_type - Network interface type.
	iface_name - Interface name

Returns:
	list - list of network interfaces hashrefs.

See Also:

=cut

sub getInterfaceTypeList
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $list_type  = shift;
	my $iface_name = shift;

	my @interfaces = ();

	if ( $list_type =~ /^(?:nic|bond|vlan|gre)$/ )
	{
		my @system_interfaces;
		if ( $iface_name )
		{
			push @system_interfaces, $iface_name;
		}
		else
		{
			@system_interfaces = sort &getInterfaceList();
		}

		for my $if_name ( @system_interfaces )
		{
			if ( $list_type eq &getInterfaceType( $if_name ) )
			{
				my $output_if = &getInterfaceConfig( $if_name );
				if ( !$output_if || !$output_if->{ mac } || $output_if->{ is_slave } eq 'true' )
				{
					$output_if = &getSystemInterface( $if_name );
				}

				push ( @interfaces, $output_if );
			}
		}
	}
	elsif ( $list_type eq 'virtual' )
	{
		require Skudonet::Validate;

		opendir my $conf_dir, &getGlobalConfiguration( 'configdir' );
		my $virt_if_re = &getValidFormat( 'virt_interface' );

		my $parents_list;
		for my $file_name ( sort readdir $conf_dir )
		{
			if ( $file_name =~ /^if_($virt_if_re)_conf$/ )
			{
				my $if_name = $1;
				next if ( $iface_name and ( $iface_name ne $if_name ) );
				my $iface = &getInterfaceConfig( $if_name );

				#$iface->{ status } = &getInterfaceSystemStatus( $iface );

				# put the mac, gateway and netmask of the parent interface
				if ( not defined $parents_list->{ $iface->{ parent } } )
				{
					$parents_list->{ $iface->{ parent } } =
					  &getInterfaceConfig( $iface->{ parent } );
				}
				$iface->{ mask }    = $parents_list->{ $iface->{ parent } }->{ mask };
				$iface->{ mac }     = $parents_list->{ $iface->{ parent } }->{ mac };
				$iface->{ gateway } = $parents_list->{ $iface->{ parent } }->{ gateway };
				push ( @interfaces, $iface );
			}
		}
	}
	else
	{
		my $msg = "Interface type '$list_type' is not supported.";
		&zenlog( $msg, "error", "NETWORK" );
		die ( $msg );
	}

	return @interfaces;
}

=begin nd
Function: getAppendInterfaces

	Get vlans or virtual interfaces configured from a interface.
	If the interface is a nic or bonding, this function return the virtual interfaces
	create from the VLANs, for example: eth0.2:virt

Parameters:
	ifaceName - Interface name.
	type - Interface type: vlan or virtual.

Returns:
	scalar - reference to an array of interfaces names.

See Also:

=cut

# Get vlan or virtual interfaces appended from a interface
sub getAppendInterfaces    # ( $iface_name, $type )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $if_parent, $type ) = @_;
	my @output = ();

	my @list = &getInterfaceList();

	my $vlan_tag    = &getValidFormat( 'vlan_tag' );
	my $virtual_tag = &getValidFormat( 'virtual_tag' );

	foreach my $if ( @list )
	{
		if ( $type eq 'vlan' )
		{
			push @output, $if if ( $if =~ /^$if_parent\.$vlan_tag$/ );
		}

		if ( $type eq 'virtual' )
		{
			push @output, $if if ( $if =~ /^$if_parent(?:\.$vlan_tag)?\:$virtual_tag$/ );
		}
	}

	return \@output;
}

=begin nd
Function: getInterfaceList

	Return a list of all network interfaces detected in the system.

Parameters:
	None.

Returns:
	array - list of network interface names.
	array empty - if no network interface is detected.

See Also:
	<listActiveInterfaces>
=cut

sub getInterfaceList
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my @if_list = ();

	#Get link interfaces
	push @if_list, &getLinkNameList();

	#Get virtual interfaces
	push @if_list, &getVirtualInterfaceNameList();

	return @if_list;
}

=begin nd
Function: getVirtualInterfaceNameList

	Get a list of the virtual interfaces names.

Parameters:
	none - .

Returns:
	list - Every virtual interface name.
=cut

sub getVirtualInterfaceNameList
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	require Skudonet::Validate;

	opendir ( my $conf_dir, &getGlobalConfiguration( 'configdir' ) );
	my $virt_if_re = &getValidFormat( 'virt_interface' );
	my @interfaces;

	foreach my $filename ( readdir ( $conf_dir ) )
	{
		push @interfaces, $1 if ( $filename =~ /^if_($virt_if_re)_conf$/ );
	}

	closedir ( $conf_dir );

	return @interfaces;
}

=begin nd
Function: getLinkInterfaceNameList

	Get a list of the link interfaces names. (nic, bond and vlan)

Parameters:
	none - .

Returns:
	list - Every link interface name.
=cut

sub getLinkNameList
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $sys_net_dir = &getGlobalConfiguration( 'sys_net_dir' );

	# Get link interfaces (nic, bond and vlan)
	opendir ( my $if_dir, $sys_net_dir );
	my @if_list = grep { -l "$sys_net_dir/$_" } readdir $if_dir;
	closedir $if_dir;

	return @if_list;
}

=begin nd
Function: getInterfaceNameStruct

	Get a struct configured interfaces names.

Parameters:
	$if_type - Type of interface. nic, bonding, vlan,virtual.

Returns:
	Hash ref - Struct of every interface name divided by type or List if type param is defined.
=cut

sub getInterfaceNameStruct
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $if_type = shift;

	my $interfaces_ref;


	opendir ( my $conf_dir, &getGlobalConfiguration( 'configdir' ) );
	foreach my $filename ( readdir ( $conf_dir ) )
	{
		if ( $filename =~
			 /^if_([a-zA-Z0-9\-]+)(?:\.(\d{1,4}))?(?:\:([a-zA-Z0-9\-]+))?_conf$/ )
		{
			my $interface = $1;
			my $tag       = $2;
			my $virtual   = $3;

			my $type = "nic";
			if ( defined $virtual )
			{
				if ( defined $if_type )
				{
					$interface .= ".$tag" if ( defined $tag );
					push @{ $interfaces_ref }, "$interface:$virtual" if ( $if_type eq "virtual" );
				}
				elsif ( defined $tag )
				{
					$interfaces_ref->{ $type }->{ $interface }->{ vlan }->{ $tag }->{ virtual }
					  ->{ $virtual } = undef;
				}
				else
				{
					if (
						 not
						 exists $interfaces_ref->{ $type }->{ $interface }->{ virtual }->{ $virtual } )
					{
						$interfaces_ref->{ $type }->{ $interface }->{ virtual }->{ $virtual } = undef;
					}
				}
			}
			else
			{
				if ( defined $tag )
				{
					if ( defined $if_type )
					{
						push @{ $interfaces_ref }, "$interface.$tag" if ( $if_type eq "vlan" );
						next;
					}
					elsif (
							not exists $interfaces_ref->{ $type }->{ $interface }->{ vlan }->{ $tag } )
					{
						$interfaces_ref->{ $type }->{ $interface }->{ vlan }->{ $tag } = undef;
					}
				}
				else
				{
					if ( defined $if_type )
					{
						push @{ $interfaces_ref }, $interface if ( $if_type eq $type );
						next;
					}
					elsif ( not exists $interfaces_ref->{ $type }->{ $interface } )
					{
						$interfaces_ref->{ $type }->{ $interface } = undef;
					}
				}
			}
		}
	}
	closedir ( $conf_dir );

	return $interfaces_ref;
}

=begin nd
Function: getInterfaceByIp

	Ask for the name of the interface using the IP address

Parameters:
	IP - IP address

Returns:
	String - Interface name

=cut

sub getInterfaceByIp
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $ip = shift;

	require Skudonet::Net::Validate;

	my $output         = "";
	my $ip_ver         = &ipversion( $ip );
	my $addr_ref       = NetAddr::IP->new( $ip );
	my $params         = ["name", "addr"];
	my $interface_list = &getConfigInterfaceList( $params );

	if ( $ip_ver == 4 )
	{
		foreach my $if_ref ( @{ $interface_list } )
		{
			if (     ( $if_ref->{ addr } eq $ip )
				 and ( &ipversion( $if_ref->{ addr } ) eq $ip_ver ) )
			{
				$output = $if_ref->{ name };
				last;
			}
		}
	}
	elsif ( $ip_ver == 6 )
	{
		foreach my $if_ref ( @{ $interface_list } )
		{
			if ( NetAddr::IP->new( $if_ref->{ addr } ) eq $addr_ref )
			{
				$output = $if_ref->{ name };
				last;
			}
		}
	}

	return $output;
}

=begin nd
Function: getIpAddressExists

	Return if a IP exists in some configurated interface

Parameters:
	IP - IP address

Returns:
	Integer - 0 if it doesn't exist or 1 if the IP already exists

=cut

sub getIpAddressExists
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $ip = shift;

	require Skudonet::Net::Validate;

	my $output         = 0;
	my $ip_ver         = &ipversion( $ip );
	my $params         = ["addr"];
	my $interface_list = &getConfigInterfaceList( $params );
	if ( $ip_ver == 4 )
	{
		foreach my $if_ref ( @{ $interface_list } )
		{
			if (     ( $if_ref->{ addr } eq $ip )
				 and ( &ipversion( $if_ref->{ addr } ) eq $ip_ver ) )
			{
				$output = 1;
				last;
			}
		}
	}
	elsif ( $ip_ver == 6 )
	{
		my $addr_ref = NetAddr::IP->new( $ip );
		foreach my $if_ref ( @{ $interface_list } )
		{
			if ( NetAddr::IP->new( $if_ref->{ addr } ) eq $addr_ref )
			{
				$output = 1;
				last;
			}
		}
	}

	return $output;
}

=begin nd
Function: getIpAddressList

	It returns a list with the IPv4 and IPv6 that exist in the system

Parameters:
	none - .

Returns:
	Array ref - List of IPs

=cut

sub getIpAddressList
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my @out = ();

	my $params = ["addr"];
	foreach my $if_ref ( @{ &getConfigInterfaceList( $params ) } )
	{
		if ( defined $if_ref->{ addr } )
		{
			push @out, $if_ref->{ addr };
		}
	}

	return \@out;
}

=begin nd
Function: getInterfaceChild

	Show the interfaces that depends directly of the interface.
	From a nic, bonding and VLANs interfaces depend the virtual interfaces.
	From a virtual interface depends the floating itnerfaces.

Parameters:
	ifaceName - Interface name.

Returns:
	scalar - Array of interfaces names.

FIXME: rename me, this function is used to check if the interface has some interfaces
 that depends of it. It is useful to avoid that corrupts the child interface

See Also:

=cut

sub getInterfaceChild
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $if_name = shift;

	my @output      = ();
	my $if_type     = &getInterfaceType( $if_name );
	my $virtual_tag = &getValidFormat( 'virtual_tag' );

	# the other type of interfaces can have virtual interfaces as child
	if ( $if_type ne 'virtual' )
	{
		push @output,
		  grep ( /^$if_name:$virtual_tag$/, &getVirtualInterfaceNameList() );
	}

	return @output;
}

sub getAddressNetwork
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $addr, $mask, $ip_v ) = @_;

	require NetAddr::IP;

	my $net;

	if ( $ip_v == 4 )
	{
		my $ip = NetAddr::IP->new( $addr, $mask );
		$net = lc $ip->network()->addr();
	}
	elsif ( $ip_v == 6 )
	{
		my $ip = NetAddr::IP->new6( $addr, $mask );
		$net = lc $ip->network()->addr();
	}
	else
	{
		$net = undef;
	}

	return $net;
}

sub get_interface_list_struct
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	require Skudonet::User;

	my @output_list;

	# Configured interfaces list
	my @interfaces = @{ &getSystemInterfaceList() };    #140


	my $user = &getUser();


	# to include 'has_vlan' to nics
	my $interfaces_ref = &getInterfaceNameStruct();

	my $all_status = &getInterfaceSystemStatusAll();
	for my $if_ref ( @interfaces )
	{

		$if_ref->{ status } = $all_status->{ $if_ref->{ name } };

		# Any key must cotain a value or "" but can't be null
		if ( !defined $if_ref->{ name } )    { $if_ref->{ name }    = ""; }
		if ( !defined $if_ref->{ addr } )    { $if_ref->{ addr }    = ""; }
		if ( !defined $if_ref->{ mask } )    { $if_ref->{ mask }    = ""; }
		if ( !defined $if_ref->{ gateway } ) { $if_ref->{ gateway } = ""; }
		if ( !defined $if_ref->{ status } )  { $if_ref->{ status }  = ""; }
		if ( !defined $if_ref->{ mac } )     { $if_ref->{ mac }     = ""; }

		my $if_conf = {
			name    => $if_ref->{ name },
			ip      => $if_ref->{ addr },
			netmask => $if_ref->{ mask },
			gateway => $if_ref->{ gateway },
			status  => $if_ref->{ status },
			mac     => $if_ref->{ mac },
			type    => $if_ref->{ type },

			#~ ipv     => $if_ref->{ ip_v },
		};

		$if_conf->{ dhcp } = $if_ref->{ dhcp }
		  if ( $if_ref->{ type } ne 'virtual' );

		if ( $if_ref->{ type } eq 'nic' )
		{

			if (
				exists $interfaces_ref->{ $if_ref->{ type } }->{ $if_ref->{ name } }->{ vlan } )
			{
				$if_conf->{ has_vlan } = 'true';
			}
			$if_conf->{ has_vlan } = 'false' unless $if_conf->{ has_vlan };
		}


		push @output_list, $if_conf;
	}


	return \@output_list;
}

sub get_nic_struct
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $nic = shift;

	my $interface;

	my @nic_list = &getInterfaceTypeList( 'nic', $nic );
	my $if_ref   = $nic_list[0];

	$if_ref->{ status } = &getInterfaceSystemStatus( $if_ref );

	# Any key must contain a value or "" but can't be null
	if ( !defined $if_ref->{ name } )    { $if_ref->{ name }    = ""; }
	if ( !defined $if_ref->{ addr } )    { $if_ref->{ addr }    = ""; }
	if ( !defined $if_ref->{ mask } )    { $if_ref->{ mask }    = ""; }
	if ( !defined $if_ref->{ dhcp } )    { $if_ref->{ dhcp }    = "false"; }
	if ( !defined $if_ref->{ gateway } ) { $if_ref->{ gateway } = ""; }
	if ( !defined $if_ref->{ status } )  { $if_ref->{ status }  = ""; }
	if ( !defined $if_ref->{ mac } )     { $if_ref->{ mac }     = ""; }

	$interface = {
				   name    => $if_ref->{ name },
				   ip      => $if_ref->{ addr },
				   netmask => $if_ref->{ mask },
				   dhcp    => $if_ref->{ dhcp },
				   gateway => $if_ref->{ gateway },
				   status  => $if_ref->{ status },
				   mac     => $if_ref->{ mac },
	};


	return $interface;
}

sub get_nic_list_struct
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my @output_list;

	my $interface_ref = &getInterfaceNameStruct();


	my $all_status = &getInterfaceSystemStatusAll();
	for my $if_ref ( &getInterfaceTypeList( 'nic' ) )
	{
		$if_ref->{ status } = $all_status->{ $if_ref->{ name } };

		# Any key must cotain a value or "" but can't be null
		if ( !defined $if_ref->{ name } )    { $if_ref->{ name }    = ""; }
		if ( !defined $if_ref->{ addr } )    { $if_ref->{ addr }    = ""; }
		if ( !defined $if_ref->{ mask } )    { $if_ref->{ mask }    = ""; }
		if ( !defined $if_ref->{ dhcp } )    { $if_ref->{ dhcp }    = "false"; }
		if ( !defined $if_ref->{ gateway } ) { $if_ref->{ gateway } = ""; }
		if ( !defined $if_ref->{ status } )  { $if_ref->{ status }  = ""; }
		if ( !defined $if_ref->{ mac } )     { $if_ref->{ mac }     = ""; }

		my $if_conf = {
						name    => $if_ref->{ name },
						ip      => $if_ref->{ addr },
						netmask => $if_ref->{ mask },
						dhcp    => $if_ref->{ dhcp },
						gateway => $if_ref->{ gateway },
						status  => $if_ref->{ status },
						mac     => $if_ref->{ mac },
		};


		if ( exists $interface_ref->{ nic }->{ $if_ref->{ name } }->{ vlan } )
		{
			$if_conf->{ has_vlan } = 'true';
		}

		$if_conf->{ has_vlan } = 'false' unless $if_conf->{ has_vlan };

		push @output_list, $if_conf;
	}

	return \@output_list;
}

sub get_vlan_struct
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $vlan ) = @_;

	my @vlan_list = &getInterfaceTypeList( 'vlan', $vlan );
	my $interface = $vlan_list[0];

	return unless $interface;

	$interface->{ status } = &getInterfaceSystemStatus( $interface );

	# Any key must contain a value or "" but can't be null
	if ( !defined $interface->{ name } )    { $interface->{ name }    = ""; }
	if ( !defined $interface->{ addr } )    { $interface->{ addr }    = ""; }
	if ( !defined $interface->{ mask } )    { $interface->{ mask }    = ""; }
	if ( !defined $interface->{ dhcp } )    { $interface->{ dhcp }    = "false"; }
	if ( !defined $interface->{ gateway } ) { $interface->{ gateway } = ""; }
	if ( !defined $interface->{ status } )  { $interface->{ status }  = ""; }
	if ( !defined $interface->{ mac } )     { $interface->{ mac }     = ""; }

	my $output = {
				   name    => $interface->{ name },
				   ip      => $interface->{ addr },
				   netmask => $interface->{ mask },
				   dhcp    => $interface->{ dhcp },
				   gateway => $interface->{ gateway },
				   status  => $interface->{ status },
				   mac     => $interface->{ mac },
	};


	return $output;
}

sub get_vlan_list_struct
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	my @output_list;

	my $all_status = &getInterfaceSystemStatusAll();
	for my $if_ref ( &getInterfaceTypeList( 'vlan' ) )
	{
		$if_ref->{ status } = $all_status->{ $if_ref->{ name } };

		# Any key must cotain a value or "" but can't be null
		if ( !defined $if_ref->{ name } )    { $if_ref->{ name }    = ""; }
		if ( !defined $if_ref->{ addr } )    { $if_ref->{ addr }    = ""; }
		if ( !defined $if_ref->{ mask } )    { $if_ref->{ mask }    = ""; }
		if ( !defined $if_ref->{ dhcp } )    { $if_ref->{ dhcp }    = "false"; }
		if ( !defined $if_ref->{ gateway } ) { $if_ref->{ gateway } = ""; }
		if ( !defined $if_ref->{ status } )  { $if_ref->{ status }  = ""; }
		if ( !defined $if_ref->{ mac } )     { $if_ref->{ mac }     = ""; }

		my $if_conf = {
						name    => $if_ref->{ name },
						ip      => $if_ref->{ addr },
						netmask => $if_ref->{ mask },
						dhcp    => $if_ref->{ dhcp },
						gateway => $if_ref->{ gateway },
						status  => $if_ref->{ status },
						mac     => $if_ref->{ mac },
						parent  => $if_ref->{ parent },
		};


		push @output_list, $if_conf;
	}

	return \@output_list;
}

sub get_virtual_struct
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $virtual ) = @_;

	my @virtual_list = &getInterfaceTypeList( 'virtual', $virtual );
	my $interface    = $virtual_list[0];

	return unless $interface;

	$interface->{ status } = &getInterfaceSystemStatus( $interface );

	# Any key must contain a value or "" but can't be null
	if ( !defined $interface->{ name } )    { $interface->{ name }    = ""; }
	if ( !defined $interface->{ addr } )    { $interface->{ addr }    = ""; }
	if ( !defined $interface->{ mask } )    { $interface->{ mask }    = ""; }
	if ( !defined $interface->{ gateway } ) { $interface->{ gateway } = ""; }
	if ( !defined $interface->{ status } )  { $interface->{ status }  = ""; }
	if ( !defined $interface->{ mac } )     { $interface->{ mac }     = ""; }

	my $output = {
				   name    => $interface->{ name },
				   ip      => $interface->{ addr },
				   netmask => $interface->{ mask },
				   gateway => $interface->{ gateway },
				   status  => $interface->{ status },
				   mac     => $interface->{ mac },
	};


	return $output;
}

sub get_virtual_list_struct
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	my @output_list = ();
	my $all_status  = &getInterfaceSystemStatusAll();
	for my $if_ref ( &getInterfaceTypeList( 'virtual' ) )
	{
		$if_ref->{ status } = $all_status->{ $if_ref->{ name } };

		# Any key must cotain a value or "" but can't be null
		if ( !defined $if_ref->{ name } )    { $if_ref->{ name }    = ""; }
		if ( !defined $if_ref->{ addr } )    { $if_ref->{ addr }    = ""; }
		if ( !defined $if_ref->{ mask } )    { $if_ref->{ mask }    = ""; }
		if ( !defined $if_ref->{ gateway } ) { $if_ref->{ gateway } = ""; }
		if ( !defined $if_ref->{ status } )  { $if_ref->{ status }  = "down"; }
		if ( !defined $if_ref->{ mac } )     { $if_ref->{ mac }     = ""; }

		push @output_list,
		  {
			name    => $if_ref->{ name },
			ip      => $if_ref->{ addr },
			netmask => $if_ref->{ mask },
			gateway => $if_ref->{ gateway },
			status  => $if_ref->{ status },
			mac     => $if_ref->{ mac },
			parent  => $if_ref->{ parent },
		  };
	}


	return \@output_list;
}

=begin nd
Function: setInterfaceConfig

	Store a network interface configuration.

Parameters:
	if_ref - Reference to a network interface hash.
	params - Reference to the hash of params to modify.

Returns:
	boolean - 0 on success, or 1 on failure.

=cut

sub setVlan    # if_ref
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $if_ref = shift;
	my $params = shift;
	my $err    = 0;

	require Skudonet::Net::Core;
	require Skudonet::Net::Route;

	my $oldIf_ref = &getInterfaceConfig( $if_ref->{ name } );

	if ( $if_ref->{ dhcp } eq "true" )
	{
		$if_ref->{ addr }    = "";
		$if_ref->{ net }     = "";
		$if_ref->{ mask }    = "";
		$if_ref->{ gateway } = "";
	}

	if ( length $if_ref->{ mac } == 0 )
	{
		my $parent_if_name = &getParentInterfaceName( $if_ref->{ name } );
		my $parent_config  = &getInterfaceConfig( $parent_if_name );

		$if_ref->{ mac } = $parent_config->{ mac };
	}

	# Creating a new interface
	if ( !defined $oldIf_ref )
	{
		$err = &createVlan( $if_ref );
		return 1 if ( $err );
	}

	# Modifying
	my $oldAddr;

	# Add new IP, netmask and gateway
	if ( exists $if_ref->{ addr } and length $if_ref->{ addr } > 0 )
	{
		return 1 if &addIp( $if_ref );
		return 1 if &writeRoutes( $if_ref->{ name } );

		$oldAddr = $oldIf_ref->{ addr };
	}

	my $state = 1;

	if ( $if_ref->{ status } eq 'up' )
	{
		$state = &upIf( $if_ref, 'writeconf' );
	}

	return 1 if ( !&setInterfaceConfig( $if_ref ) );

	if ( $state == 0 )
	{
		$if_ref->{ status } = "up";

		if ( $if_ref->{ addr } > 0 )
		{
			return 1 if &applyRoutes( "local", $if_ref );
		}
	}


	# if the GW is changed, change it in all appending virtual interfaces
	if ( exists $if_ref->{ gateway } and length $if_ref->{ gateway } > 0 )
	{
		foreach my $appending ( &getInterfaceChild( $if_ref->{ vlan } ) )
		{
			my $app_config = &getInterfaceConfig( $appending );
			$app_config->{ gateway } = $params->{ gateway };
			&setInterfaceConfig( $app_config );
		}
	}

	# if the netmask is changed, change it in all appending virtual interfaces
	if ( exists $params->{ netmask } )
	{
		foreach my $appending ( &getInterfaceChild( $if_ref->{ name } ) )
		{
			my $app_config = &getInterfaceConfig( $appending );
			&delRoutes( "local", $app_config );
			&downIf( $app_config );
			$app_config->{ mask } = $params->{ netmask };
			&setInterfaceConfig( $app_config );
		}
	}

	# put all dependant interfaces up
	require Skudonet::Net::Util;
	&setIfacesUp( $if_ref->{ name }, "vini" );

	if ( $oldAddr )
	{
		require Skudonet::Farm::Base;
		my @farms = &getFarmListByVip( $oldAddr );

		# change farm vip,
		if ( @farms )
		{
			require Skudonet::Farm::Config;
			&setAllFarmByVip( $params->{ ip }, \@farms );
		}
	}

	return 0;
}

sub createVlan
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $if_ref = shift;

	require Skudonet::Net::Core;
	require Skudonet::Net::Route;

	my $err = 0;

	$err = &createIf( $if_ref );    # Create interface

	if ( !$err )
	{
		&writeRoutes( $if_ref->{ name } );
	}

	if ( !$err )
	{
		$err = 2 if ( !&setInterfaceConfig( $if_ref ) );
	}

	if ( $err )
	{
		&zenlog( "The vlan $if_ref->{name} could not be created", "error", "NETWORK" );
	}
	else
	{
		&zenlog( "The vlan $if_ref->{name} was created properly", "info", "NETWORK" );
	}

	return $err;
}

1;
