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

require Skudonet::Core;
require Skudonet::Net::Core;
require Skudonet::Net::Route;
require Skudonet::Net::Interface;

=begin nd
Function: enableDHCP

	This function enables the dhcp for a networking interface.
	Set the configuration file and execute the dhcpclient

Parameters:
	if_ref - Reference to a network interface hash.

Returns:
	Integer - Error code, 0 on success or another value on failure.

=cut

sub enableDHCP
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $if_ref = shift;
	my $err    = 1;

	# save
	$if_ref->{ 'dhcp' } = 'true';
	$err = 0 if ( &setInterfaceConfig( $if_ref ) );

	# load the interface to reload the ip, gw and netmask
	my $status = &getInterfaceSystemStatus( $if_ref );

	if ( $status eq 'up' and !$err )
	{
		$err = &startDHCP( $if_ref->{ name } );
	}

	return $err;
}

=begin nd
Function: disableDHCP

	This function disables the dhcp for a networking interface.
	Set the configuration file and stop the dhcpclient process

Parameters:
	if_ref - Reference to a network interface hash.

Returns:
	Integer - Error code, 0 on success or 1 on failure.

=cut

sub disableDHCP
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $if_ref = shift;
	my $err    = 0;

	if ( &stopDHCP( $if_ref->{ name } ) )
	{
		return 1;
	}
	if ( $if_ref->{ addr } )
	{
		# Delete old IP and Netmask from system to replace it
		&delIp( $if_ref->{ name }, $if_ref->{ addr }, $if_ref->{ mask } );

		# Remove routes if the interface has its own route table: nic and vlan
		&delRoutes( "local", $if_ref );
	}

	# update config file and DHCP field of if_ref
	$if_ref->{ dhcp } = 'false';

	# Use a new hash ref to clean the dhcp configuration
	my $new_if_ref = {
					   name    => $if_ref->{ name },
					   dhcp    => "false",
					   mask    => "",
					   addr    => "",
					   gateway => ""
	};

	$err = 1
	  if ( !&setInterfaceConfig( $new_if_ref ) );

	return $err;
}

=begin nd
Function: getDHCPCmd

	Build the command line for executing a dhcpclient. This command is used to
	stop the dhclient process too.

Parameters:
	if_name - String with the interface name

Returns:
	String - Command line

=cut

sub getDHCPCmd
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $if_name  = shift;
	my $dhcp_cli = &getGlobalConfiguration( 'dhcp_bin' );
	return "$dhcp_cli $if_name";
}

=begin nd
Function: startDHCP

	Run a dhclient process for a interface

Parameters:
	if_name - String with the interface name

Returns:
	Integer - Error code, 0 on success or another value on failure

=cut

sub startDHCP
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $if_name = shift;
	my $pgrep   = &getGlobalConfiguration( "pgrep" );
	my $cmd     = &getDHCPCmd( $if_name );
	my @pids    = @{ &logAndGet( "$pgrep -f \"$cmd\"", "array" ) };

	if ( @pids )
	{
		&zenlog(
				 "The dhcp service is already running for $if_name, it will be restarted",
				 "debug2", "dhcp" );
		&stopDHCP( $if_name );
	}

	&zenlog( "starting dhcp service for $if_name", "debug", "dhcp" );

	my $err = &logAndRunBG( $cmd );
	sleep ( 2 );    # wait a while to get an IP

	return $err;
}

=begin nd
Function: stopDHCP

	Stop a dhclient process looking for the command line in the process table

Parameters:
	if_name - String with the interface name

Returns:
	Integer - Error code, 0 on success or 1 on failure

=cut

sub stopDHCP
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $if_name = shift;
	my $pgrep   = &getGlobalConfiguration( "pgrep" );
	my $cmd     = &getDHCPCmd( $if_name );
	my @pids    = @{ &logAndGet( "$pgrep -f \"^$cmd\"", "array" ) };
	if ( @pids )
	{
		&zenlog( "Stopping dhcp service for $if_name", "debug", "dhcp" );
		kill 'KILL', @pids;
	}

	use Time::HiRes qw(usleep);
	my $max_retry = 50;
	my $retry     = 0;
	while ( ( $retry < $max_retry ) )
	{
		# success if all process were killed (pgrep return code should be 1)
		my $status = &logRunAndGet( "$pgrep -f \"^$cmd\"", "array" );
		if ( $status->{ stderr } == 1 )
		{
			return 0;
		}
		$retry += 1;
		usleep( 100_000 );
	}
	&zenlog( "DHCP could not be stopped for $if_name", "error", "dhcp" );
	return 1;
}

1;
