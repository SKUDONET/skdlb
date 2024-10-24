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
use warnings;

use Skudonet::Core;
use Skudonet::Farm::L4xNAT::Action;

my $configdir = &getGlobalConfiguration( 'configdir' );

=begin nd
Function: runL4FarmCreate

	Create a l4xnat farm

Parameters:
	vip - Virtual IP
	port - Virtual port. In l4xnat it ls possible to define multiport using ',' for add ports and ':' for ranges
	farmname - Farm name
	status - Set the initial status of the farm. The possible values are: 'down' for creating the farm and do not run it or 'up' (default) for running the farm when it has been created

Returns:
	Integer - return 0 on success or other value on failure

=cut

sub runL4FarmCreate
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $vip, $farm_name, $vip_port, $status ) = @_;

	$status = 'up' if not defined $status;

	my $output        = -1;
	my $farm_type     = 'l4xnat';
	my $farm_filename = "$configdir/$farm_name\_$farm_type.cfg";

	require Skudonet::Farm::L4xNAT::Action;
	require Skudonet::Farm::L4xNAT::Config;

	my $proto = ( $vip_port eq "*" ) ? 'all' : 'tcp';
	$vip_port = "80" if not defined $vip_port;
	$vip_port = ""   if ( $vip_port eq "*" );
	$vip_port =~ s/\:/\-/g;

	require Skudonet::Net::Validate;
	my $vip_family;
	if ( &ipversion( $vip ) == 6 )
	{
		$vip_family = "ipv6";
	}
	else
	{
		$vip_family = "ipv4";
	}

	$output = &sendL4NlbCmd(
		{
		   farm   => $farm_name,
		   file   => "$farm_filename",
		   method => "POST",
		   body   =>
			 qq({"farms" : [ { "name" : "$farm_name", "virtual-addr" : "$vip", "virtual-ports" : "$vip_port", "protocol" : "$proto", "mode" : "snat", "scheduler" : "weight", "state" : "$status", "family" : "$vip_family" } ] })
		}
	);

	if ( $output )
	{
		require Skudonet::Farm::Action;
		&runFarmDelete( $farm_name );
		return 1;
	}

	if ( $status eq 'up' )
	{
		$output = &startL4Farm( $farm_name );
	}

	return $output;
}

=begin nd
Function: runL4FarmDelete

	Delete a l4xnat farm

Parameters:

	farm_name - Farm name

Returns:
	Integer - return 0 on success or other value on failure

=cut

sub runL4FarmDelete
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name ) = @_;

	my $output = -1;

	require Skudonet::Farm::L4xNAT::Action;
	require Skudonet::Farm::L4xNAT::Config;
	require Skudonet::Farm::Core;
	require Skudonet::Netfilter;

	my $farmfile = &getFarmFile( $farm_name );

	$output = &sendL4NlbCmd( { farm => $farm_name, method => "DELETE" } );

	unlink ( "$configdir/$farmfile" ) if ( -f "$configdir/$farmfile" );

	&delMarks( $farm_name, "" );

	return $output;
}

1;

