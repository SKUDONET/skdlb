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


=begin nd
Function: getFarmEstConns

	Get all ESTABLISHED connections for a farm

Parameters:
	farmname - Farm name
	netstat  - reference to array with Conntrack -L output

Returns:
	unsigned integer - Return number of ESTABLISHED conntrack lines for a farm

=cut

sub getFarmEstConns    # ($farm_name,$netstat)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $netstat ) = @_;

	my $farm_type   = &getFarmType( $farm_name );
	my $connections = 0;

	if ( $farm_type eq "http" || $farm_type eq "https" )
	{
		my @pid = &getFarmPid( $farm_name );
		return $connections if ( !@pid );
		require Skudonet::Farm::HTTP::Stats;
		$connections = &getHTTPFarmEstConns( $farm_name );
	}
	elsif ( $farm_type eq "l4xnat" )
	{
		require Skudonet::Farm::L4xNAT::Stats;
		$connections = &getL4FarmEstConns( $farm_name, $netstat );
	}

	return $connections;
}

=begin nd
Function: getBackendSYNConns

	Get all SYN connections for a backend

Parameters:
	farmname     - Farm name
	ip_backend   - IP backend
	port_backend - backend port
	netstat      - reference to array with Conntrack -L output

Returns:
	integer - Return number of SYN conntrack lines for a backend of a farm or -1 if error

=cut

sub getBackendSYNConns    # ($farm_name,$ip_backend,$port_backend,$netstat)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $ip_backend, $port_backend, $netstat ) = @_;

	my $farm_type   = &getFarmType( $farm_name );
	my $connections = 0;

	if ( $farm_type eq "http" || $farm_type eq "https" )
	{
		require Skudonet::Farm::HTTP::Stats;
		$connections =
		  &getHTTPBackendSYNConns( $farm_name, $ip_backend, $port_backend );
	}
	elsif ( $farm_type eq "l4xnat" )
	{
		require Skudonet::Farm::L4xNAT::Stats;
		$connections =
		  &getL4BackendSYNConns( $farm_name, $ip_backend, $port_backend, $netstat );
	}

	return $connections;
}

=begin nd
Function: getFarmSYNConns

	Get all SYN connections for a farm

Parameters:
	farmname - Farm name
	netstat  - reference to array with Conntrack -L output

Returns:
	unsigned integer - Return number of SYN conntrack lines for a farm

=cut

sub getFarmSYNConns    # ($farm_name, $netstat)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $netstat ) = @_;

	my $farm_type   = &getFarmType( $farm_name );
	my $connections = 0;

	if ( $farm_type eq "http" || $farm_type eq "https" )
	{
		require Skudonet::Farm::HTTP::Stats;
		$connections = &getHTTPFarmSYNConns( $farm_name );
	}
	elsif ( $farm_type eq "l4xnat" )
	{
		require Skudonet::Farm::L4xNAT::Stats;
		$connections = &getL4FarmSYNConns( $farm_name, $netstat );
	}

	return $connections;
}

1;

