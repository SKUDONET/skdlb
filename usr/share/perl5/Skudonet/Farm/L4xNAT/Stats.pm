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

=begin nd
Function: getL4BackendEstConns

	Get all ESTABLISHED connections for a backend

Parameters:
	farmname - Farm name
	ip_backend - IP backend
	netstat - reference to array with Conntrack -L output

Returns:
	array - Return all ESTABLISHED conntrack lines for the backend

FIXME:
	dnat and nat regexp is duplicated

=cut

sub getL4BackendEstConns
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $be_ip, $be_port, $netstat ) = @_;

	my $farm = &getL4FarmStruct( $farm_name );

	my @fportlist   = &getFarmPortList( $farm->{ vport } );
	my $regexp      = "";
	my $connections = 0;
	my $add_search  = "";

	#if there is a backend port then must be included in the filter
	if ( $be_port > 0 )
	{
		$add_search = "sport=$be_port";
	}

	if ( $fportlist[0] !~ /\*/ )
	{
		$regexp = "\(" . join ( '|', @fportlist ) . "\)";
	}
	else
	{
		$regexp = "\.*";
	}

	if ( $farm->{ mode } eq "dnat" )
	{
		if (    $farm->{ proto } eq "sip"
			 || $farm->{ proto } eq "all"
			 || $farm->{ proto } eq "tcp" )
		{
# i.e.
# tcp      6 431998 ESTABLISHED src=192.168.0.168 dst=192.168.100.241 sport=40130 dport=81 src=192.168.100.254 dst=192.168.100.241 sport=80 dport=40130 [ASSURED] mark=523 use=1
#protocol				 status		      client                         vip                                                           vport          backend_ip                   (vip, but can change)    backend_port
			$connections += scalar @{
				&getNetstatFilter(
					"tcp",
					"",
					"\.* ESTABLISHED src=\.* dst=$farm->{ vip } \.* dport=$regexp \.*src=$be_ip \.*$add_search",
					"",
					$netstat
				)
			};
		}
		if (    $farm->{ proto } eq "sip"
			 || $farm->{ proto } eq "all"
			 || $farm->{ proto } eq "udp" )
		{
			$connections += scalar @{
				&getNetstatFilter(
					 "udp",
					 "",
					 "\.* src=\.* dst=$farm->{ vip } \.* dport=$regexp .*src=$be_ip \.*$add_search",
					 "",
					 $netstat
				)
			};
		}
	}
	else
	{
		if (    $farm->{ proto } eq "sip"
			 || $farm->{ proto } eq "all"
			 || $farm->{ proto } eq "tcp" )
		{
			$connections += scalar @{
				&getNetstatFilter(
					"tcp",
					"",
					"\.*ESTABLISHED src=\.* dst=$farm->{ vip } sport=\.* dport=$regexp \.*src=$be_ip \.*$add_search",
					"",
					$netstat
				)
			};
		}
		if (    $farm->{ proto } eq "sip"
			 || $farm->{ proto } eq "all"
			 || $farm->{ proto } eq "udp" )
		{
			$connections += scalar @{
				&getNetstatFilter(
					 "udp",
					 "",
					 "\.* src=\.* dst=$farm->{ vip } \.* dport=$regexp .*src=$be_ip \.*$add_search",
					 "",
					 $netstat
				)
			};
		}
	}

	return $connections;
}

=begin nd
Function: getL4FarmEstConns

	Get all ESTABLISHED connections for a farm

Parameters:
	farmname - Farm name
	netstat - reference to array with Conntrack -L output

Returns:
	array - Return all ESTABLISHED conntrack lines for a farm

FIXME:
	dnat and nat regexp is duplicated

=cut

sub getL4FarmEstConns
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $netstat ) = @_;
	require Skudonet::Net::ConnStats;

	my $farm = &getL4FarmStruct( $farm_name );

# states : NONE | SYN_SENT | SYN_RECV | ESTABLISHED | FIN_WAIT | CLOSE_WAIT | LAST_ACK | TIME_WAIT | CLOSE | LISTEN
	my $established_filter =
	  '(?:SYN_RECV|ESTABLISHED|FIN_WAIT|CLOSE_WAIT|LAST_ACK)';

	my @fportlist   = &getFarmPortList( $farm->{ vport } );
	my $regexp      = "";
	my $connections = 0;

	if ( $fportlist[0] !~ /\*/ )
	{
		$regexp = "\(" . join ( '|', @fportlist ) . "\)";
	}
	else
	{
		$regexp = "\.*";
	}

	my $backends = &getL4FarmServers( $farm_name );

	foreach my $backend ( @{ $backends } )
	{
		if ( $backend->{ status } eq "up" )
		{
			if ( $farm->{ mode } eq "dnat" )
			{
				if (    $farm->{ proto } eq "sip"
					 || $farm->{ proto } eq "all"
					 || $farm->{ proto } eq "tcp" )
				{
					$connections += scalar @{
						&getNetstatFilter(
							"tcp",
							"",
							"\.* $established_filter src=\.* dst=$farm->{ vip } \.* dport=$regexp .*src=$backend->{ ip } \.*",
							"",
							$netstat
						)
					};
				}

				if (    $farm->{ proto } eq "sip"
					 || $farm->{ proto } eq "all"
					 || $farm->{ proto } eq "udp" )
				{
					$connections += scalar @{
						&getNetstatFilter( "udp", "",
							"\.* src=\.* dst=$farm->{ vip } \.* dport=$regexp .*src=$backend->{ ip } \.*",
							"", $netstat )
					};
				}
			}
			else
			{
				if (    $farm->{ proto } eq "sip"
					 || $farm->{ proto } eq "all"
					 || $farm->{ proto } eq "tcp" )
				{
					$connections += scalar @{
						&getNetstatFilter(
							"tcp",
							"",
							"\.* $established_filter src=\.* dst=$farm->{ vip } \.* dport=$regexp .*src=$backend->{ ip } \.*",
							"",
							$netstat
						)
					};
				}

				if (    $farm->{ proto } eq "sip"
					 || $farm->{ proto } eq "all"
					 || $farm->{ proto } eq "udp" )
				{
					$connections += scalar @{
						&getNetstatFilter( "udp", "",
							   "\.* src=\.* dst=$farm->{ vip } \.* dport=$regexp .*src=$backend->{ ip }",
							   "", $netstat )
					};
				}
			}
		}
	}

	return $connections;
}

=begin nd
Function: getL4BackendSYNConns

	Get all SYN connections for a backend. This connection are called "pending". UDP protocol doesn't have pending concept

Parameters:
	farmname - Farm name
	ip_backend - IP backend
	netstat - reference to array with Conntrack -L output

Returns:
	array - Return all SYN conntrack lines for a backend of a farm

FIXME:
	dnat and nat regexp is duplicated

=cut

sub getL4BackendSYNConns
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $be_ip, $be_port, $netstat ) = @_;

	my $farm = &getL4FarmStruct( $farm_name );

	my @fportlist   = &getFarmPortList( $farm->{ vport } );
	my $regexp      = "";
	my $connections = 0;
	my $add_search  = "";

	#if there is a backend port then must be included in the filter
	if ( $be_port > 0 )
	{
		$add_search = "sport=$be_port";
	}

	if ( $fportlist[0] !~ /\*/ )
	{
		$regexp = "\(" . join ( '|', @fportlist ) . "\)";
	}
	else
	{
		$regexp = "\.*";
	}

	if ( $farm->{ mode } eq "dnat" )
	{
		if (    $farm->{ proto } eq "sip"
			 || $farm->{ proto } eq "all"
			 || $farm->{ proto } eq "tcp" )
		{
			$connections += scalar @{
				&getNetstatFilter(
					"tcp",
					"",
					"\.* SYN\.* src=\.* dst=$farm->{ vip } \.* dport=$regexp \.* src=$be_ip \.*$add_search",
					"",
					$netstat
				)
			};
		}

		# udp doesn't have pending connections
	}
	else
	{
		if (    $farm->{ proto } eq "sip"
			 || $farm->{ proto } eq "all"
			 || $farm->{ proto } eq "tcp" )
		{
			$connections += scalar @{
				&getNetstatFilter(
					"tcp",
					"",
					"\.* SYN\.* src=\.* dst=$farm->{ vip } \.* dport=$regexp \.* src=$be_ip \.*$add_search",
					"",
					$netstat
				)
			};
		}

		# udp doesn't have pending connections
	}

	return $connections;
}

=begin nd
Function: getL4FarmSYNConns

	Get all SYN connections for a farm. This connection are called "pending". UDP protocol doesn't have pending concept

Parameters:
	farmname - Farm name
	netstat - reference to array with Conntrack -L output

Returns:
	array - Return all SYN conntrack lines for a farm

FIXME:
	dnat and nat regexp is duplicated

=cut

sub getL4FarmSYNConns    # ($farm_name,$netstat)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $netstat ) = @_;

	my $farm = &getL4FarmStruct( $farm_name );

	my @fportlist   = &getFarmPortList( $farm->{ vport } );
	my $regexp      = "";
	my $connections = 0;

	if ( $fportlist[0] !~ /\*/ )
	{
		$regexp = "\(" . join ( '|', @fportlist ) . "\)";
	}
	else
	{
		$regexp = ".*";
	}

	my $backends = &getL4FarmServers( $farm_name );

# tcp      6 299 ESTABLISHED src=192.168.0.186 dst=192.168.100.241 sport=56668 dport=80 src=192.168.0.186 dst=192.168.100.241 sport=80 dport=56668 [ASSURED] mark=517 use=2
	foreach my $backend ( @{ $backends } )
	{
		if ( $backend->{ status } eq "up" )
		{
			if ( $farm->{ mode } eq "dnat" )
			{
				if (    $farm->{ proto } eq "sip"
					 || $farm->{ proto } eq "all"
					 || $farm->{ proto } eq "tcp" )
				{
					$connections += scalar @{
						&getNetstatFilter(
							"tcp",
							"",
							"\.* SYN\.* src=\.* dst=$farm->{ vip } \.* dport=$regexp \.* src=$backend->{ ip } \.*",
							"",
							$netstat
						)
					};
				}

				# udp doesn't have pending connections
			}
			else
			{
				if (    $farm->{ proto } eq "sip"
					 || $farm->{ proto } eq "all"
					 || $farm->{ proto } eq "tcp" )
				{
					$connections += scalar @{
						&getNetstatFilter(
							"tcp",
							"",
							"\.* SYN\.* src=\.* dst=$farm->{ vip } \.* dport=$regexp \.* src=$backend->{ ip } \.*",
							"",
							$netstat
						)
					};
				}

				# udp doesn't have pending connections
			}
		}
	}

	return $connections;
}

=begin nd
Function: getL4FarmBackendsStats



Parameters:
	farmname - Farm name

Returns:
	array ref -
=cut

sub getL4FarmBackendsStats
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farmname = shift;

	require Skudonet::Net::ConnStats;
	require Skudonet::Farm::L4xNAT::Config;

	# Get list of backend hashes and add stats
	my $farm_st = &getL4FarmStruct( $farmname );

	my $backends = $farm_st->{ servers };

	foreach my $be ( @{ $backends } )
	{
		my $netstat = &getConntrack( "", $farm_st->{ vip }, $be->{ 'ip' }, "", "" );

		# Established
		$be->{ 'established' } =
		  &getL4BackendEstConns( $farmname, $be->{ 'ip' }, $be->{ 'port' }, $netstat );

		# Pending
		$be->{ 'pending' } = 0;

		if ( $farm_st->{ proto } ne "udp" )
		{
			$be->{ 'pending' } =
			  &getL4BackendSYNConns( $farmname, $be->{ 'ip' }, $be->{ 'port' }, $netstat );
		}
	}

	return $backends;
}

1;

