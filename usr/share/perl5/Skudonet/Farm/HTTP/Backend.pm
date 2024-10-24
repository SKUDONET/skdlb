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
sub include;
require Skudonet::Netfilter;
require Skudonet::Farm::Config;

my $configdir = &getGlobalConfiguration( 'configdir' );
my $proxy_ng  = &getGlobalConfiguration( 'proxy_ng' );


=begin nd
Function: setHTTPFarmServer

	Add a new backend to a HTTP service or modify if it exists

Parameters:
	ids - backend id
	rip - backend ip
	port - backend port
	weight - The weight of this backend (between 1 and 9). Higher weight backends will be used more often than lower weight ones.
	timeout - Override the global time out for this backend
	farmname - Farm name
	service - service name
	priority - The priority of this backend (greater than 1). Lower value indicates higher priority

Returns:
	Integer - return 0 on success or -1 on failure

=cut

sub setHTTPFarmServer # ($ids,$rip,$port,$weight,$timeout,$farm_name,$service,$priority,$connlimit)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my (
		 $ids,       $rip,     $port,     $weight, $timeout,
		 $farm_name, $service, $priority, $connlimit
	) = @_;

	if ( $proxy_ng eq 'true' )
	{
		return
		  &setHTTPNGFarmServer(
								$ids,     $rip,      $port,
								$weight,  $timeout,  $farm_name,
								$service, $priority, $connlimit
		  );
	}
	elsif ( $proxy_ng eq 'false' )
	{
		$priority = $weight;
	}

	my $farm_filename = &getFarmFile( $farm_name );
	my $output        = -1;

	require Skudonet::Lock;
	my $lock_file = &getLockFile( $farm_name );
	my $lock_fh   = &openlock( $lock_file, 'w' );

	require Tie::File;
	tie my @contents, 'Tie::File', "$configdir\/$farm_filename";

	if ( $ids !~ /^$/ )
	{
		my $index_count = -1;
		my $i           = -1;
		my $sw          = 0;

		foreach my $line ( @contents )
		{
			$i++;

			#search the service to modify
			if ( $line =~ /Service \"$service\"/ )
			{
				$sw = 1;
			}
			if ( $line =~ /BackEnd/ && $line !~ /#/ && $sw eq 1 )
			{
				$index_count++;
				if ( $index_count == $ids )
				{
					#server for modify $ids;
					#HTTPS
					my $httpsbe = &getHTTPFarmVS( $farm_name, $service, "httpsbackend" );
					if ( $httpsbe eq "true" )
					{
						#add item
						$i++;
					}
					$output           = $?;
					$contents[$i + 1] = "\t\t\tAddress $rip";
					$contents[$i + 2] = "\t\t\tPort $port";
					my $p_m = 0;
					if ( $contents[$i + 3] =~ /TimeOut/ )
					{
						$contents[$i + 3] = "\t\t\tTimeOut $timeout";
						&zenlog( "Modified current timeout", "info", "LSLB", "info", "LSLB" );
					}
					if ( $contents[$i + 4] =~ /Priority/ )
					{
						$contents[$i + 4] = "\t\t\tPriority $priority";
						&zenlog( "Modified current priority", "info", "LSLB" );
						$p_m = 1;
					}
					if ( $contents[$i + 3] =~ /Priority/ )
					{
						$contents[$i + 3] = "\t\t\tPriority $priority";
						$p_m = 1;
					}

					#delete item
					if ( $timeout =~ /^$/ )
					{
						if ( $contents[$i + 3] =~ /TimeOut/ )
						{
							splice @contents, $i + 3, 1,;
						}
					}
					if ( $priority =~ /^$/ )
					{
						if ( $contents[$i + 3] =~ /Priority/ )
						{
							splice @contents, $i + 3, 1,;
						}
						if ( $contents[$i + 4] =~ /Priority/ )
						{
							splice @contents, $i + 4, 1,;
						}
					}

					#new item
					if (
						 $timeout !~ /^$/
						 && (    $contents[$i + 3] =~ /End/
							  || $contents[$i + 3] =~ /Priority/ )
					  )
					{
						splice @contents, $i + 3, 0, "\t\t\tTimeOut $timeout";
					}
					if (
							$p_m eq 0
						 && $priority !~ /^$/
						 && (    $contents[$i + 3] =~ /End/
							  || $contents[$i + 4] =~ /End/ )
					  )
					{
						if ( $contents[$i + 3] =~ /TimeOut/ )
						{
							splice @contents, $i + 4, 0, "\t\t\tPriority $priority";
						}
						else
						{
							splice @contents, $i + 3, 0, "\t\t\tPriority $priority";
						}
					}
				}
			}
		}
	}
	else
	{
		#add new server
		my $nsflag     = "true";
		my $index      = -1;
		my $backend    = 0;
		my $be_section = -1;

		foreach my $line ( @contents )
		{
			$index++;
			if ( $be_section == 1 && $line =~ /Address/ )
			{
				$backend++;
			}
			if ( $line =~ /Service \"$service\"/ && $be_section == -1 )
			{
				$be_section++;
			}
			if ( $line =~ /#BackEnd/ && $be_section == 0 )
			{
				$be_section++;
			}
			if ( $be_section == 1 && $line =~ /#End/ )
			{
				splice @contents, $index, 0, "\t\tBackEnd";
				$output = $?;
				$index++;
				splice @contents, $index, 0, "\t\t\tAddress $rip";
				my $httpsbe = &getHTTPFarmVS( $farm_name, $service, "httpsbackend" );
				if ( $httpsbe eq "true" )
				{
					#add item
					splice @contents, $index, 0, "\t\t\tHTTPS";
					$index++;
				}
				$index++;
				splice @contents, $index, 0, "\t\t\tPort $port";
				$index++;

				#Timeout?
				if ( $timeout )
				{
					splice @contents, $index, 0, "\t\t\tTimeOut $timeout";
					$index++;
				}

				#Priority?
				if ( $priority )
				{
					splice @contents, $index, 0, "\t\t\tPriority $priority";
					$index++;
				}
				splice @contents, $index, 0, "\t\tEnd";
				$be_section++;    # Backend Added
			}

			# if backend added then go out of form
		}
		if ( $nsflag eq "true" )
		{
			my $idservice = &getFarmVSI( $farm_name, $service );
			if ( $idservice ne "" )
			{
				&setHTTPFarmBackendStatusFile( $farm_name, $backend, "active", $idservice );
			}
		}
	}
	untie @contents;
	close $lock_fh;

	return $output;
}

=begin nd
Function: setHTTPNGFarmServer

	Add a new backend to a HTTP service or modify if it exists

Parameters:
	ids - backend id
	rip - backend ip
	port - backend port
	weight - The weight of this backend (between 1 and 9). Higher weight backends will be used more often than lower weight ones.
	timeout - Override the global time out for this backend
	farmname - Farm name
	service - service name
	priority - The priority of this backend (greater than 1). Lower value indicates higher priority

Returns:
	Integer - return 0 on success or -1 on failure

=cut

sub setHTTPNGFarmServer # ($ids,$rip,$port,$weight,$timeout,$farm_name,$service,$priority,$connlimit)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	my (
		 $ids,       $rip,     $port,     $weight, $timeout,
		 $farm_name, $service, $priority, $connlimit
	) = @_;
	my $farm_filename = &getFarmFile( $farm_name );
	my $output        = -1;

	require Skudonet::Lock;
	my $lock_file = &getLockFile( $farm_name );
	my $lock_fh   = &openlock( $lock_file, 'w' );

	require Tie::File;
	tie my @contents, 'Tie::File', "$configdir\/$farm_filename";

	if ( $ids !~ /^$/ )
	{
		my $index_count = -1;
		my $i           = -1;
		my $sw          = 0;
		my $bw          = 0;
		my %data = (
					 'TimeOut', $timeout, 'Priority',  $priority,
					 'Weight',  $weight,  'ConnLimit', $connlimit,
					 'Address', $rip,     'Port',      $port
		);
		my %setted = (
					   'TimeOut',   0, 'Priority', 0, 'Weight', 0,
					   'ConnLimit', 0, 'Address',  0, 'Port',   0
		);
		my $value;
		my $dec_mark;

		my $line;
		for ( $i = 0 ; $i < $#contents ; $i++ )
		{
			$line = $contents[$i];

			#search the service to modify
			if ( $line =~ /Service \"$service\"/ )
			{
				$sw = 1;
				next;
			}
			if ( $line =~ /BackEnd/ && $line !~ /#/ && $sw eq 1 )
			{
				$index_count++;
				if ( $index_count == $ids )
				{
					$output = $?;
					$bw     = 1;
				}
				next;
			}
			if ( $bw == 1 )
			{
				if ( $line =~ /(TimeOut|Priority|Weight|ConnLimit|Address|Port)/ )
				{
					$value = $data{ $1 };
					$setted{ "$1" } = 1;
					if ( $value =~ /^$/ )
					{
						splice @contents, $i, 1,;
						$i--;
						next;
					}
					else
					{
						$contents[$i] = "\t\t\t$1 $value";
						next;
					}
				}
				if ( $line =~ /\s*NfMark\s*(.*)/ )
				{
					$dec_mark = $1;
					next;
				}
				if ( $line =~ /^\s+End/ )
				{
					my @keys = keys %data;
					foreach my $key ( @keys )
					{
						$value = $data{ $key };
						if ( !$setted{ $key } && $value !~ /^$/ )
						{
							splice @contents, $i, 0, "\t\t\t$key $data{\"$key\"}";
							$data{ "$key" } = 1;
						}
					}
					last;
				}
			}
		}
	}
	else
	{
		#add new server
		my $nsflag             = "true";
		my $index              = -1;
		my $backend            = 0;
		my $be_section         = -1;
		my $farm_ref->{ name } = $farm_name;
		$ids = 0;

		foreach my $line ( @contents )
		{
			$index++;
			if ( $be_section == 1 && $line =~ /Address/ )
			{
				$ids++;
				$backend++;
			}
			if ( $line =~ /Service \"$service\"/ && $be_section == -1 )
			{
				$be_section++;
			}
			if ( $line =~ /#BackEnd/ && $be_section == 0 )
			{
				$be_section++;
			}
			if ( $be_section == 1 && $line =~ /#End/ )
			{
				splice @contents, $index, 0, "\t\tBackEnd";
				$output = $?;
				$index++;
				splice @contents, $index, 0, "\t\t\tAddress $rip";
				my $httpsbe = &getHTTPFarmVS( $farm_name, $service, "httpsbackend" );
				if ( $httpsbe eq "true" )
				{
					#add item
					splice @contents, $index, 0, "\t\t\tHTTPS";
					$index++;
				}
				$index++;
				splice @contents, $index, 0, "\t\t\tPort $port";
				$index++;

				#Timeout?
				if ( $timeout )
				{
					splice @contents, $index, 0, "\t\t\tTimeOut $timeout";
					$index++;
				}

				#Priority?
				if ( $priority )
				{
					splice @contents, $index, 0, "\t\t\tPriority $priority";
					$index++;
				}

				#Weight?
				if ( $weight )
				{
					splice @contents, $index, 0, "\t\t\tWeight $weight";
					$index++;
				}

				#ConnLimit?
				if ( $connlimit )
				{
					splice @contents, $index, 0, "\t\t\tConnLimit $connlimit";
					$index++;
				}

				#NfMark
				my $hex_mark = &getNewMark( $farm_name );
				my $dec_mark = sprintf ( "%D", hex ( $hex_mark ) );
				splice @contents, $index, 0, "\t\t\tNfMark $dec_mark";
				if ( &getGlobalConfiguration( 'mark_routing_L7' ) eq 'true' )
				{
					my $fstate = &getFarmStatus( $farm_name );
					$farm_ref->{ vip } = &getFarmVip( 'vip', $farm_name );
					require Skudonet::Farm::Backend;
					&setBackendRule( "add", $farm_ref, $hex_mark ) if ( $fstate eq 'up' );
				}
				$index++;

				splice @contents, $index, 0, "\t\tEnd";
				$be_section++;    # Backend Added

			}

			# if backend added then go out of form
		}
		if ( $nsflag eq "true" )
		{
			my $idservice = &getFarmVSI( $farm_name, $service );
			if ( $idservice ne "" )
			{
				&setHTTPFarmBackendStatusFile( $farm_name, $backend, "active", $idservice );
			}
		}
	}
	untie @contents;
	close $lock_fh;

	return $output;
}

=begin nd
Function: runHTTPFarmServerDelete

	Delete a backend in a HTTP service

Parameters:
	ids - backend id to delete it
	farmname - Farm name
	service - service name where is the backend

Returns:
	Integer - return 0 on success or -1 on failure

=cut

sub runHTTPFarmServerDelete    # ($ids,$farm_name,$service)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $ids, $farm_name, $service ) = @_;

	my $farm_filename = &getFarmFile( $farm_name );
	my $output        = -1;
	my $i             = -1;
	my $j             = -1;
	my $sw            = 0;
	my $dec_mark;
	my $farm_ref = getFarmStruct( $farm_name );

	require Skudonet::Lock;
	my $lock_file = &getLockFile( $farm_name );
	my $lock_fh   = &openlock( $lock_file, 'w' );

	require Tie::File;
	tie my @contents, 'Tie::File', "$configdir\/$farm_filename";
	foreach my $line ( @contents )
	{
		$i++;
		if ( $line =~ /Service \"$service\"/ )
		{
			$sw = 1;
		}
		if ( $line =~ /BackEnd/ && $line !~ /#/ && $sw == 1 )
		{
			$j++;
			if ( $j == $ids )
			{
				splice @contents, $i, 1,;
				$output = $?;
				while ( $contents[$i] !~ /End/ )
				{
					if ( $contents[$i] =~ /\s*NfMark\s*(.*)/ )
					{
						$dec_mark = $1;
						my $mark = sprintf ( "0x%x", $1 );
						&delMarks( "", $mark );
						if ( &getGlobalConfiguration( 'mark_routing_L7' ) eq 'true' )
						{
							require Skudonet::Farm::Backend;
							&setBackendRule( "del", $farm_ref, $mark );
						}
					}
					splice @contents, $i, 1,;
				}
				splice @contents, $i, 1,;
			}
		}
	}
	untie @contents;

	close $lock_fh;

	if ( &getGlobalConfiguration( 'proxy_ng' ) eq 'true' )
	{
		require Skudonet::Farm::HTTP::Sessions;
		&deleteConfL7FarmAllSession( $farm_name, $service, $ids );

	}

	if ( $output != -1 )
	{
		&runRemoveHTTPBackendStatus( $farm_name, $ids, $service );
	}

	return $output;
}

=begin nd
Function: setHTTPFarmBackendsMarks

	Set marks in the backends of an HTTP farm

Parameters:
	farmname - Farm name

Returns:
	$error_ref: $error_ref->{ code } - 0 on success, 1 on failure.
				$error_ref->{ desc } - error message.
=cut

sub setHTTPFarmBackendsMarks    # ($farm_name)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	my ( $farm_name ) = @_;
	my $error_ref->{ code } = -1;
	require Skudonet::Farm::Core;
	my $farm_filename = &getFarmFile( $farm_name );
	if ( $farm_filename == -1 )
	{
		my $msg =
		  "Backend Marks for farm $farm_name could not be set, config file does not exist";
		$error_ref->{ code } = 1;
		$error_ref->{ desc } = $msg;
		&zenlog( $error_ref->{ desc }, "warning", "HTTP" );
		return $error_ref;
	}
	else
	{
		$error_ref->{ code } = 0;
	}

	my $i        = -1;
	my $farm_ref = getFarmStruct( $farm_name );
	my $sw       = 0;
	my $bw       = 0;
	my $ms       = 0;

	require Tie::File;
	tie my @contents, 'Tie::File', "$configdir\/$farm_filename";
	foreach my $line ( @contents )
	{
		$i++;
		if ( $line =~ /^\s+Service\s*\".*\"/ )
		{
			$sw = 1;
		}
		if ( $line =~ /^\s+BackEnd/ && $sw == 1 )
		{
			$bw = 1;
			$ms = 0;
		}
		if ( $line =~ /^\s+NfMark\s*(.*)/ && $bw == 1 )
		{
			$ms = 1;
		}
		if ( $line =~ /^\s+End/ && $bw == 1 )
		{
			$bw = 0;
			if ( $ms == 0 )
			{
				my $hex_mark = &getNewMark( $farm_name );
				my $dec_mark = sprintf ( "%D", hex ( $hex_mark ) );
				splice @contents, $i, 0, "\t\t\tNfMark $dec_mark";
				if ( &getGlobalConfiguration( 'mark_routing_L7' ) eq 'true' )
				{
					my $fstate = &getFarmStatus( $farm_name );
					&setBackendRule( "add", $farm_ref, $hex_mark ) if ( $fstate eq 'up' );
				}
				$ms = 1;
			}
		}
	}
	untie @contents;
	return $error_ref;
}

=begin nd
Function: removeHTTPFarmBackendsMarks

	Remove marks from the backends of an HTTP farm

Parameters:
	farmname - Farm name

Returns:
	None

=cut

sub removeHTTPFarmBackendsMarks    # ($farm_name)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	require Skudonet::Farm::Core;
	my ( $farm_name ) = @_;
	my $farm_filename = &getFarmFile( $farm_name );

	my $i        = -1;
	my $farm_ref = getFarmStruct( $farm_name );
	my $sw       = 0;
	my $bw       = 0;

	require Tie::File;
	tie my @contents, 'Tie::File', "$configdir\/$farm_filename";
	foreach my $line ( @contents )
	{
		$i++;
		if ( $line =~ /^\tService\s*\".*\"/ )
		{
			$sw = 1;
		}
		if ( $line =~ /^\tEnd/ && $sw == 1 && $bw == 0 )
		{
			$sw = 0;
		}
		if ( $line =~ /^\t\tBackEnd/ && $sw == 1 )
		{
			$bw = 1;
		}
		if ( $line =~ /^\s+NfMark\s*(.*)/ && $bw == 1 )
		{
			my $mark = sprintf ( "0x%x", $1 );
			&delMarks( "", $mark );
			if ( &getGlobalConfiguration( 'mark_routing_L7' ) eq 'true' )
			{
				require Skudonet::Farm::Backend;
				&setBackendRule( "del", $farm_ref, $mark );
			}
			splice @contents, $i, 1,;
		}
		if ( $line =~ /^\t\tEnd/ && $bw == 1 )
		{
			$bw = 0;
		}
	}
	untie @contents;
}

=begin nd
Function: getHTTPFarmBackendStatusCtl

	Get status of a HTTP farm and its backends, sessions can be not included

Parameters:
	farmname - Farm name
	sessions - "true" show sessions info. "false" sessions are not shown.

Returns:
	array - return the output of proxyctl command for a farm

=cut

sub getHTTPFarmBackendStatusCtl    # ($farm_name, $sessions)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $sessions ) = @_;

	my $proxyctl = &getGlobalConfiguration( 'proxyctl' );

	my $sessions_option = "-C";
	if ( defined $sessions and $sessions = "true" )
	{
		$sessions_option = "";
	}
	return @{
		&logAndGet( "$proxyctl $sessions_option -c /tmp/$farm_name\_proxy.socket",
					"array" )
	};
}

=begin nd
Function: getHTTPFarmBackends

	Return a list with all backends in a service and theirs configuration

Parameters:
	farmname - Farm name
	service - Service name
	param_status - "true" or "false" to indicate to get backend status.

Returns:
	array ref - Each element in the array it is a hash ref to a backend.
	the array index is the backend id

=cut

sub getHTTPFarmBackends    # ($farm_name,$service,$param_status)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farmname, $service, $param_status ) = @_;

	require Skudonet::Farm::HTTP::Service;

	my $proxy_ng   = &getGlobalConfiguration( 'proxy_ng' );
	my $backendsvs = &getHTTPFarmVS( $farmname, $service, "backends" );
	my @be         = split ( "\n", $backendsvs );
	my @be_status;
	if ( !$param_status or $param_status eq "true" )
	{
		@be_status = @{ &getHTTPFarmBackendsStatus( $farmname, $service ) };
	}
	my @out_ba;

	my $backend_ref;
	foreach my $subl ( @be )
	{
		my @subbe = split ( ' ', $subl );
		my $id    = $subbe[1] + 0;

		my $ip   = $subbe[3];
		my $port = $subbe[5] + 0;
		my $tout = $subbe[7];
		my $prio = $subbe[9];
		my $weig = $subbe[11];
		my $conn = $subbe[13];
		my $tag  = $subbe[15];

		$tout = $tout eq '-' ? undef : $tout + 0;
		$prio = $prio eq '-' ? undef : $prio + 0;
		$weig = $weig eq '-' ? undef : $weig + 0;
		$conn = $conn eq '-' ? undef : $conn + 0;
		$tag  = $tag eq '-'  ? undef : $tag + 0;

		my $status = "undefined";
		if ( !$param_status or $param_status eq "true" )
		{
			$status = $be_status[$id] if $be_status[$id];
		}

		if ( $proxy_ng eq 'true' )
		{
			$backend_ref = {
							 id               => $id,
							 ip               => $ip,
							 port             => $port + 0,
							 timeout          => $tout,
							 priority         => $prio,
							 weight           => $weig,
							 connection_limit => $conn,
							 tag              => $tag
			};

		}
		elsif ( $proxy_ng )
		{
			$backend_ref = {
							 id      => $id,
							 ip      => $ip,
							 port    => $port + 0,
							 timeout => $tout,
							 weight  => $prio
			};
		}
		if ( !$param_status or $param_status eq "true" )
		{
			$backend_ref->{ status } = $status;
		}
		push @out_ba, $backend_ref;
		$backend_ref = undef;

	}

	return \@out_ba;
}

=begin nd
Function: getHTTPFarmBackendsStatus

	Get the status of all backends in a service. The possible values are:

	- up = The farm is in up status and the backend is OK.
	- down = The farm is in up status and the backend is unreachable
	- maintenace = The backend is in maintenance mode.
	- undefined = The farm is in down status and backend is not in maintenance mode.


Parameters:
	farmname - Farm name
	service - Service name

Returns:
	Array ref - the index is backend index, the value is the backend status

=cut

#ecm possible bug here returns 2 values instead of 1 (1 backend only)
sub getHTTPFarmBackendsStatus    # ($farm_name,@content)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $service ) = @_;

	require Skudonet::Farm::Base;

	my @status;
	my $farmStatus = &getFarmStatus( $farm_name );
	my $stats;

	if ( $farmStatus eq "up" )
	{
		require Skudonet::Farm::HTTP::Backend;
		$stats = &getHTTPFarmBackendsStatusInfo( $farm_name );
	}

	require Skudonet::Farm::HTTP::Service;

	my $backendsvs = &getHTTPFarmVS( $farm_name, $service, "backends" );
	my @be         = split ( "\n", $backendsvs );
	my $id         = 0;

	# @be is used to get size of backend array
	for ( @be )
	{
		my $backendstatus = &getHTTPBackendStatusFromFile( $farm_name, $id, $service );
		if ( $backendstatus ne "maintenance" )
		{
			if ( $farmStatus eq "up" )
			{
				$backendstatus = $stats->{ $service }->{ backends }[$id]->{ status };
			}
			else
			{
				$backendstatus = "undefined";
			}
		}
		push @status, $backendstatus;
		$id = $id + 1;
	}

	return \@status;
}

=begin nd
Function: getHTTPBackendStatusFromFile

	Function that return if a l7 proxy backend is active, down by farmguardian or it's in maintenance mode

Parameters:
	farmname - Farm name
	backend - backend id
	service - service name

Returns:
	scalar - return backend status: "maintentance", "fgDOWN", "active" or -1 on failure

=cut

sub getHTTPBackendStatusFromFile    # ($farm_name,$backend,$service)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $backend, $service ) = @_;

	require Skudonet::Farm::HTTP::Service;

	my $index;
	my $stfile = "$configdir\/$farm_name\_status.cfg";

	# if the status file does not exist the backend is ok
	my $output = "active";
	if ( !-e $stfile )
	{
		return $output;
	}

	$index = &getFarmVSI( $farm_name, $service );
	open my $fd, '<', $stfile;

	while ( my $line = <$fd> )
	{
		#service index
		if ( $line =~ /\ 0\ ${index}\ ${backend}/ )
		{
			if ( $line =~ /maintenance/ )
			{
				$output = "maintenance";
			}
			elsif ( $line =~ /fgDOWN/ )
			{
				$output = "fgDOWN";
			}
			else
			{
				$output = "active";
			}
		}
	}
	close $fd;
	return $output;
}

=begin nd
Function: setHTTPFarmBackendStatusFile

	Function that save in a file the backend status (maintenance or not)

Parameters:
	farmname - Farm name
	backend - Backend id
	status - backend status to save in the status file
	service_id - Service id

Returns:
	none - .

FIXME:
	Not return anything, do error control

=cut

sub setHTTPFarmBackendStatusFile    # ($farm_name,$backend,$status,$idsv)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $backend, $status, $idsv ) = @_;

	require Tie::File;

	my $statusfile = "$configdir\/$farm_name\_status.cfg";
	my $changed    = "false";

	if ( !-e $statusfile )
	{
		open my $fd, '>', "$statusfile";
		my $proxyctl = &getGlobalConfiguration( 'proxyctl' );
		my @run =
		  @{ &logAndGet( "$proxyctl -C -c /tmp/$farm_name\_proxy.socket", "array" ) };
		my @sw;
		my @bw;

		foreach my $line ( @run )
		{
			if ( $line =~ /\.\ Service\ / )
			{
				@sw = split ( "\ ", $line );
				$sw[0] =~ s/\.//g;
				chomp $sw[0];
			}
			if ( $line =~ /\.\ Backend\ / )
			{
				@bw = split ( "\ ", $line );
				$bw[0] =~ s/\.//g;
				chomp $bw[0];
				if ( $bw[3] eq "active" )
				{
					#~ print FW "-B 0 $sw[0] $bw[0] active\n";
				}
				else
				{
					print $fd "-b 0 $sw[0] $bw[0] fgDOWN\n";
				}
			}
		}
		close $fd;
	}

	tie my @filelines, 'Tie::File', "$statusfile";
	my $i;

	foreach my $linea ( @filelines )
	{
		if ( $linea =~ /\ 0\ $idsv\ $backend/ )
		{
			if ( $status =~ /maintenance/ || $status =~ /fgDOWN/ )
			{
				$linea   = "-b 0 $idsv $backend $status";
				$changed = "true";
			}
			else
			{
				splice @filelines, $i, 1,;
				$changed = "true";
			}
		}
		$i++;
	}
	untie @filelines;

	if ( $changed eq "false" )
	{
		open my $fd, '>>', "$statusfile";

		if ( $status =~ /maintenance/ || $status =~ /fgDOWN/ )
		{
			print $fd "-b 0 $idsv $backend $status\n";
		}
		else
		{
			splice @filelines, $i, 1,;
		}

		close $fd;
	}

}

=begin nd
Function: getHTTPFarmBackendsClients

	Function that return number of clients with session in a backend server

Parameters:
	backend - backend id
	content - command output where parsing backend status
	farmname - Farm name

Returns:
	Integer - return number of clients in the backend

=cut

sub getHTTPFarmBackendsClients    # ($idserver,@content,$farm_name)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $idserver, @content, $farm_name ) = @_;

	if ( !@content )
	{
		@content = &getHTTPFarmBackendStatusCtl( $farm_name );
	}

	my $numclients = 0;

	foreach ( @content )
	{
		if ( $_ =~ / Session .* -> $idserver$/ )
		{
			$numclients++;
		}
	}

	return $numclients;
}

=begin nd
Function: getHTTPFarmBackendsClientsList

	Function that return sessions of clients

Parameters:
	farmname - Farm name
	content - command output where it must be parsed backend status

Returns:
	array - return information about existing sessions. The format for each line is: "service" . "\t" . "session_id" . "\t" . "session_value" . "\t" . "backend_id"

FIXME:
	will be useful change output format to hash format

=cut

sub getHTTPFarmBackendsClientsList    # ($farm_name,@content)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, @content ) = @_;

	my @client_list;
	my $s;

	if ( !@content )
	{
		@content = &getHTTPFarmBackendStatusCtl( $farm_name );
	}

	foreach ( @content )
	{
		my $line;
		if ( $_ =~ /Service/ )
		{
			my @service = split ( "\ ", $_ );
			$s = $service[2];
			$s =~ s/"//g;
		}
		if ( $_ =~ / Session / )
		{
			my @sess = split ( "\ ", $_ );
			my $id   = $sess[0];
			$id =~ s/\.//g;
			$line = $s . "\t" . $id . "\t" . $sess[2] . "\t" . $sess[4];
			push ( @client_list, $line );
		}
	}

	return @client_list;
}

=begin nd
Function: setHTTPFarmBackendMaintenance

	Function that enable the maintenance mode for backend

Parameters:
	farmname - Farm name
	backend - Backend id
	mode - Maintenance mode, the options are: drain, the backend continues working with
	  the established connections; or cut, the backend cuts all the established
	  connections
	service - Service name

Returns:
	Integer - return 0 on success or -1 on failure

=cut

sub setHTTPFarmBackendMaintenance    # ($farm_name,$backend,$mode,$service)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $backend, $mode, $service ) = @_;

	my $output = 0;

	#find the service number
	my $idsv = &getFarmVSI( $farm_name, $service );

	&zenlog(
			"setting Maintenance mode for $farm_name service $service backend $backend",
			"info", "LSLB" );

	if ( &getFarmStatus( $farm_name ) eq 'up' )
	{
		my $proxyctl = &getGlobalConfiguration( 'proxyctl' );
		my $proxyctl_command =
		  "$proxyctl -c /tmp/$farm_name\_proxy.socket -b 0 $idsv $backend";

		$output = &logAndRun( $proxyctl_command );
	}

	if ( !$output )
	{
		if ( $mode eq "cut" )
		{
			require Skudonet::Farm::HTTP::Service;
			if ( &getHTTPFarmVS( $farm_name, $service, "sesstype" ) ne "" )
			{
				&setHTTPFarmBackendsSessionsRemove( $farm_name, $service, $backend );
			}
		}
		&setHTTPFarmBackendStatusFile( $farm_name, $backend, "maintenance", $idsv );
	}

	return $output;
}

=begin nd
Function: setHTTPFarmBackendNoMaintenance

	Function that disable the maintenance mode for backend

Parameters:
	farmname - Farm name
	backend - Backend id
	service - Service name

Returns:
	Integer - return 0 on success or -1 on failure

=cut

sub setHTTPFarmBackendNoMaintenance    # ($farm_name,$backend,$service)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $backend, $service ) = @_;

	my $output = 0;

	#find the service number
	my $idsv = &getFarmVSI( $farm_name, $service );

	&zenlog(
		"setting Disabled maintenance mode for $farm_name service $service backend $backend",
		"info", "LSLB"
	);

	if ( &getFarmStatus( $farm_name ) eq 'up' )
	{
		my $proxyctl = &getGlobalConfiguration( 'proxyctl' );
		my $proxyctl_command =
		  "$proxyctl -c /tmp/$farm_name\_proxy.socket -B 0 $idsv $backend";

		$output = &logAndRun( $proxyctl_command );
	}

	# save backend status in status file
	&setHTTPFarmBackendStatusFile( $farm_name, $backend, "active", $idsv );

	return $output;
}

=begin nd
Function: runRemoveHTTPBackendStatus

	Function that removes a backend from the status file

Parameters:
	farmname - Farm name
	backend - Backend id
	service - Service name

Returns:
	none - .

FIXME:
	This function returns nothing, do error control

=cut

sub runRemoveHTTPBackendStatus    # ($farm_name,$backend,$service)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $backend, $service ) = @_;

	require Tie::File;

	my $i          = -1;
	my $serv_index = &getFarmVSI( $farm_name, $service );

	tie my @contents, 'Tie::File', "$configdir\/$farm_name\_status.cfg";

	foreach my $line ( @contents )
	{
		$i++;
		if ( $line =~ /0\ ${serv_index}\ ${backend}/ )
		{
			splice @contents, $i, 1,;
			last;
		}
	}
	untie @contents;

	# decrease backend index in greater backend ids
	tie my @filelines, 'Tie::File', "$configdir\/$farm_name\_status.cfg";

	foreach my $line ( @filelines )
	{
		if ( $line =~ /0\ ${serv_index}\ (\d+) (\w+)/ )
		{
			my $backend_index = $1;
			my $status        = $2;
			if ( $backend_index > $backend )
			{
				$backend_index = $backend_index - 1;
				$line          = "-b 0 $serv_index $backend_index $status";
			}
		}
	}
	untie @filelines;
}

=begin nd
Function: setHTTPFarmBackendStatus

	For a HTTP farm, it gets each backend status from status file and set it in ly proxy daemon

Parameters:
	farmname - Farm name

Returns:
	none - .

FIXME:
	This function returns nothing, do error control

=cut

sub setHTTPFarmBackendStatus    # ($farm_name)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farm_name = shift;

	&zenlog( "Setting backends status in farm $farm_name", "info", "LSLB" );

	my $be_status_filename = "$configdir\/$farm_name\_status.cfg";

	unless ( -f $be_status_filename )
	{
		open my $fh, ">", $be_status_filename;
		close $fh;
	}

	open my $fh, "<", $be_status_filename;

	unless ( $fh )
	{
		my $msg = "Error opening $be_status_filename: $!. Aborting execution.";

		&zenlog( $msg, "error", "LSLB" );
		die $msg;
	}

	my $proxyctl = &getGlobalConfiguration( 'proxyctl' );

	while ( my $line_aux = <$fh> )
	{
		my @line = split ( "\ ", $line_aux );
		&logAndRun(
			"$proxyctl -c /tmp/$farm_name\_proxy.socket $line[0] $line[1] $line[2] $line[3]"
		);
	}
	close $fh;
}

=begin nd
Function: setHTTPFarmBackendsSessionsRemove

	Remove all the active sessions enabled to a backend in a given service
	Used by farmguardian

Parameters:
	farmname - Farm name
	service - Service name
	backend - Backend id

Returns:
	Integer - Error code: It returns 0 on success or another value if it fails deleting some sessions

FIXME:

=cut

sub setHTTPFarmBackendsSessionsRemove    #($farm_name,$service,$backendid)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $service, $backendid ) = @_;

	my $serviceid;
	my $proxy_ng = &getGlobalConfiguration( 'proxy_ng' );
	my $err      = 0;

	&zenlog(
		"Deleting established sessions to a backend $backendid from farm $farm_name in service $service",
		"info", "LSLB"
	);

	$serviceid = &getFarmVSI( $farm_name, $service );
	if ( $proxy_ng eq "true" )
	{
		require Skudonet::Farm::HTTP::Action;
		$err = &sendL7ZproxyCmd(
								 {
								   farm   => $farm_name,
								   uri    => "listener/0/services/$serviceid/session",
								   method => "DELETE",
								   body   => '{ "backend-id":$backendid }',
								 }
		);
	}
	elsif ( $proxy_ng eq "false" )
	{
		my $proxyctl = &getGlobalConfiguration( 'proxyctl' );
		my $cmd =
		  "$proxyctl -c /tmp/$farm_name\_proxy.socket -f 0 $serviceid $backendid";
		$err = &logAndRun( $cmd );
	}

	return $err;
}

sub getHTTPFarmBackendAvailableID
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farmname = shift;
	my $service  = shift;

	require Skudonet::Farm::HTTP::Service;

	# get an ID for the new backend
	my $backendsvs = &getHTTPFarmVS( $farmname, $service, "backends" );
	my @be         = split ( "\n", $backendsvs );
	my $id;

	foreach my $subl ( @be )
	{
		my @subbe = split ( ' ', $subl );
		$id = $subbe[1] + 1;
	}

	$id = 0 if $id eq '';

	return $id;
}

=begin nd
Function: getHTTPFarmBackendsStatusInfo

	This function take data from proxy and it gives hash format

Parameters:
	farmname - Farm name

Returns:
	hash ref - hash with backends farm status

		services =>
		[
			"id" => $service_id,				 # it is the index in the backend array too
			"name" => $service_name,
			"backends" =>
			[
				{
					"id" = $backend_id		# it is the index in the backend array too
					"ip" = $backend_ip
					"port" = $backend_port
					"status" = $backend_status
					"service" = $service_name
				}
			]
		]

=cut

sub getHTTPFarmBackendsStatusInfo    # ($farm_name)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name ) = @_;

	require Skudonet::Farm::Base;
	require Skudonet::Farm::HTTP::Backend;
	require Skudonet::Validate;
	my $status;

	my $serviceName;
	my $service_re = &getValidFormat( 'service' );
	my $fqdn_re    = &getValidFormat( 'fqdn' );

	# Get l7 proxy info
	#i.e. of proxyctl:

	#Requests in queue: 0
	#0. http Listener 185.76.64.223:80 a
	#0. Service "HTTP" active (4)
	#0. Backend 172.16.110.13:80 active (1 0.780 sec) alive (61)
	#1. Backend (bakend.test)172.16.110.14:80 active (1 0.878 sec) alive (90)
	#2. Backend 172.16.110.11:80 active (1 0.852 sec) alive (99)
	#3. Backend 172.16.110.12:80 active (1 0.826 sec) alive (75)
	my @proxyctl = &getHTTPFarmBackendStatusCtl( $farm_name );

	# Parse l7 proxy info
	foreach my $line ( @proxyctl )
	{
		# i.e.
		#     0. Service "HTTP" active (10)
		if ( $line =~ /(\d+)\. Service "($service_re)"/ )
		{
			$serviceName = $2;
		}

	   # Parse backend connections
	   # i.e.
	   #      0. Backend (backend.test)192.168.100.254:80 active (5 0.000 sec) alive (0)
	   #      1. Backend 192.168.100.253:80 active (5 0.000 sec) alive (0)
		if ( $line =~
			/(\d+)\. Backend (?:\(($fqdn_re)\))?(\d+\.\d+\.\d+\.\d+|[a-fA-F0-9:]+):(\d+) (\w+) .+ (\w+)(?: \((\d+)\))?/
		  )
		{
			my $backendHash = {
								id     => $1 + 0,
								ip     => $2 ? $2 : $3,
								port   => $4 + 0,
								status => $6,
			};

			# Getting real status
			my $backend_disabled = $5;
			if ( $backend_disabled eq "DISABLED" )
			{
				require Skudonet::Farm::HTTP::Backend;

				#Checkstatusfile
				$backendHash->{ "status" } =
				  &getHTTPBackendStatusFromFile( $farm_name, $backendHash->{ id },
												 $serviceName );

				# not show fgDOWN status
				$backendHash->{ "status" } = "down"
				  if ( $backendHash->{ "status" } ne "maintenance" );
			}
			elsif ( $backendHash->{ "status" } eq "alive" )
			{
				$backendHash->{ "status" } = "up";
			}
			elsif ( $backendHash->{ "status" } eq "DEAD" )
			{
				$backendHash->{ "status" } = "down";
			}

			push ( @{ $status->{ $serviceName }->{ backends } }, $backendHash );
		}
	}

	return $status;
}

1;
