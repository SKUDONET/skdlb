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

use Skudonet::Config;
use Skudonet::Nft;

my $configdir = &getGlobalConfiguration( 'configdir' );


=begin nd
Function: setL4FarmServer

	Edit a backend or add a new one if the id is not found

Parameters:
	farmname - Farm name
	id - Backend id
	rip - Backend IP
	port - Backend port
	weight - Backend weight. The backend with more weight will manage more connections
	priority - The priority of this backend (between 1 and 9). Higher priority backends will be used more often than lower priority ones
	maxconn - Maximum connections for the given backend

Returns:
	Integer - return 0 on success, -1 on NFTLB failure or -2 on IP duplicated.

Returns:
	Scalar - 0 on success or other value on failure
	FIXME: Stop returning -2 when IP duplicated, nftlb should do this
=cut

sub setL4FarmServer
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $ids, $ip, $port, $weight, $priority, $max_conns ) = @_;

	require Skudonet::Farm::L4xNAT::Config;
	require Skudonet::Farm::L4xNAT::Action;
	require Skudonet::Farm::Backend;
	require Skudonet::Netfilter;

	my $farm_filename = &getFarmFile( $farm_name );
	my $output        = 0;
	my $json          = qq();
	my $msg           = "setL4FarmServer << farm_name:$farm_name ids:$ids ";

	# load the configuration file first if the farm is down
	my $f_ref = &getL4FarmStruct( $farm_name );
	if ( $f_ref->{ status } ne "up" )
	{
		my $out = &loadL4FarmNlb( $farm_name );
		return $out if ( $out != 0 );
	}

	my $exists = &getFarmServer( $f_ref->{ servers }, $ids );

	my $rip  = $ip;
	my $mark = "0x0";

	if ( defined $port && $port ne "" )
	{
		if ( &ipversion( $ip ) == 4 )
		{
			$rip = "$ip\:$port";
		}
		elsif ( &ipversion( $ip ) == 6 )
		{
			$rip = "[$ip]\:$port";
		}

		if ( !defined $exists || ( defined $exists && $exists->{ port } ne $port ) )
		{
			$json .= qq(, "port" : "$port");
			$msg  .= "port:$port ";
		}
	}
	elsif ( defined $port && $port eq "" )
	{
		$json .= qq(, "port" : "$port");
		$msg  .= "port:$port ";
	}

	if (   defined $ip
		&& $ip ne ""
		&& ( !defined $exists || ( defined $exists && $exists->{ rip } ne $rip ) ) )
	{
		my $existrip = &getFarmServer( $f_ref->{ servers }, $rip, "rip" );
		return -2 if ( defined $existrip && ( $existrip->{ id } ne $ids ) );
		$json = qq(, "ip-addr" : "$ip") . $json;
		$msg .= "ip:$ip ";

		if ( !defined $exists )
		{
			$mark = &getNewMark( $farm_name );
			return -1 if ( !defined $mark || $mark eq "" );
			$json .= qq(, "mark" : "$mark");
			$msg  .= "mark:$mark ";
		}
		else
		{
			$mark = $exists->{ tag };
		}

		&setBackendRule( "add", $f_ref, $mark ) if ( $f_ref->{ status } eq "up" );

	}

	if (
		   defined $weight
		&& $weight ne ""
		&& ( !defined $exists || ( defined $exists && $exists->{ weight } ne $weight ) )
	  )
	{
		$weight = 1 if ( $weight == 0 );
		$json .= qq(, "weight" : "$weight");
		$msg  .= "weight:$weight ";
	}

	if (
			defined $priority
		 && $priority ne ""
		 && ( !defined $exists
			  || ( defined $exists && $exists->{ priority } ne $priority ) )
	  )
	{
		$priority = 1 if ( $priority == 0 );
		$json .= qq(, "priority" : "$priority");
		$msg  .= "priority:$priority ";
	}

	if (
			defined $max_conns
		 && $max_conns ne ""
		 && ( !defined $exists
			  || ( defined $exists && $exists->{ max_conns } ne $max_conns ) )
	  )
	{
		$max_conns = 0 if ( $max_conns < 0 );
		$json .= qq(, "est-connlimit" : "$max_conns");
		$msg  .= "maxconns:$max_conns ";
	}

	if ( !defined $exists )
	{
		$json .= qq(, "state" : "up");
		$msg  .= "state:up ";
	}

	&zenlog( "$msg" ) if &debug;

	$output = &sendL4NlbCmd(
		{
		   farm   => $farm_name,
		   file   => "$configdir/$farm_filename",
		   method => "PUT",
		   body   =>
			 qq({"farms" : [ { "name" : "$farm_name", "backends" : [ { "name" : "bck$ids"$json } ] } ] })
		}
	);


	return $output;
}

=begin nd
Function: runL4FarmServerDelete

	Delete a backend from a l4 farm

Parameters:
	backend - Backend id
	farmname - Farm name

Returns:
	Scalar - 0 on success or other value on failure

=cut

sub runL4FarmServerDelete
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $ids, $farm_name ) = @_;

	require Skudonet::Farm::L4xNAT::Config;
	require Skudonet::Farm::L4xNAT::Action;
	require Skudonet::Netfilter;

	my $farm_filename = &getFarmFile( $farm_name );
	my $output        = 0;
	my $mark          = "0x0";

	# load the configuration file first if the farm is down
	my $f_ref = &getL4FarmStruct( $farm_name );

	$output = &sendL4NlbCmd(
							 {
							   farm    => $farm_name,
							   backend => "bck" . $ids,
							   file    => "$configdir/$farm_filename",
							   method  => "DELETE",
							 }
	);

	my $backend;
	foreach my $server ( @{ $f_ref->{ servers } } )
	{
		if ( $server->{ id } eq $ids )
		{
			$mark    = $server->{ tag };
			$backend = $server;
			last;
		}
	}

	### Flush conntrack
	&resetL4FarmBackendConntrackMark( $backend );

	&setBackendRule( "del", $f_ref, $mark );
	&delMarks( "", $mark );

	return $output;
}

=begin nd
Function: setL4FarmBackendsSessionsRemove

	Remove all the active sessions enabled to a backend

Parameters:
	farmname - Farm name
	backend_id - Backend id

Returns:
	Integer - 0 on success or -1 on failure

=cut

sub setL4FarmBackendsSessionsRemove
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farmname, $backend_id ) = @_;
	my $output  = 0;
	my $nft_bin = &getGlobalConfiguration( 'nft_bin' );

	require Skudonet::Farm::L4xNAT::Config;
	my $farm = &getL4FarmStruct( $farmname );

	my $be;
	foreach my $server ( @{ $farm->{ servers } } )
	{
		if ( defined $backend_id )
		{
			if ( $server->{ id } == $backend_id )
			{
				$be = $server;
				last;
			}
		}
	}

	if ( not defined $be )
	{
		&zenlog(
			"Warning removing sessions for backend id '$backend_id' in farm '$farmname': Backend id not found",
			"warning", "lslb"
		);
		return $output;
	}

	( my $tag = $be->{ tag } ) =~ s/0x//g;

	my $table = "ip";
	my $mac   = "";
	if ( $farm->{ mode } eq "dsr" )
	{
		$table = "netdev";
		my $ip_bin = &getGlobalConfiguration( 'ip_bin' );
		$mac = &logAndRun( "$ip_bin neigh show $be->{ ip }" );
		my @mac_split = split ( ' ', $mac );
		$mac = $mac_split[4];
	}
	else
	{
		require Skudonet::Net::Validate;
		if ( &ipversion( $farm->{ vip } ) == 6 )
		{
			$table .= "6";
		}
	}

	my $map_name = "persist-$farmname";
	my @persistmap =
	  @{ &logAndGet( "$nft_bin list map $table nftlb $map_name", "array" ) };
	my $data = 0;

	my $n_sessions_deleted;
	foreach my $line ( @persistmap )
	{

		$data = 1 if ( $line =~ /elements = / );
		next      if ( !$data );

		#default table ip
		my ( $key, $time, $value ) =
		  ( $line =~ / ([\w\.\s\:]+) expires (\w+) : (\w+)[\s,]/ );
		if ( $value =~ /^0x.0*$tag/ )
		{
			if (
				 &logAndRun(
							 "/usr/local/sbin/nft delete element $table nftlb $map_name { $key }"
				 ) == 0
			  )
			{
				$n_sessions_deleted++;
			}
		}

		( $key, $time, $value ) =
		  ( $line =~ /, ([\w\.\s\:]+) expires (\w+) : (\w+)[\s,]/ );
		if ( $value ne "" && $value =~ /^0x.0*$tag/ )
		{
			if (
				 &logAndRun(
							 "/usr/local/sbin/nft delete element $table nftlb $map_name { $key }"
				 ) == 0
			  )
			{
				$n_sessions_deleted++;
			}
		}

		if ( $table eq "netdev" )
		{

			( $key, $time, $value ) =
			  ( $line =~ / ([\w\.\s\:]+) expires (\w+) : ([a-fA-F0-9:]{1,})[\s,]/ );
			if ( $value eq $mac )
			{
				if (
					 &logAndRun(
								 "/usr/local/sbin/nft delete element $table nftlb $map_name { $key }"
					 ) == 0
				  )
				{
					$n_sessions_deleted++;
				}
			}

			( $key, $time, $value ) =
			  ( $line =~ /, ([\w\.\s\:]+) expires (\w+) : ([a-fA-F0-9:]{1,})[\s,]/ );
			if ( $value ne "" && $value eq $mac )
			{
				if (
					 &logAndRun(
								 "/usr/local/sbin/nft delete element $table nftlb $map_name { $key }"
					 ) == 0
				  )
				{
					$n_sessions_deleted++;
				}
			}
		}

		last if ( $data && $line =~ /\}/ );

	}

	if ( defined $n_sessions_deleted )
	{
		&zenlog(
			"Removing '$n_sessions_deleted' sessions for backend id '$backend_id' in farm '$farmname'",
			"info", "lslb"
		);
	}

	return $output;
}

=begin nd
Function: setL4FarmBackendStatus

	Set backend status for a l4 farm

Parameters:
	farmname - Farm name
	backend - Backend id
	status - Backend status. The possible values are: "up" or "down"
	cutmode - cut to force the traffic stop for such backend
	priority - true / false, if true then only sessions and conntrack inputs are deleted, current backend need to release connections because higher priority has been enabled.

Returns:
	Integer - 0 on success or other value on failure

=cut

sub setL4FarmBackendStatus
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $backend, $status, $cutmode, $prio ) = @_;

	require Skudonet::Farm::L4xNAT::Config;
	require Skudonet::Farm::L4xNAT::Action;

	my $output        = 0;
	my $farm          = &getL4FarmStruct( $farm_name );
	my $farm_filename = $farm->{ filename };

	$status = 'off'  if ( $status eq "maintenance" );
	$status = 'down' if ( $status eq "fgDOWN" );

#prio flag is used to delete only information of other servers before to run the most priority already alive
	if ( not defined $prio )
	{
		$output =
		  &sendL4NlbCmd(
			{
			   farm   => $farm_name,
			   file   => "$configdir/$farm_filename",
			   method => "PUT",
			   body   =>
				 qq({"farms" : [ { "name" : "$farm_name", "backends" : [ { "name" : "bck$backend", "state" : "$status" } ] } ] })
			}
		  );

	}

	#if ( $status ne "up" && $cutmode eq "cut" && $farm->{ persist } ne '' )
	if (    ( $status ne "up" && $cutmode eq "cut" )
		 || ( defined $prio && $prio eq 'true' ) )
	{

		if ( $farm->{ persist } ne '' )
		{
			#delete backend session
			&setL4FarmBackendsSessionsRemove( $farm_name, $backend );
		}

		my $server;

		# get backend with id $backend
		foreach my $srv ( @{ $$farm{ servers } } )
		{
			if ( $srv->{ 'id' } == $backend )
			{
				$server = $srv;
				last;
			}
		}

		# remove conntrack
		&resetL4FarmBackendConntrackMark( $server );

		if ( $farm->{ persist } ne '' )
		{
			# delete backend session again in case new connections are created
			&setL4FarmBackendsSessionsRemove( $farm_name, $backend );
		}
	}

	#~ TODO
	#~ my $stopping_fg = ( $caller =~ /runFarmGuardianStop/ );
	#~ if ( $fg_enabled eq 'true' && !$stopping_fg )
	#~ {
	#~ if ( $0 !~ /farmguardian/ && $fg_pid > 0 )
	#~ {
	#~ kill 'CONT' => $fg_pid;
	#~ }
	#~ }

	if ( $farm->{ lbalg } eq 'leastconn' )
	{
		require Skudonet::Farm::L4xNAT::L4sd;
		&sendL4sdSignal();
	}

	return $output;
}

=begin nd
Function: getL4FarmServers

	 Get all backends and their configuration

Parameters:
	farmname - Farm name

Returns:
	Array - array of hash refs of backend struct

=cut

sub getL4FarmServers
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farm_name = shift;

	my $farm_filename = &getFarmFile( $farm_name );

	open my $fd, '<', "$configdir/$farm_filename";
	chomp ( my @content = <$fd> );
	close $fd;

	return &_getL4FarmParseServers( \@content );
}

=begin nd
Function: _getL4FarmParseServers

	Return the list of backends with all data about a backend in a l4 farm

Parameters:
	config - plain text server list

Returns:
	backends array - array of backends structure
		\%backend = { $id, $alias, $family, $ip, $port, $tag, $weight, $priority, $status, $rip = $ip, $max_conns }

=cut

sub _getL4FarmParseServers
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $config = shift;
	my $stage  = 0;
	my $server;
	my @servers;

	require Skudonet::Farm::L4xNAT::Config;
	my $fproto = &_getL4ParseFarmConfig( 'proto', undef, $config );

	foreach my $line ( @{ $config } )
	{
		if ( $line =~ /\"farms\"/ )
		{
			$stage = 1;
		}

		# do not go to the next level if empty
		if ( $line =~ /\"backends\"/ && $line !~ /\[\],/ )
		{
			$stage = 2;
		}

		if ( $stage == 2 && $line =~ /\{/ )
		{
			$stage = 3;
			undef $server;
		}

		if ( $stage == 3 && $line =~ /\}/ )
		{
			$stage = 2;
			push ( @servers, $server );
		}

		if ( $stage == 2 && $line =~ /\]/ )
		{
			last;
		}

		if ( $stage == 3 && $line =~ /\"name\"/ )
		{
			my @l     = split /"/, $line;
			my $index = $l[3];
			$index =~ s/bck//;
			$server->{ id }        = $index + 0;
			$server->{ port }      = undef;
			$server->{ tag }       = "0x0";
			$server->{ max_conns } = 0;
		}

		if ( $stage == 3 && $line =~ /\"ip-addr\"/ )
		{
			my @l = split /"/, $line;
			$server->{ ip }  = $l[3];
			$server->{ rip } = $l[3];
		}

		if ( $stage == 3 && $line =~ /\"source-addr\"/ )
		{
			my @l = split /"/, $line;
			$server->{ sourceip } = $l[3];
		}

		if ( $stage == 3 && $line =~ /\"port\"/ )
		{
			my @l = split /"/, $line;
			$server->{ port } = $l[3];

			require Skudonet::Net::Validate;
			if ( $server->{ port } ne '' && $fproto ne 'all' )
			{
				if ( &ipversion( $server->{ rip } ) == 4 )
				{
					$server->{ rip } = "$server->{ip}\:$server->{port}";
				}
				elsif ( &ipversion( $server->{ rip } ) == 6 )
				{
					$server->{ rip } = "[$server->{ip}]\:$server->{port}";
				}
			}
		}

		if ( $stage == 3 && $line =~ /\"weight\"/ )
		{
			my @l = split /"/, $line;
			$server->{ weight } = $l[3] + 0;
		}

		if ( $stage == 3 && $line =~ /\"priority\"/ )
		{
			my @l = split /"/, $line;
			$server->{ priority } = $l[3] + 0;
		}

		if ( $stage == 3 && $line =~ /\"mark\"/ )
		{
			my @l = split /"/, $line;
			$server->{ tag } = $l[3];
		}

		if ( $stage == 3 && $line =~ /\"est-connlimit\"/ )
		{
			my @l = split /"/, $line;
			$server->{ max_conns } = $l[3] + 0;
		}

		if ( $stage == 3 && $line =~ /\"state\"/ )
		{
			my @l = split /"/, $line;
			$server->{ status } = $l[3];
			$server->{ status } = "undefined" if ( $server->{ status } eq "config_error" );
			$server->{ status } = "maintenance" if ( $server->{ status } eq "off" );
			$server->{ status } = "fgDOWN"      if ( $server->{ status } eq "down" );
			$server->{ status } = "up"          if ( $server->{ status } eq "available" );
		}
	}

	return \@servers;
}

=begin nd
Function: getL4ServerWithLowestPriority

	Look for backend with the lowest priority

Parameters:
	farm - Farm hash ref. It is a hash with all information about the farm

Returns:
	hash ref - reference to the selected server for prio algorithm

=cut

sub getL4ServerWithLowestPriority
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farm = shift;

	my $prio_server;

	foreach my $server ( @{ $$farm{ servers } } )
	{
		if ( $$server{ status } eq 'up' )
		{
			# find the lowest priority server
			$prio_server = $server if not defined $prio_server;
			$prio_server = $server if $$prio_server{ priority } > $$server{ priority };
		}
	}

	return $prio_server;
}

=begin nd
Function: getL4BackendsWeightProbability

	Get probability for every backend

Parameters:
	farm - Farm hash ref. It is a hash with all information about the farm

Returns:
	none - .

=cut

sub getL4BackendsWeightProbability
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farm = shift;

	my $weight_sum = 0;

	&doL4FarmProbability( $farm );

	foreach my $server ( @{ $$farm{ servers } } )
	{
		# only calculate probability for the servers running
		if ( $$server{ status } eq 'up' )
		{
			$weight_sum += $$server{ weight };
			$$server{ prob } = $weight_sum / $$farm{ prob };
		}
		else
		{
			$$server{ prob } = 0;
		}
	}
}

=begin nd
Function: getL4BackendsWeightProbability

	Reset Connection tracking for a given backend

Parameters:
	server - Backend hash reference. It uses the backend unique mark in order to deletes the conntrack entries.

Returns:
	scalar - 0 if deleted, 1 if not found or not deleted

=cut

sub resetL4FarmBackendConntrackMark
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $server = shift;

	my $conntrack = &getGlobalConfiguration( 'conntrack' );
	my $cmd       = "$conntrack -D -m $server->{ tag }/0x7fffffff";

	&zenlog( "running: $cmd" ) if &debug();

	# return_code = 0 -> deleted
	# return_code = 1 -> not found/deleted
	my $return_code = &logAndRunCheck( "$cmd" );

	if ( &debug() )
	{
		if ( $return_code )
		{
			&zenlog( "Connection tracking for " . $server->{ ip } . " not found." );
		}
		else
		{
			&zenlog( "Connection tracking for " . $server->{ ip } . " removed." );
		}
	}

	return $return_code;
}

=begin nd
Function: getL4FarmBackendAvailableID

	Get next available backend ID

Parameters:
	farmname - farm name

Returns:
	integer - .

=cut

sub getL4FarmBackendAvailableID
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farmname = shift;

	require Skudonet::Farm::Backend;

	my $backends  = &getL4FarmServers( $farmname );
	my $nbackends = $#{ $backends } + 1;

	for ( my $id = 0 ; $id < $nbackends ; $id++ )
	{
		my $exists = &getFarmServer( $backends, $id );
		return $id if ( !$exists );
	}

	return $nbackends;
}

=begin nd
Function: getL4ServerByMark

	Obtain the backend id from the mark

Parameters:
	servers_ref - reference to the servers array
	mark - backend mark to discover the id

Returns:
	integer - > 0 if successful, -1 if error.

=cut

sub getL4ServerByMark
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $servers_ref = shift;
	my $mark        = shift;

	( my $tag = $mark ) =~ s/0x.0*/0x/g;

	foreach my $server ( @{ $servers_ref } )
	{
		if ( $server->{ tag } eq $tag )
		{
			return $server->{ id };
		}
	}

	return -1;
}

=begin nd
Function: getL4FarmPriorities

	Get the list of the backends priorities in a L4 farm

Parameters:
	farmname - Farm name

Returns:
	Array Ref - it returns an array ref of priority values

=cut

sub getL4FarmPriorities    # ( $farmname )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farmname ) = shift;
	my @priorities;
	my $backends = &getL4FarmServers( $farmname );
	foreach my $backend ( @{ $backends } )
	{
		if ( defined $backend->{ priority } )
		{
			push @priorities, $backend->{ priority };
		}
		else
		{
			push @priorities, 1;
		}

	}
	return \@priorities;
}

1;

