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
use Skudonet::Config;


my $configdir = &getGlobalConfiguration( 'configdir' );

=begin nd
Function: _runFarmStart

	Run a farm

Parameters:
	farm_name - Farm name
	writeconf - write this change in configuration status "writeconf" for true or omit it for false

Returns:
	Integer - return 0 on success, 2 if the ip:port is busy for another farm or another value on another failure

=cut

sub _runFarmStart    # ($farm_name, $writeconf)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $writeconf ) = @_;

	# The parameter expect "undef" to not write it
	$writeconf = undef if ( $writeconf eq 'false' );

	require Skudonet::Farm::Base;
	require Skudonet::Farm::Config;

	my $status = -1;

	# finish the function if the farm is already up
	if ( &getFarmStatus( $farm_name ) eq "up" )
	{
		zenlog( "Farm $farm_name already up", "info", "FARMS" );
		return 0;
	}

	# check if the ip exists in any interface
	my $ip = &getFarmVip( "vip", $farm_name );
	require Skudonet::Net::Interface;
	if ( !&getIpAddressExists( $ip ) )
	{
		&zenlog( "The virtual interface $ip is not defined in any interface." );
		return $status;
	}

	require Skudonet::Net::Interface;
	my $farm_type = &getFarmType( $farm_name );
	if ( $farm_type ne "datalink" )
	{
		my $port = &getFarmVip( "vipp", $farm_name );
		if ( !&validatePort( $ip, $port, undef, $farm_name ) )
		{
			&zenlog( "The networking '$ip:$port' is being used." );
			return 2;
		}
	}

	&zenlog( "Starting farm $farm_name with type $farm_type", "info", "FARMS" );

	if ( $farm_type eq "http" || $farm_type eq "https" )
	{
		require Skudonet::Farm::HTTP::Action;
		$status = &_runHTTPFarmStart( $farm_name, $writeconf );
	}
	elsif ( $farm_type eq "datalink" )
	{
		require Skudonet::Farm::Datalink::Action;
		$status = &_runDatalinkFarmStart( $farm_name, $writeconf );
	}
	elsif ( $farm_type eq "l4xnat" )
	{
		require Skudonet::Farm::L4xNAT::Action;
		$status = &startL4Farm( $farm_name, $writeconf );
	}

	&setFarmNoRestart( $farm_name );

	return $status;
}

=begin nd
Function: runFarmStart

	Run a farm completely a farm. Run farm, its farmguardian, ipds rules and ssyncd

Parameters:
	farm_name - Farm name
	writeconf - write this change in configuration status "writeconf" for true or omit it for false

Returns:
	Integer - return 0 on success, 2 if the ip:port is busy for another farm or another value on another failure

NOTE:
	Generic function

=cut

sub runFarmStart    # ($farm_name, $writeconf)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $writeconf ) = @_;

	my $status = &_runFarmStart( $farm_name, $writeconf );

	return $status if ( $status != 0 );

	require Skudonet::FarmGuardian;
	&runFarmGuardianStart( $farm_name, "" );

	return $status;
}

=begin nd
Function: runFarmStop

	Stop a farm completely a farm. Stop the farm, its farmguardian, ipds rules and ssyncd

Parameters:
	farm_name - Farm name
	writeconf - write this change in configuration status "writeconf" for true or omit it for false

Returns:
	Integer - return 0 on success or different of 0 on failure

NOTE:
	Generic function

=cut

sub runFarmStop    # ($farm_name, $writeconf)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $writeconf ) = @_;


	require Skudonet::FarmGuardian;
	&runFGFarmStop( $farm_name );

	my $status = &_runFarmStop( $farm_name, $writeconf );

	return $status;
}

=begin nd
Function: _runFarmStop

	Stop a farm

Parameters:
	farm_name - Farm name
	writeconf - write this change in configuration status "writeconf" for true or omit it for false

Returns:
	Integer - return 0 on success or different of 0 on failure

=cut

sub _runFarmStop    # ($farm_name, $writeconf)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $writeconf ) = @_;

	# The parameter expects "undef" to not write it
	$writeconf = undef if ( $writeconf eq 'false' );

	require Skudonet::Farm::Base;

	my $farm_filename = &getFarmFile( $farm_name );
	if ( $farm_filename eq '-1' )
	{
		return -1;
	}

	my $farm_type = &getFarmType( $farm_name );
	my $status    = $farm_type;

	&zenlog( "Stopping farm $farm_name with type $farm_type", "info", "FARMS" );

	if ( $farm_type =~ /http/ )
	{
		require Skudonet::Farm::HTTP::Action;
		$status = &_runHTTPFarmStop( $farm_name, $writeconf );
	}
	elsif ( $farm_type eq "datalink" )
	{
		require Skudonet::Farm::Datalink::Action;
		$status = &_runDatalinkFarmStop( $farm_name, $writeconf );
	}
	elsif ( $farm_type eq "l4xnat" )
	{
		require Skudonet::Farm::L4xNAT::Action;
		$status = &stopL4Farm( $farm_name, $writeconf );
	}

	&setFarmNoRestart( $farm_name );

	return $status;
}

=begin nd
Function: runFarmDelete

	Delete a farm

Parameters:
	farmname - Farm name

Returns:
	String - farm name

NOTE:
	Generic function

=cut

sub runFarmDelete    # ($farm_name)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farm_name = shift;

	require Skudonet::Netfilter;

	# global variables
	my $configdir = &getGlobalConfiguration( 'configdir' );


	# stop and unlink farmguardian
	require Skudonet::FarmGuardian;
	&delFGFarm( $farm_name );

	my $farm_type = &getFarmType( $farm_name );
	my $status    = 1;

	&zenlog( "running 'Delete' for $farm_name", "info", "FARMS" );

	if ( $farm_type eq "http" || $farm_type eq "https" )
	{
		unlink glob ( "$configdir/$farm_name\_*\.html" );

		# For HTTPS farms only
		my $dhfile = "$configdir\/$farm_name\_dh2048.pem";
		unlink ( "$dhfile" ) if -e "$dhfile";
		&delMarks( $farm_name, "" );

		# Check if local farm exists and delete it
		require Skudonet::Nft;
		my $output = &httpNlbRequest(
									  {
										method => "GET",
										uri    => "/farms/" . $farm_name,
										check  => 1,
									  }
		);
		$output = &httpNlbRequest(
								   {
									 farm   => $farm_name,
									 method => "DELETE",
									 uri    => "/farms/" . $farm_name,
								   }
		) if ( !$output );
	}
	elsif ( $farm_type eq "datalink" )
	{
		# delete cron task to check backends
		require Tie::File;
		tie my @filelines, 'Tie::File', "/etc/cron.d/skudonet";
		@filelines = grep !/\# \_\_$farm_name\_\_/, @filelines;
		untie @filelines;
	}
	elsif ( $farm_type eq "l4xnat" )
	{
		require Skudonet::Farm::L4xNAT::Factory;
		&runL4FarmDelete( $farm_name );
	}

	unlink glob ( "$configdir/$farm_name\_*\.cfg" );
	$status = 0
	  if ( !-f "$configdir/$farm_name\_*\.cfg" );

	require Skudonet::RRD;

	&delGraph( $farm_name, "farm" );

	return $status;
}

=begin nd
Function: runFarmReload

	Reload a farm

Parameters:
	farm_name - Farm name

Returns:
Integer - return 0 on success, another value on another failure

=cut

sub runFarmReload    # ($farm_name)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farm_name = shift;
	require Skudonet::Farm::Action;
	if ( &getFarmRestartStatus( $farm_name ) )
	{
		&zenlog( "'Reload' on $farm_name is not executed. 'Restart' is needed.",
				 "info", "FARMS" );
		return 2;
	}
	my $status = 0;

	&zenlog( "running 'Reload' for $farm_name", "info", "FARMS" );

	# Reload config daemon
	$status = &_runFarmReload( $farm_name );

	# Reload Farm status from its cfg file
	require Skudonet::Farm::HTTP::Backend;
	&setHTTPFarmBackendStatus( $farm_name );

	return $status;
}

=begin nd
Function: _runFarmReload

	It reloads a farm to update the configuration.

Parameters:
	Farm - It is the farm name

Returns:
	Integer - It returns 0 on success or another value on failure.

=cut

sub _runFarmReload    # ($farm_name)

{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farm = shift;
	my $err  = 0;

	require Skudonet::Farm::Base;
	return 0 if ( &getFarmStatus( $farm ) ne 'up' );

	require Skudonet::Farm::HTTP::Config;
	my $proxy_ctl = &getGlobalConfiguration( 'proxyctl' );
	my $socket    = &getHTTPFarmSocket( $farm );

	$err = &logAndRun( "$proxy_ctl -c $socket -R 0" );

	return $err;
}

=begin nd
Function: getFarmRestartFile

	This function returns a file name that indicates that a farm is waiting to be restarted

Parameters:
	farmname - Farm name

Returns:
	sting - path to flag file

NOTE:
	Generic function

=cut

sub getFarmRestartFile    # ($farm_name)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farm_name = shift;

	return "/tmp/_farm_need_restart_$farm_name";
}

=begin nd
Function: getFarmRestartStatus

	This function responses if a farm has pending changes waiting for restarting

Parameters:
	farmname - Farm name

Returns:
	Integer - 1 if the farm has to be restarted or 0 if it is not

NOTE:
	Generic function

=cut

sub getFarmRestartStatus
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $fname = shift;

	require Skudonet::Farm::Action;
	my $lfile = &getFarmRestartFile( $fname );

	return 1 if ( -e $lfile );
	return 0;
}

=begin nd
Function: setFarmRestart

	This function creates a file to tell that the farm needs to be restarted to apply changes

Parameters:
	farmname - Farm name

Returns:
	undef

NOTE:
	Generic function

=cut

sub setFarmRestart    # ($farm_name)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farm_name = shift;

	# do nothing if the farm is not running
	require Skudonet::Farm::Base;
	return if &getFarmStatus( $farm_name ) ne 'up';

	require Skudonet::Lock;
	my $lf = &getFarmRestartFile( $farm_name );
	my $fh = &openlock( $lf, 'w' );
	close $fh;
}

=begin nd
Function: setFarmNoRestart

	This function deletes the file marking the farm to be restarted to apply changes

Parameters:
	farmname - Farm name

Returns:
	none - .

NOTE:
	Generic function

=cut

sub setFarmNoRestart    # ($farm_name)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farm_name = shift;

	my $lf = &getFarmRestartFile( $farm_name );
	unlink ( $lf ) if -e $lf;
}

=begin nd
Function: setNewFarmName

	Function that renames a farm. Before call this function, stop the farm.

Parameters:
	farmname - Farm name
	newfarmname - New farm name

Returns:
	Integer - return 0 on success or -1 on failure

=cut

sub setNewFarmName    # ($farm_name,$new_farm_name)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $new_farm_name ) = @_;

	my $rrdap_dir = &getGlobalConfiguration( 'rrdap_dir' );
	my $rrd_dir   = &getGlobalConfiguration( 'rrd_dir' );

	my $farm_type = &getFarmType( $farm_name );
	my $output    = -1;

	my $farm_status;

	# farmguardian renaming
	require Skudonet::FarmGuardian;

	# stop farm
	&runFGFarmStop( $farm_name );

	# rename farmguardian
	&setFGFarmRename( $farm_name, $new_farm_name );

	# end of farmguardian renaming

	&zenlog( "setting 'NewFarmName $new_farm_name' for $farm_name farm $farm_type",
			 "info", "FARMS" );

	if ( $farm_type eq "http" || $farm_type eq "https" )
	{
		require Skudonet::Farm::HTTP::Action;
		$output = &copyHTTPFarm( $farm_name, $new_farm_name, 'del' );
	}
	elsif ( $farm_type eq "datalink" )
	{
		require Skudonet::Farm::Datalink::Action;
		$output = &copyDatalinkFarm( $farm_name, $new_farm_name, 'del' );
	}
	elsif ( $farm_type eq "l4xnat" )
	{
		require Skudonet::Farm::L4xNAT::Action;
		$output = &setL4NewFarmName( $farm_name, $new_farm_name );
	}

	# farmguardian renaming
	if ( $output == 0 and $farm_status eq 'up' )
	{
		&zenlog( "restarting farmguardian", 'info', 'FG' ) if &debug;
		&runFGFarmStart( $farm_name );
	}

	# end of farmguardian renaming

	# rename rrd
	rename ( "$rrdap_dir/$rrd_dir/$farm_name-farm.rrd",
			 "$rrdap_dir/$rrd_dir/$new_farm_name-farm.rrd" );


	# FIXME: farmguardian files
	# FIXME: logfiles
	return $output;
}

=begin nd
Function: copyFarm

	Function that copies the configuration file of a farm to create a new one.

Parameters:
	farmname - Farm name
	newfarmname - New farm name

Returns:
	Integer - return 0 on success or -1 on failure

=cut

sub copyFarm    # ($farm_name,$new_farm_name)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $new_farm_name ) = @_;

	my $farm_type = &getFarmType( $farm_name );
	my $output    = -1;

	&zenlog( "copying the farm '$farm_name' to '$new_farm_name'", "info", "FARMS" );

	if ( $farm_type eq "http" || $farm_type eq "https" )
	{
		require Skudonet::Farm::HTTP::Action;
		$output = &copyHTTPFarm( $farm_name, $new_farm_name );
	}
	elsif ( $farm_type eq "datalink" )
	{
		require Skudonet::Farm::Datalink::Action;
		$output = &copyDatalinkFarm( $farm_name, $new_farm_name );
	}
	elsif ( $farm_type eq "l4xnat" )
	{
		require Skudonet::Farm::L4xNAT::Action;
		$output = &copyL4Farm( $farm_name, $new_farm_name );
	}

	return $output;
}

1;

