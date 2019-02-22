#!/usr/bin/perl
###############################################################################
#
#    Zevenet Software License
#    This file is part of the Zevenet Load Balancer software package.
#
#    Copyright (C) 2014-today ZEVENET SL, Sevilla (Spain)
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

use Zevenet::Nft;

=begin nd
Function: getNlbPid

	Return the nftlb pid

Parameters:
	none

Returns:
	Integer - PID if successful or -1 on failure

=cut

sub getNlbPid
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	my $nlbpidfile = &getNlbPidFile();
	my $nlbpid     = -1;

	if ( !-f "$nlbpidfile" )
	{
		return -1;
	}

	open my $fd, '<', "$nlbpidfile";
	$nlbpid = <$fd>;
	close $fd;

	if ( $nlbpid eq "" )
	{
		return -1;
	}

	return $nlbpid;
}

=begin nd
Function: getNlbPidFile

	Return the nftlb pid file

Parameters:
	none

Returns:
	String - Pid file path or -1 on failure

=cut

sub getNlbPidFile
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	my $piddir     = &getGlobalConfiguration( 'piddir' );
	my $nlbpidfile = "$piddir/nftlb.pid";

	return $nlbpidfile;
}

=begin nd
Function: startNlb

	Launch the nftlb daemon and create the PID file. Do
	nothing if already is launched.

Parameters:
	none

Returns:
	Integer - return PID on success or <= 0 on failure

=cut

sub startNlb
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $nftlbd     = &getGlobalConfiguration( 'zbindir' ) . "/nftlbd";
	my $pidof      = &getGlobalConfiguration( 'pidof' );
	my $nlbpidfile = &getNlbPidFile();
	my $nlbpid     = &getNlbPid();

	if ( $nlbpid eq "-1" )
	{
		&logAndRun( "$nftlbd start" );

		#required to wait at startup to ensure the process is up
		sleep 1;

		$nlbpid = `$pidof nftlb`;
		if ( $nlbpid eq "" )
		{
			return -1;
		}

		open my $fd, '>', "$nlbpidfile";
		print $fd "$nlbpid";
		close $fd;
	}

	return $nlbpid;
}

=begin nd
Function: stopNlb

	Stop the nftlb daemon. Do nothing if is already stopped.

Parameters:
	none

Returns:
	Integer - return PID on success or <= 0 on failure

=cut

sub stopNlb
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	my $nftlbd     = &getGlobalConfiguration( 'zbindir' ) . "/nftlbd";
	my $pidof      = &getGlobalConfiguration( 'pidof' );
	my $nlbpidfile = &getNlbPidFile();
	my $nlbpid     = &getNlbPid();

	if ( $nlbpid ne "-1" )
	{
		&logAndRun( "$nftlbd stop" );
	}

	return $nlbpid;
}

=begin nd
Function: httpNlbRequest

	Send an action to nftlb

Parameters:
	self - hash that includes hash_keys -> ( $file, $method, $uri, $body )

Returns:
	Integer - return code of the request command

=cut

sub httpNlbRequest
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $self     = shift;
	my $curl_cmd = `which curl`;
	my $output   = -1;
	my $body     = "";

	my $pid = &startNlb();
	if ( $pid <= 0 )
	{
		return -1;
	}

	chomp ( $curl_cmd );
	return -1 if ( $curl_cmd eq "" );

	$body = qq(-d'$self->{ body }')
	  if ( defined $self->{ body } && $self->{ body } ne "" );

	my $execmd =
	  qq($curl_cmd -s -H "Key: HoLa" -H \"Expect:\" -X "$self->{ method }" $body http://127.0.0.1:27$self->{ uri });

	if ( defined $self->{ file } && $self->{ file } ne "" )
	{
		$execmd = $execmd . " > " . $self->{ file };
	}

	$output = &logAndRun( $execmd );

	return -1 if ( $output != 0 );

	return 0;
}

1;
