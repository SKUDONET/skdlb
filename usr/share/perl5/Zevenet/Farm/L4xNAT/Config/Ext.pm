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

require Zevenet::Farm::L4xNAT::Config;
my $configdir = &getGlobalConfiguration( 'configdir' );

sub setL4FarmParamExt    # ($param, $value, $farm_name)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $param, $value, $farm_name ) = @_;

	require Zevenet::Farm::Core;
	my $farm_filename = &getFarmFile( $farm_name );
	my $output        = -1;
	my $srvparam      = "";

	if ( $param eq "logs" )
	{
		$srvparam = "log";
		$value    = "input" if ( $value eq "true" );
		$value    = "none" if ( $value eq "false" );
	}
	else
	{
		return -1;
	}

	# load the configuration file first if the farm is down
	my $f_ref = &getL4FarmStruct( $farm_name );
	if ( $f_ref->{ status } ne "up" )
	{
		require Zevenet::Farm::L4xNAT::Action;
		my $out = &loadNLBFarm( $farm_name );
		if ( $out != 0 )
		{
			return $out;
		}
	}

	require Zevenet::Nft;
	$output = &sendL4NlbCmd(
		{
		   farm   => $farm_name,
		   file   => ( $param ne 'status' ) ? "$configdir/$farm_filename" : undef,
		   method => "PUT",
		   uri    => "/farms",
		   body   => qq({"farms" : [ { "name" : "$farm_name", "$srvparam" : "$value" } ] })
		}
	);

	return $output;
}

sub modifyLogsParam
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farmname  = shift;
	my $logsValue = shift;

	my $msg;
	my $err = 0;
	if ( $logsValue =~ /(?:true|false)/ )
	{
		$err = &setL4FarmParamExt( 'logs', $logsValue, $farmname );
	}
	else
	{
		$msg = "Invalid value for logs parameter.";
	}

	if ( $err )
	{
		$msg = "Error modifying the parameter logs.";
	}
	return $msg;
}

1;
