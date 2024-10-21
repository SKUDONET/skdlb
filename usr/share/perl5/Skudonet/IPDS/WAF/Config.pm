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
use Skudonet::Lock;
use Skudonet::IPDS::WAF::Core;
use Skudonet::IPDS::WAF::Runtime;
use Skudonet::IPDS::WAF::Parser;

my $mark_conf_begin = "## begin conf";
my $mark_conf_end   = "## end conf";


=begin nd
Function: getWAFSetConf

	It parses a set file and returns a object with configuration. 

Parameters:
	Set name - It is the name of a WAF set rule

Returns:
	Array ref - It is a list of configuration object.

=cut

sub getWAFSetConf
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $set = shift;

	my $fh = &openlock( &getWAFSetFile( $set ), 'r' ) or return undef;
	my @conf_arr;
	my $conf_flag = 0;

	while ( my $line = <$fh> )
	{
		# get global configuration of the set
		if ( $line =~ /^$mark_conf_begin/ )
		{
			$conf_flag = 1;
			next;
		}
		if ( $conf_flag )
		{
			push @conf_arr, $line;

			# end conf
			if ( $line =~ /^$mark_conf_end/ )
			{
				last;
			}
		}

		next if ( $line =~ /^\s*$/ );    # skip blank lines
		next if ( $line =~ /^\s*#/ );    # skip commentaries
	}

	close $fh;

	my $conf = &parseWAFSetConf( \@conf_arr );

	return { configuration => $conf };
}

=begin nd
Function: setWAFSetConf

	It modifies the configuration of a WAF set.

Parameters:
	Set - It is the name of the set.
	Params - It is a hash ref with the parameters to modify. The possible parameters and theirs values are:
		audit: on, off or RelevantOnly;
		process_request_body: true or false;
		process_response_body: true or false;
		request_body_limit: a interger;
		status: on, off, DetectionOnly;
		disable_rules: it is an array of integers, each integer is a rule id;
		default_action: pass, allow, deny or redirect:url;
		default_log: true, false or blank;
		default_phase: 1-5;

Returns:
	String - Returns a message with a description about the file is bad-formed. It will return a blank string if the file is well-formed.

=cut

sub setWAFSetConf
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $setname = shift;
	my $params  = shift;

	my $struct = &getWAFSetConf( $setname );

	foreach my $key ( keys %{ $params } )
	{
		$struct->{ configuration }->{ $key } = $params->{ $key };
	}
	return &buildWAFSetByConf( $setname, $struct );
}

=begin nd
Function: deleteWAFSet

	It deletes a WAF set from the system.

Parameters:
	Set - It is the name of the set.

Returns:
	Integer - It returns 0 on success or another value on failure.

=cut

sub deleteWAFSet
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $set = shift;
	my $err = 0;

	# delete from all farms where is applied and restart them
	foreach my $farm ( &listWAFBySet( $set ) )
	{
		$err = &removeWAFSetFromFarm( $set, $farm );
		return $err if $err;
	}

	$err = unlink &getWAFSetFile( $set );


	return $err;
}

=begin nd
Function: moveWAFSet

	It moves a WAF set in the list of set linked to a farm. The set order is the same
	in which they will be executed.

Parameters:
	Farm - It is farm name.
	Set - It is the name of the set.
	Position - It is the desired position for the set

Returns:
	Integer - It returns 0 on success or another value on failure.

=cut

sub moveWAFSet
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farm     = shift;
	my $set      = shift;
	my $position = shift;
	my $err      = 0;

	require Skudonet::Farm::Core;

	my $farm_file = &getFarmFile( $farm );
	my $configdir = &getGlobalConfiguration( 'configdir' );

	# write conf
	my $lock_file = &getLockFile( $farm );
	my $lock_fh = &openlock( $lock_file, 'w' );

	require Tie::File;
	tie my @filefarmhttp, 'Tie::File', "$configdir/$farm_file";

	# get line where waf rules begins
	my $waf_ind = -1;
	foreach my $line ( @filefarmhttp )
	{
		$waf_ind++;
		last if ( $line =~ /^[\s#]*WafRules/ );
	}

	# get set id
	my $set_ind   = -1;
	my @sets_list = &listWAFByFarm( $farm );
	foreach my $line ( @sets_list )
	{
		$set_ind++;
		last if ( $line =~ /^$set$/ );
	}

	require Skudonet::Arrays;
	&moveByIndex( \@filefarmhttp, $waf_ind + $set_ind, $waf_ind + $position );

	untie @filefarmhttp;
	close $lock_fh;

		# reload farm
		require Skudonet::Farm::Base;
		if ( &getFarmStatus( $farm ) eq 'up' )
		{
			require Skudonet::IPDS::WAF::Runtime;
			$err = &reloadWAFByFarm( $farm );
		}

	return $err;
}

1;

