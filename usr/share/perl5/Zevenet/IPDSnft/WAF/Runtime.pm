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
use Zevenet::Core;
use Zevenet::Lock;

include 'Zevenet::IPDS::WAF::Core';

=begin nd
Function: reloadWAFByFarm

	It reloads a farm to update the WAF configuration.

Parameters:
	Farm - It is the farm name

Returns:
	Integer - It returns 0 on success or another value on failure.

=cut

sub reloadWAFByFarm
{
	my $farm = shift;
	my $err  = 0;
	require Zevenet::Farm::HTTP::Config;

	my $pound_ctl = &getGlobalConfiguration( 'poundctl' );
	my $socket    = getHTTPFarmSocket( $farm );
	my $set_file;

	# check set
	foreach my $set ( &listWAFByFarm( $farm ) )
	{
		include 'Zevenet::IPDS::WAF::Parser';
		$set_file = &getWAFSetFile( $set );
		return 1 if ( &checkWAFFileSyntax( $set_file ) );
	}

	$err = &logAndRun( "$pound_ctl -c $socket -R" );

	return $err;
}

=begin nd
Function: addWAFsetToFarm

	It applies a WAF set to a HTTP farm.

Parameters:
	Farm - It is the farm name
	Set  - It is the WAF set name

Returns:
	Integer - It returns 0 on success or another value on failure.

=cut

sub addWAFsetToFarm
{
	my $farm = shift;
	my $set  = shift;
	my $err  = 1;

	require Zevenet::Farm::Core;

	my $set_file  = &getWAFSetFile( $set );
	my $farm_file = &getFarmFile( $farm );
	my $configdir = &getGlobalConfiguration( 'configdir' );

	# write conf
	my $lock_file = &getLockFile( $farm );
	my $lock_fh   = &openlock( $lock_file, 'w' );
	my $flag_sets = 0;

	require Tie::File;
	tie my @filefarmhttp, 'Tie::File', "$configdir/$farm_file";

	foreach my $line ( @filefarmhttp )
	{
		if ( $line =~ /^WafRules/ )
		{
			$flag_sets = 1;
		}
		elsif ( $line !~ /^WafRules/ and $flag_sets )
		{
			$err  = 0;
			$line = "WafRules	\"$set_file\"" . "\n" . $line;
			last;
		}

		# not found any waf directive
		elsif ( $line =~ /^\s*$/ )
		{
			$err  = 0;
			$line = "WafRules	\"$set_file\"" . "\n" . "\n";
			last;
		}
		elsif ( $line =~ /#HTTP\(S\) LISTENERS/ )
		{
			$err  = 0;
			$line = "WafRules	\"$set_file\"" . "\n" . $line;
			last;
		}
	}

	untie @filefarmhttp;
	close $lock_fh;

	# reload farm
	require Zevenet::Farm::Base;
	if ( &getFarmStatus( $farm ) eq 'up' and !$err )
	{
		$err = &reloadWAFByFarm( $farm );
	}

	return $err;
}

=begin nd
Function: removeWAFSetFromFarm

	It removes a WAF set from a HTTP farm.

Parameters:
	Farm - It is the farm name
	Set  - It is the WAF set name

Returns:
	Integer - It returns 0 on success or another value on failure.

=cut

sub removeWAFSetFromFarm
{
	my $farm = shift;
	my $set  = shift;
	my $err  = 0;

	require Zevenet::Farm::Core;

	my $set_file  = &getWAFSetFile( $set );
	my $farm_file = &getFarmFile( $farm );
	my $configdir = &getGlobalConfiguration( 'configdir' );

	# write conf
	$err = 1;
	&ztielock( \my @fileconf, "$configdir/$farm_file" );

	my $index = 0;
	foreach my $line ( @fileconf )
	{
		if ( $line =~ /^WafRules\s+\"$set_file\"/ )
		{
			$err = 0;
			splice @fileconf, $index, 1;
			last;
		}
		$index++;
	}
	untie @fileconf;

	# reload farm
	require Zevenet::Farm::Base;
	if ( &getFarmStatus( $farm ) eq 'up' and !$err )
	{
		$err = &reloadWAFByFarm( $farm );
	}

	return $err;
}

=begin nd
Function: reloadWAFByRule

	It reloads all farms where the WAF set is applied

Parameters:
	Set  - It is the WAF set name

Returns:
	Integer - It returns 0 on success or another value on failure.

=cut

sub reloadWAFByRule
{
	my $set = shift;
	my $err;

	require Zevenet::Farm::Base;
	foreach my $farm ( &listWAFBySet( $set ) )
	{
		if ( &getFarmStatus( $farm ) eq 'up' )
		{
			if ( &reloadWAFByFarm( $farm ) )
			{
				$err++;
				&zenlog( "Error reloading the WAF in the farm $farm", "error", "waf" );
			}
		}
	}
	return $err;
}

# ???? add function to change wafbodysize. It is needed to restart
#~ my $bodysize = &getGlobalConfiguration( 'waf_body_size' );
#~ ... tener en cuenta que debe borrarse o comentarse la directiva si en
#~ globalconf esta vacia ... cambiar este parametro en el reload de la granja
#~ . Si cambia ... pedir un restart

1;
