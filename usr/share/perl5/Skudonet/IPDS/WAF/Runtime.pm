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
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farm = shift;
	my $err  = 0;

	require Skudonet::Farm::Base;
	return 0 if ( &getFarmStatus( $farm ) ne 'up' );

	require Skudonet::Farm::HTTP::Config;
	my $proxy_ctl = &getGlobalConfiguration( 'proxyctl' );
	my $socket    = &getHTTPFarmSocket( $farm );

	$err = &logAndRun( "$proxy_ctl -c $socket -R" );

	return $err;
}

=begin nd
Function: addWAFsetToFarm

	It adds a WAF set to a HTTP farm.

Parameters:
	Farm - It is the farm name
	Set  - It is the WAF set name
	set_status  - It is the Status. If defined, update in farm config file.

Returns:
	Hash {
		error - It returns 0 on success or another value on failure.
		message - Error message or empty.
	}

=cut

sub addWAFsetToFarm
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farm       = shift;
	my $set        = shift;
	my $set_status = shift;
	my $err        = 1;
	my $msg        = "";

	use File::Copy;
	require Skudonet::Farm::Core;

	my $set_file  = &getWAFSetFile( $set );
	my $farm_file = &getFarmFile( $farm );
	my $configdir = &getGlobalConfiguration( 'configdir' );
	my $farm_path = "$configdir/$farm_file";
	my $tmp_conf  = "/tmp/waf_$farm.tmp";
	my $proxy     = &getGlobalConfiguration( 'proxy' );
	my $cp        = &getGlobalConfiguration( 'cp' );
	my $mv        = &getGlobalConfiguration( 'mv' );

	my $lock_file = &getLockFile( $tmp_conf );
	my $lock_fh = &openlock( $lock_file, 'w' );

	$err = &logAndRun( "$cp $farm_path $tmp_conf" );
	if ( $err )
	{
		&zenlog( "The file $farm_path could not be copied", "error", "waf" );
		unlink $tmp_conf;
		close $lock_fh;
		$msg = "The file $farm_path could not be copied";
		return { error => $err, message => $msg };
	}

	use Tie::File;
	tie my @filefarmhttp, 'Tie::File', $tmp_conf;

	# write conf
	my $flag_sets = 0;
	foreach my $line ( @filefarmhttp )
	{
		if ( $line =~ /[\s#]*WafRules/ )
		{
			$flag_sets = 1;
			if ( defined $set_status )
			{
				if ( $line =~ /^([\s#]*)WafRules\s+\"\Q$set_file\E\"\s*$/ )
				{
					my $status_value = $1;

					# replace '#' by empty
					$status_value =~ s/#//;
					if ( $set_status eq "down" )
					{
						$status_value .= "#";
					}
					$line = $status_value . "WafRules	\"$set_file\"" . "\n";
					last;
				}
			}
		}
		elsif ( $line !~ /[\s#]*WafRules/ and $flag_sets )
		{
			$err = 0;
			my $status = "";
			$status = "#" if &getWAFSetStatus( $set ) eq "down";
			$line = $status . "WafRules	\"$set_file\"" . "\n" . $line;
			last;
		}

		# not found any waf directive
		elsif ( $line =~ /#HTTP\(S\) LISTENERS/ )
		{
			$err = 0;
			my $status = "";
			$status = "#" if &getWAFSetStatus( $set ) eq "down";
			$line = $status . "WafRules	\"$set_file\"" . "\n" . $line;
			last;
		}

	}
	untie @filefarmhttp;

	# check config file
	my $cmd = "$proxy -f $tmp_conf -c";
	my $status = &logRunAndGet( $cmd, "array" );

	if ( $status->{ stderr } )
	{
		unlink $tmp_conf;
		close $lock_fh;

		my @duplicated =
		  grep ( s/^.*(\d+) is duplicated.*$/$1/, @{ $status->{ stdout } } );
		$msg = "Duplicated rule_id found: @duplicated"
		  if ( scalar @duplicated > 0 );

		return { error => $status->{ stderr }, message => $msg };
	}

	require Skudonet::Farm::Base;

	# if there is not error, overwrite configfile
	$err = &logAndRun( "$mv $tmp_conf $farm_path" );
	if ( $err )
	{
		&zenlog( 'Error saving changes', 'error', "waf" );
	}
	elsif ( &getFarmStatus( $farm ) eq 'up' )
	{
		# reload farm
		$err = &reloadWAFByFarm( $farm );
	}

	# Not to need farm restart
	close $lock_fh;

	return { error => $err, message => $msg };
}

=begin nd
Function: setWAFsetToFarm

	It applies a WAF set list to an HTTP farm.

Parameters:
	farm_name - It is the farm name
	set_ref  - It is the list of WAF set names to be applied

Returns:
	Hash {
		error - It returns 0 on success or another value on failure.
		message - Error message or empty.
	}

=cut

sub setWAFsetToFarm    #( $farm_name, $set_ref )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farm_name = shift;
	my $set_ref   = shift;
	my $err       = 1;
	my $msg       = "";
	if ( ref ( $set_ref ) ne "ARRAY" )
	{
		$msg = "The set param has to be an ARRAY";
		return { error => $err, message => $msg };
	}

	use File::Copy;
	require Skudonet::Farm::Core;

	my $farm_file = &getFarmFile( $farm_name );
	my $configdir = &getGlobalConfiguration( 'configdir' );
	my $farm_path = "$configdir/$farm_file";
	my $tmp_conf  = "/tmp/waf_$farm_name.tmp";
	my $proxy     = &getGlobalConfiguration( 'proxy' );
	my $cp        = &getGlobalConfiguration( 'cp' );
	my $mv        = &getGlobalConfiguration( 'mv' );

	my $lock_file = &getLockFile( $tmp_conf );
	my $lock_fh = &openlock( $lock_file, 'w' );

	$err = &logAndRun( "$cp $farm_path $tmp_conf" );
	if ( $err )
	{
		$msg = "The file $farm_path could not be copied";
		&zenlog( $msg, "error", "waf" );
		unlink $tmp_conf;
		close $lock_fh;
		return { error => $err, message => $msg };
	}

	my $new_sets = [];
	my $line;
	my $set_status;
	foreach my $set ( @{ $set_ref } )
	{
		$set_status = &getWAFSetStatus( $set ) eq "down" ? "#" : "";
		$line .= $set_status . "WafRules	\"" . &getWAFSetFile( $set ) . "\"";
		push @{ $new_sets }, $line;
		$line = "";
	}

	use Tie::File;
	tie my @filefarmhttp, 'Tie::File', $tmp_conf;

	# write conf
	my $first_set_index = "-1";
	my $num_set         = 0;
	my $index           = 0;
	foreach my $line ( @filefarmhttp )
	{
		if ( $line =~ /[\s#]*WafRules/ )
		{
			if ( $first_set_index < 0 )
			{
				$first_set_index = $index;
			}
			$num_set++;
		}

		# not found any waf directive
		elsif ( !$num_set )
		{
			if ( $line =~ /#HTTP\(S\) LISTENERS/ )
			{
				$err             = 0;
				$first_set_index = $index - 1;
				last;
			}
		}
		$index++;

	}
	splice ( @filefarmhttp, $first_set_index, $num_set, @{ $new_sets } );
	untie @filefarmhttp;

	# check config file
	my $cmd = "$proxy -f $tmp_conf -c";
	my $status = &logRunAndGet( $cmd, "array" );

	if ( $status->{ stderr } )
	{
		unlink $tmp_conf;
		close $lock_fh;

		my @duplicated =
		  grep ( s/^.*(\d+) is duplicated.*$/$1/, @{ $status->{ stdout } } );
		$msg = "Duplicated rule_id found: @duplicated"
		  if ( scalar @duplicated > 0 );

		my @failed =
		  grep ( s/^error loading waf ruleset file (?:.*\/)+(.+).conf: .*$/$1/,
				 @{ $status->{ stdout } } );
		$msg = "Error Loading set: @failed"
		  if ( scalar @failed > 0 );

		return { error => $status->{ stderr }, message => $msg };
	}

	require Skudonet::Farm::Base;

	# if there is not error, overwrite configfile
	$err = &logAndRun( "$mv $tmp_conf $farm_path" );
	if ( $err )
	{
		&zenlog( 'Error saving changes on $farm_path"', 'error', "waf" );
	}
	elsif ( &getFarmStatus( $farm_name ) eq 'up' )
	{
		# reload farm
		$err = &reloadWAFByFarm( $farm_name );
	}

	# Not to need farm restart
	close $lock_fh;

	return { error => $err, message => $msg };
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
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farm = shift;
	my $set  = shift;
	my $err  = 0;

	require Skudonet::Farm::Core;

	my $set_file  = &getWAFSetFile( $set );
	my $farm_file = &getFarmFile( $farm );
	my $configdir = &getGlobalConfiguration( 'configdir' );
	my $farm_path = "$configdir/$farm_file";

	my $lock_file = &getLockFile( $farm );
	my $lock_fh = &openlock( $lock_file, 'w' );

	# write conf
	$err = 1;
	&ztielock( \my @fileconf, $farm_path );

	my $index = 0;
	foreach my $line ( @fileconf )
	{
		if ( $line =~ /^[\s#]*WafRules\s+\"$set_file\"/ )
		{
			$err = 0;
			splice @fileconf, $index, 1;
			last;
		}
		$index++;
	}
	untie @fileconf;

	# reload farm
	require Skudonet::Farm::Base;
	if ( &getFarmStatus( $farm ) eq 'up' and !$err )
	{
		$err = &reloadWAFByFarm( $farm );
	}

	close $lock_fh;

	# Not to need farm restart
	unlink $lock_file;

	return $err;
}

=begin nd
Function: reloadWAFByRule

	It reloads all farms where the WAF set is applied

Parameters:
	Set  - It is the WAF set name
	set_status - It is the status. Possible values "up" or "down". If defined updates farm config file.

Returns:
	Integer - It returns 0 on success or another value on failure.

=cut

sub reloadWAFByRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $set        = shift;
	my $set_status = shift;
	my $err;

	require Skudonet::Farm::Base;
	foreach my $farm ( &listWAFBySet( $set ) )
	{
		if ( defined $set_status )
		{
			# update set on farm config
			my $add_err = &addWAFsetToFarm( $farm, $set, $set_status );
			$err += $add_err->{ error };
		}
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

1;

