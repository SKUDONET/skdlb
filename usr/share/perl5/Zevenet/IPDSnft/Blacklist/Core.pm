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

# The goal of this file is to keep the needed functions to get information about
# the blacklist process: configuration, runtime...

use strict;
use Config::Tiny;
use Zevenet::Core;
use Zevenet::Debug;

my $blacklistsPath = &getGlobalConfiguration( 'blacklistsPath' );
my $blacklistsConf = &getGlobalConfiguration( 'blacklistsConf' );

=begin nd
Function: getBLExists

	Get if a list exists o all available lists

Parameters:

	listName	-	return 0 if list exists
	no param	-	return a ref array of all available lists

Returns:

	1   - list exists
	0  - list doesn't exist
=cut

sub getBLExists
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $listName = shift;

	my $output         = 0;
	my $blacklistsConf = &getGlobalConfiguration( 'blacklistsConf' );
	my $fileHandle     = Config::Tiny->read( $blacklistsConf );

	if ( $listName )
	{
		$output = 1 if ( exists $fileHandle->{ $listName } );
	}

	return $output;
}

#  &getBLIpsetStatus ( $listName );
sub getBLIpsetStatus
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $listName = shift;
	my $output   = "down";

	$output = "up" if ( &getIPDSPolicyParam( 'name', $listName ) > 0 );

	return $output;
}

#  &getBLStatus ( $listName );
sub getBLStatus
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $listName = shift;

	my $output = &getBLParam( $listName, 'status' );
	$output = "down" if ( !$output );

	return $output;
}

# return 0 if the list has no rules applied
#  else return the number of farms that are using the list
# $lists = &getListNoUsed ();
sub getBLListNoUsed
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $listName = shift;
	my $matches  = 0;

	$matches = &getIPDSPolicyParam( 'farms', $listName );
	$matches = 0 if ( $matches < 0 );

	return $matches;
}

=begin nd
Function: getBLParam

	Get list config

Parameters:

	name	- section name
	key		- field to modificate
		- name	-> list name
		- farm	-> add or delete a asociated farm
		- url	-> modificate url ( only remote lists )
		- update_status-> modificate list status ( only remote lists )
		- list  -> modificate ip list ( only local lists )

	value	- value for the field

Returns:

	0	- successful
	!=0	- error

=cut

sub getBLParam
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $listName, $key ) = @_;

	my $output;
	my $fileHandle;

	my $blacklistsConf = &getGlobalConfiguration( 'blacklistsConf' );
	$fileHandle = Config::Tiny->read( $blacklistsConf );
	my @aux = ();

	if ( !$key )
	{
		$output               = $fileHandle->{ $listName };
		$output->{ 'name' }   = $listName;
		$output->{ 'source' } = &getBLIpList( $listName );
		@aux                  = split ( ' ', $fileHandle->{ $listName }->{ 'farms' } );
		$output->{ 'farms' }  = \@aux;
	}
	elsif ( $key eq 'source' )
	{
		$output = &getBLIpList( $listName );
	}
	elsif ( $key eq 'farms' )
	{
		my $farm_string = $fileHandle->{ $listName }->{ $key };
		if ( $fileHandle->{ $listName }->{ $key } )
		{
			@aux = split ( ' ', $farm_string );
		}
		$output = \@aux;
	}
	else
	{
		$output = $fileHandle->{ $listName }->{ $key };
	}

	return $output;
}

sub getBLlastUptdate
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $listName = shift;

	my $date;
	my $listFile = &getGlobalConfiguration( 'blacklistsPath' ) . "/$listName.txt";
	my $stat     = &getGlobalConfiguration( 'stat' );

	# only update remote lists
	return -1 if ( &getBLParam( $listName, 'type' ) eq 'local' );
	return 0 if ( !-f $listFile );

	my $outCmd = `$stat -c %y $listFile`;

	# 2016-12-22 10:21:07.000000000 -0500
	if ( $outCmd =~ /^(.+)\./ )
	{
		$date = $1;
	}
	else
	{
		$date = -2;
	}

	return $date;
}

sub getBLzapi
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $listName = shift;

	my %listHash;
	my @ipList;
	my $index = 0;

	foreach my $source ( @{ &getBLParam( $listName, 'source' ) } )
	{
		push @ipList, { id => $index++, source => $source };
	}

	%listHash = %{ &getBLParam( $listName ) };
	delete $listHash{ 'source' };
	$listHash{ 'sources' } = \@ipList;
	$listHash{ 'status' }  = &getBLStatus( $listName );
	$listHash{ 'farms' }   = &getBLParam( $listName, 'farms' );

	# day as a number type
	$listHash{ 'day' } += 0 if ( $listHash{ 'day' } =~ /^\d+$/ );

	# save hour, minute, period and unit parameters in 'time' hash
	my @timeParameters = ( 'period', 'unit', 'hour', 'minutes' );

	foreach my $param ( @timeParameters )
	{
		if ( exists $listHash{ $param } )
		{
			my $var = $listHash{ $param };
			$var += 0 if ( $var =~ /^\d+$/ );
			$listHash{ 'time' }->{ $param } = $var;
			delete $listHash{ $param };
		}
	}

	return \%listHash;
}

=begin nd
Function: getBLIpList

	Get list of IPs from a local or remote list.

Parameters:

	listName - local listname / remote url, where find list of IPs

Returns:

	-1		 	- error
	\@ipList	- successful

=cut

sub getBLIpList
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $listName ) = @_;

	require Zevenet::Validate;

	my $output         = -1;
	my $blacklistsPath = &getGlobalConfiguration( 'blacklistsPath' );
	my $source_format  = &getValidFormat( 'blacklists_source' );

	# ip list format wrong
	# get only correct format lines
	open my $fh, '<', "$blacklistsPath/$listName.txt";
	chomp ( my @ipList = grep ( /($source_format)/, <$fh> ) );
	$output = \@ipList;
	close $fh;

	return $output;
}

sub setBLLockConfigFile
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	require Zevenet::Lock;

	my $lockfile = "/tmp/blacklist.lock";

	return &openlock( $lockfile, 'w' );
}

sub getBLAllLists
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	require Config::Tiny;
	require Zevenet::Config;

	my @lists;

	my $blacklistsConf = &getGlobalConfiguration( 'blacklistsConf' );
	my %all_bl         = %{ Config::Tiny->read( $blacklistsConf ) };

	delete $all_bl{ _ };

	foreach my $list_name ( sort keys %all_bl )
	{
		my $bl        = $all_bl{ $list_name };
		my $bl_status = $bl->{ status };
		my @bl_farms  = split ( ' ', $bl->{ farms } );

		$bl_status = "down" if ( !$bl_status );

		my %listHash = (
						 name    => $list_name,
						 farms   => ( @bl_farms ) ? \@bl_farms : [],
						 policy  => $bl->{ policy },
						 type    => $bl->{ type },
						 status  => $bl_status,
						 preload => $bl->{ preload },
		);

		push @lists, \%listHash;
	}

	return \@lists;
}

1;
