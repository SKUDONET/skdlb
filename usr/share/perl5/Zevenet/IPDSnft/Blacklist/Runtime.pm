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

# The goal of this file is to keep the needed functions to apply actions to system
# related with the blacklist process: iptables, ipset, cron...

use strict;

use Zevenet::Core;
include 'Zevenet::IPDS::Blacklist::Core';
include 'Zevenet::IPDS::Core';

sub setBLRunList
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $listName = shift;
	my $output;
	my $action;
	my $type = "blacklist";

	&zenlog( "Loading the list $listName", "info", "IPDS" );

	$action = &getBLParam( $listName, 'policy' );
	$type = "whitelist" if ( $action eq "allow" );

	$output = &setIPDSPolicyParam( 'type', $type, $listName );

	if ( $output == 0 )
	{
		$output = &setBLRefreshList( $listName );
		&zenlog( "Error, refreshing the list $listName", "error", "IPDS" )
		  if ( $output );
	}

	if ( &getBLParam( $listName, 'type' ) eq 'remote' )
	{
		&setBLCronTask( $listName );
	}

	return $output;
}

sub setBLDestroyList
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $listName = shift;

	my $output;

	# delete task from cron
	if ( &getBLParam( $listName, 'type' ) eq 'remote' )
	{
		&delBLCronTask( $listName );
	}

	&zenlog( "Destroying blacklist $listName", "info", "IPDS" );
	$output = &delIPDSPolicy( 'policy', undef, $listName );

	return $output;
}

=begin nd
Function: setBLRefreshList

	Update IPs from a list.

Parameters:

	$listName

Returns:

	== 0	- successful
	!= 0	- error

=cut

sub setBLRefreshList
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $listName ) = @_;

	my $ipList    = &getBLIpList( $listName );
	my $source_re = &getValidFormat( 'blacklists_source' );
	my $output;

	&zenlog( "Refreshing the list $listName", "info", "IPDS" );

	$output = &delIPDSPolicy( 'elements', undef, $listName );

	$output = &setIPDSPolicyParam( 'elements', $ipList, $listName );

	if ( $output )
	{
		&zenlog( "Error refreshing '$listName'.", "error", "IPDS" );
	}

	return $output;
}

=begin nd
Function: setBLDownloadRemoteList

	Download a list from url and keep it in file

Parameters:

	listName

Returns:

=cut

sub setBLDownloadRemoteList
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $listName ) = @_;

	require Tie::File;
	require Zevenet::Validate;
	include 'Zevenet::IPDS::Blacklist::Config';

	my $url = &getBLParam( $listName, 'url' );
	my $timeout = 10;
	my $error;

	&zenlog( "Downloading $listName...", "info", "IPDS" );

	# Not direct standard output to null, this output is used for web variable
	my @web           = `curl --connect-timeout $timeout \"$url\" 2>/dev/null`;
	my $source_format = &getValidFormat( 'blacklists_source' );

	my @ipList;

	foreach my $line ( @web )
	{
		if ( $line =~ /($source_format)/ )
		{
			push @ipList, $1;
		}
	}

	# set URL down if it doesn't have any ip
	if ( !@ipList )
	{
		&setBLParam( $listName, 'update_status', 'down' );
		&zenlog( "Failed downloading $listName from url '$url'. Not found any source.",
				 "error", "IPDS" );
		$error = 1;
	}
	else
	{
		my $path     = &getGlobalConfiguration( 'blacklistsPath' );
		my $fileList = "$path/$listName.txt";

		require Zevenet::Lock;
		&ztielock( \my @list, $fileList );
		@list = @ipList;
		untie @list;

		&setBLParam( $listName, 'update_status', 'up' );
		&zenlog( "$listName was downloaded successful.", "info", "IPDS" );
	}

	return $error;
}

=begin nd
Function: setBLCreateRule

	Assign a policy to a farm.

Parameters:

	farmName - farm where the list will be applied
	listName - ip list name

Returns:

	$cmd	- Command
	-1		- error

=cut

sub setBLCreateRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farmName, $listName ) = @_;

	include 'Zevenet::IPDS::Core';

	my $output;
	my $action = &getBLParam( $listName, 'policy' );

	if ( &getBLIpsetStatus( $listName ) eq "down" )
	{
		&setBLRunList( $listName );
	}

	$output = &setIPDSFarmParam( 'policy', $listName, $farmName );
	if ( !$output )
	{
		&zenlog( "List '$listName' was applied successful to the farm '$farmName'.",
				 "info", "IPDS" );
	}

	return $output;
}

=begin nd
Function: setBLDeleteRule

	Delete a iptables rule.

Parameters:

	farmName - farm where rules will be applied
	list	 - ip list name

Returns:

	== 0	- successful
	!= 0	- error

=cut

sub setBLDeleteRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farmName, $listName ) = @_;

	my $output;

	include 'Zevenet::IPDS::Core';

	$output = &delIPDSFarmParam( 'policy', $listName, $farmName );

	# delete list if it isn't used. This has to be the last call.
	if ( !&getBLListNoUsed( $listName ) )
	{
		&setBLDestroyList( $listName );
	}

	return $output;
}

sub delBLCronTask
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $listName = shift;

	require Tie::File;

	my $blacklistsCronFile = &getGlobalConfiguration( 'blacklistsCronFile' );
	my $index              = 0;

	require Zevenet::Lock;
	&ztielock( \my @list, $blacklistsCronFile );

	foreach my $line ( @list )
	{
		if ( $line =~ /\s$listName\s/ )
		{
			splice @list, $index, 1;
			last;
		}
		$index++;
	}

	untie @list;

	my $cron_service = &getGlobalConfiguration( 'cron_service' );
	&logAndRun( "$cron_service restart" );

	&zenlog( "Deleted the task associated to the list $listName", "info", "IPDS" );
}

# &setBLCronTask ( $list );
sub setBLCronTask
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $listName ) = @_;

	my $cronFormat =
	  { 'min' => '*', 'hour' => '*', 'dow' => '*', 'dom' => '*', 'month' => '*' };
	my $rblFormat;

	# get values
	$rblFormat->{ 'frequency' }      = &getBLParam( $listName, 'frequency' );
	$rblFormat->{ 'minutes' }        = &getBLParam( $listName, 'minutes' );
	$rblFormat->{ 'hour' }           = &getBLParam( $listName, 'hour' );
	$rblFormat->{ 'period' }         = &getBLParam( $listName, 'period' );
	$rblFormat->{ 'unit' }           = &getBLParam( $listName, 'unit' );
	$rblFormat->{ 'frequency_type' } = &getBLParam( $listName, 'frequency_type' );
	$rblFormat->{ 'day' }            = &getBLParam( $listName, 'day' );

	# change to cron format
	if (    $rblFormat->{ 'frequency' } eq 'daily'
		 && $rblFormat->{ 'frequency_type' } eq 'period' )
	{
		my $period = $rblFormat->{ 'period' };
		if ( $rblFormat->{ 'unit' } eq 'minutes' )
		{
			$cronFormat->{ 'min' } = "*/$rblFormat->{ 'period' }";
		}
		elsif ( $rblFormat->{ 'unit' } eq 'hours' )
		{
			$cronFormat->{ 'min' }  = '00';
			$cronFormat->{ 'hour' } = "*/$rblFormat->{ 'period' }";
		}
	}
	else
	{
		$cronFormat->{ 'hour' } = "$rblFormat->{ 'hour' }";
		$cronFormat->{ 'min' }  = "$rblFormat->{ 'minutes' }";

		# exact daily frencuncies only need these fields

		if ( $rblFormat->{ 'frequency' } eq 'weekly' )
		{
			my $day = $rblFormat->{ 'day' };

			if    ( $day eq 'monday' )    { $cronFormat->{ 'dow' } = '0' }
			elsif ( $day eq 'tuesday' )   { $cronFormat->{ 'dow' } = '1' }
			elsif ( $day eq 'wednesday' ) { $cronFormat->{ 'dow' } = '2' }
			elsif ( $day eq 'thursday' )  { $cronFormat->{ 'dow' } = '3' }
			elsif ( $day eq 'friday' )    { $cronFormat->{ 'dow' } = '4' }
			elsif ( $day eq 'saturday' )  { $cronFormat->{ 'dow' } = '5' }
			elsif ( $day eq 'sunday' )    { $cronFormat->{ 'dow' } = '6' }
		}
		elsif ( $rblFormat->{ 'frequency' } eq 'monthly' )
		{
			$cronFormat->{ 'dom' } = $rblFormat->{ 'day' };
		}
	}

	my $blacklistsCronFile = &getGlobalConfiguration( 'blacklistsCronFile' );
	my $zbindir            = &getGlobalConfiguration( 'zbindir' );

	# 0 0 * * 1	root	/usr/local/zevenet/app/zenrrd/zenrrd & >/dev/null 2>&1
	my $cmd =
	  "$cronFormat->{ 'min' } $cronFormat->{ 'hour' } $cronFormat->{ 'dom' } $cronFormat->{ 'month' } $cronFormat->{ 'dow' }\t"
	  . "root\t$zbindir/updateRemoteList $listName & >/dev/null 2>&1";
	&zenlog( "Added cron task: $cmd", "info", "IPDS" );

	require Zevenet::Lock;
	&ztielock( \my @list, $blacklistsCronFile );

	# this line already exists, replace it
	if ( grep ( s/.* $listName .*/$cmd/, @list ) )
	{
		&zenlog( "update cron task for list $listName", "info", "IPDS" );
	}
	else
	{
		push @list, $cmd;
	}
	untie @list;

	my $cron_service = &getGlobalConfiguration( 'cron_service' );
	&logAndRun( "$cron_service restart" );
	&zenlog( "Created a cron task for the list $listName", "info", "IPDS" );
}

sub setBLApplyToFarm
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farmName, $listName ) = @_;

	require Zevenet::Farm::Base;

	my $output;

	# run rule only if the farm is up and the rule is enabled
	if ( &getBLParam( $listName, 'status' ) ne 'down' )
	{
		if ( &getFarmStatus( $farmName ) eq 'up' )
		{
			# load de list if it is not been used
			if ( &getBLIpsetStatus( $listName ) eq 'down' )
			{
				$output = &setBLRunList( $listName );

				# if the list is remote and is not downloaded yet, downloaded it
				if ( &getBLParam( $listName, 'remote' ) )
				{
					&setBLDownloadRemoteList( $listName );
				}
			}

			# create iptable rule
			if ( !$output )
			{
				$output = &setBLCreateRule( $farmName, $listName );
			}
		}
	}

	if ( !$output )
	{
		include 'Zevenet::IPDS::Blacklist::Config';
		$output = &setBLParam( $listName, 'farms-add', $farmName );
	}

	return $output;
}

sub setBLRemFromFarm
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farmName, $listName ) = @_;

	my $output = &setBLDeleteRule( $farmName, $listName );

	if ( !$output )
	{
		include 'Zevenet::IPDS::Blacklist::Config';
		$output = &setBLParam( $listName, 'farms-del', $farmName );
	}

	# delete list if it isn't used. This has to be the last call.
	if ( !$output && !&getBLListNoUsed( $listName ) )
	{
		&setBLDestroyList( $listName );
	}

	return $output;
}

1;
