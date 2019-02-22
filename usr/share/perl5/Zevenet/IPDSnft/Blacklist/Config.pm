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

# The goal of this file is to keep the needed functions to apply configurations
# to config files: blacklist config...

# Once the configuration is saved in the system, the functions will apply some
# action to system if it is necessary using Zevenet::IPDS::Blacklist::Runtime module

use strict;

use Config::Tiny;

# general dependencies
use Zevenet::Core;
use Zevenet::Debug;

include 'Zevenet::IPDS::Blacklist::Core';

sub setBLCreateList
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $listName   = shift;
	my $listParams = shift;

	my $def_policy  = 'deny';
	my $def_preload = 'false';
	my $output;

	my $blacklistsConf = &getGlobalConfiguration( 'blacklistsConf' );
	my $blacklistsPath = &getGlobalConfiguration( 'blacklistsPath' );
	my $touch          = &getGlobalConfiguration( 'touch' );
	my $type           = $listParams->{ 'type' };

	if ( !-e $blacklistsConf )
	{
		$output = system ( "$touch $blacklistsConf" );
		&zenlog( "blacklists configuration file was created.", "info", "IPDS" );
	}

	if ( $listParams->{ 'type' } eq 'remote' && !exists $listParams->{ 'url' } )
	{
		&zenlog( "Remote lists need an url", "warning", "IPDS" );
		return -1;
	}

	# share params
	my $lock       = &setBLLockConfigFile();
	my $fileHandle = Config::Tiny->read( $blacklistsConf );
	$fileHandle->{ $listName }->{ 'type' }   = $listParams->{ 'type' };
	$fileHandle->{ $listName }->{ 'status' } = "down";
	$fileHandle->{ $listName }->{ 'farms' }  = "";
	if ( exists $listParams->{ 'preload' } )
	{
		$fileHandle->{ $listName }->{ 'preload' } = $listParams->{ 'preload' };
	}
	else
	{
		$fileHandle->{ $listName }->{ 'preload' } = $def_preload;
	}
	if ( exists $listParams->{ 'policy' } )
	{
		$fileHandle->{ $listName }->{ 'policy' } = $listParams->{ 'policy' };
	}
	else
	{
		$fileHandle->{ $listName }->{ 'policy' } = $def_policy;
	}

	$fileHandle->write( $blacklistsConf );
	close $lock;

	# specific to remote lists
	if ( $type eq 'remote' )
	{
		include 'Zevenet::IPDS::Blacklist::Config';

		&setBLParam( $listName, 'url',           $listParams->{ 'url' } );
		&setBLParam( $listName, 'update_status', "This list isn't downloaded yet." );

		# default value to update the list
		# the list is updated the mondays at 00:00 weekly
		&setBLParam( $listName, 'minutes',   '00' );
		&setBLParam( $listName, 'hour',      '00' );
		&setBLParam( $listName, 'day',       'monday' );
		&setBLParam( $listName, 'frequency', 'weekly' );
	}

	# specific to local lists
	elsif ( $type eq 'local' )
	{
		$output = system ( "$touch $blacklistsPath/$listName.txt 2>/dev/null" );
	}

	return $output;
}

=begin nd
Function: setBLDeleteList

	Delete a list from iptables, ipset and configuration file

Parameters:

	$listName	- List to delete

Returns:

	==0	- successful
	!=0 - error

=cut

sub setBLDeleteList
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $listName ) = @_;

	my $fileHandle;
	my $output;
	my $error;

	my $blacklistsConf = &getGlobalConfiguration( 'blacklistsConf' );
	my $blacklistsPath = &getGlobalConfiguration( 'blacklistsPath' );
	my $ipset          = &getGlobalConfiguration( 'ipset' );
	my @farms          = @{ &getBLParam( $listName, 'farms' ) };

	# Check if the rule is down
	if ( &getBLIpsetStatus( $listName ) eq "up" )
	{
		&zenlog(
			"Error deleting the list, it is not possible remove the rule while it is running.",
			"error", "IPDS"
		);
		return -1;
	}

	# delete from config file
	my $lock = &setBLLockConfigFile();
	$fileHandle = Config::Tiny->read( $blacklistsConf );
	delete $fileHandle->{ $listName };
	$fileHandle->write( $blacklistsConf );
	close $lock;

	if ( -f "$blacklistsPath/$listName.txt" )
	{
		$output = unlink "$blacklistsPath/$listName.txt";
		$output = ( $output ) ? 0 : 1;
	}

	if ( $output != 0 )
	{
		&zenlog( "Error deleting the list '$listName'.", "error", "IPDS" );
	}

	return $output;
}

=begin nd
Function: setBLAddPreloadLists

	This function return all preload lists available or
	the source list of ones of this

Parameters:

	country - This param is optional, with this param, the function return the
			  source list of lan segment for a country

Returns:

		array ref	- availabe counrties or source list

=cut

sub setBLAddPreloadLists
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $local_list     = shift;
	my $preload_remote = shift;

	my $blacklistsConf = &getGlobalConfiguration( 'blacklistsConf' );
	my $blacklistsPath = &getGlobalConfiguration( 'blacklistsPath' );
	my $touch          = &getGlobalConfiguration( 'touch' );

	# Local preload lists
	my @preloadLists = @{ $local_list };
	my $fileHandle   = Config::Tiny->read( $blacklistsConf );

	foreach my $list ( @preloadLists )
	{
		$list =~ s/\.txt$//;

		# save lists
		if ( !exists $fileHandle->{ $list } )
		{
			my $listHash;
			$listHash->{ 'type' }    = 'local';
			$listHash->{ 'preload' } = 'true';

			&setBLCreateList( $list, $listHash );
		}
	}

	# Remote preload lists
	foreach my $list ( keys %{ $preload_remote } )
	{
		# list don't exist. Download
		if ( !exists $fileHandle->{ $list } )
		{
			my $listHash;
			$listHash->{ 'url' }     = $preload_remote->{ $list }->{ 'url' };
			$listHash->{ 'type' }    = 'remote';
			$listHash->{ 'preload' } = 'true';

			&setBLCreateList( $list, $listHash );
			&zenlog( "The preload list '$list' was created.", "info", "IPDS" );
		}

		# list exists like preload. Update settings
		elsif ( &getBLParam( $list, 'preload' ) eq 'true' )
		{
			&zenlog( "Update list $list", "info", "IPDS" );
			&setBLParam( $list, 'url', $preload_remote->{ $list }->{ 'url' } );

			# Create list file if it doesn't exist
			if ( !-f "$blacklistsPath/$list.txt" )
			{
				system ( "$touch $blacklistsPath/$list.txt 2>/dev/null" );
			}
			&zenlog( "The preload list '$list' was updated.", "info", "IPDS" );
		}

		# list exists like NO preload
		else
		{
			&zenlog(
				"The preload list '$list' can't be loaded because other list exists with the same name.",
				"warning", "IPDS"
			);
		}
	}
}

=begin nd
	Function: getBLMaxelem

        Get the maxelem configurated when the list was created

        Parameters:
        list - list name

        Returns:
			integer - maxelem of the set

=cut

sub getBLMaxelem
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $list    = shift;
	my $ipset   = &getGlobalConfiguration( "ipset" );
	my $maxelem = 0;

	my @aux = `$ipset list $list -terse`;
	for my $line ( @aux )
	{
		if ( $line =~ /maxelem (\d+)/ )
		{
			$maxelem = $1;
			last;
		}
	}
	return $maxelem;
}

=begin nd
Function: setBLParam

		Modificate local config file.

Parameters:

	name	- section name
	key		- field to modificate
	value	- value for the field
	opt		- add / del		when key = farms

Returns:

	0	- successful
	!=0	- error

=cut

sub setBLParam
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $name, $key, $value ) = @_;

	my $output;

	# get conf
	my $type           = &getBLParam( $name, 'type' );
	my $blacklistsConf = &getGlobalConfiguration( 'blacklistsConf' );
	my $blacklistsPath = &getGlobalConfiguration( 'blacklistsPath' );
	my $fileHandle     = Config::Tiny->read( $blacklistsConf );
	my $conf           = $fileHandle->{ $name };
	my @farmList       = @{ &getBLParam( $name, 'farms' ) };
	my $ipList         = &getBLParam( $name, 'source' );

	# change name of the list
	if ( 'name' eq $key )
	{
		if ( &getBLExists( $value ) )
		{
			&zenlog( "List '$value' already exists.", "warning", "IPDS" );
			$output = -1;
		}
		else
		{
			# delete list and all rules applied to the farms
			$output = system (
						"mv $blacklistsPath/$name.txt $blacklistsPath/$value.txt 2>/dev/null" );

			my $lock = &setBLLockConfigFile();
			$fileHandle = Config::Tiny->read( $blacklistsConf );
			$fileHandle->{ $value } = $fileHandle->{ $name };
			delete $fileHandle->{ $name };
			$fileHandle->write( $blacklistsConf );
			close $lock;

			return $output;
		}
	}
	elsif ( 'source' eq $key )
	{
		# only can be modificated local lists not preloaded
		if (    $conf->{ 'type' } eq 'local'
			 && $conf->{ 'preload' } eq 'false' )
		{
			$output = &setBLAddToList( $name, $value );

			# refresh if not error and this list is applied almost to one farm
			if ( !$output && &getBLIpsetStatus( $name ) eq 'up' )
			{
				include 'Zevenet::IPDS::Blacklist::Runtime';
				$output = &setBLRefreshList( $name );
			}
		}
	}
	elsif ( 'farms-add' eq $key )
	{
		my $lock = &setBLLockConfigFile();
		$fileHandle = Config::Tiny->read( $blacklistsConf );
		$conf       = $fileHandle->{ $name };

		if ( $conf->{ $key } !~ /(^| )$value( |$)/ )
		{
			my $farmList = $fileHandle->{ $name }->{ 'farms' };
			$fileHandle->{ $name }->{ 'farms' } = "$farmList $value";
			$fileHandle->write( $blacklistsConf );
		}

		close $lock;
	}
	elsif ( 'farms-del' eq $key )
	{
		my $lock = &setBLLockConfigFile();
		$fileHandle = Config::Tiny->read( $blacklistsConf );
		$conf       = $fileHandle->{ $name };
		$fileHandle->{ $name }->{ 'farms' } =~ s/(^| )$value( |$)/ /;
		$fileHandle->write( $blacklistsConf );
		close $lock;
	}
	elsif ( 'update_status' eq $key )
	{
		my $date = &getBLlastUptdate( $name );
		my $lock = &setBLLockConfigFile();
		$fileHandle = Config::Tiny->read( $blacklistsConf );
		if ( $value eq 'up' )
		{
			$fileHandle->{ $name }->{ $key } = "Sync OK. Last update: $date";
		}
		elsif ( $value eq 'down' )
		{
			# never was downloaded
			if ( !$date )
			{
				$fileHandle->{ $name }->{ $key } =
				  "Sync fail. The list has not been downloaded yet";
			}
			else
			{
				$fileHandle->{ $name }->{ $key } = "Sync fail. Last update: $date";
			}
		}
		else
		{
			$fileHandle->{ $name }->{ $key } = $value;
		}
		$fileHandle->write( $blacklistsConf );
		close $lock;
	}

	# other value  of the file conf
	else
	{
		my $lock = &setBLLockConfigFile();
		$fileHandle = Config::Tiny->read( $blacklistsConf );
		$fileHandle->{ $name }->{ $key } = $value;
		$fileHandle->write( $blacklistsConf );
		close $lock;
	}

	return $output;
}

sub delBLParam
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $listName, $key ) = @_;

	my $output;
	my $fileHandle;

	my $blacklistsConf = &getGlobalConfiguration( 'blacklistsConf' );

	my $lock = &setBLLockConfigFile();
	$fileHandle = Config::Tiny->read( $blacklistsConf );

	if ( exists ( $fileHandle->{ $listName }->{ $key } ) )
	{
		&zenlog( "Deleted parameter $key in list $listName.", "info", "IPDS" );
		delete $fileHandle->{ $listName }->{ $key };
		$fileHandle->write( $blacklistsConf );
	}
	close $lock;
}

=begin nd
Function: setBLAddToList

	Change ip list for a list

Parameters:
	listName
	listRef	 - ref to ip list

Returns:

=cut

sub setBLAddToList
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $listName, $listRef ) = @_;

	require Zevenet::Validate;

	my $blacklistsPath = &getGlobalConfiguration( 'blacklistsPath' );
	my $source_format  = &getValidFormat( 'blacklists_source' );
	my @ipList         = grep ( /$source_format/, @{ $listRef } );
	my $output         = -1;

	if ( -f "$blacklistsPath/$listName.txt" )
	{
		require Zevenet::Lock;
		&ztielock( \my @list, "$blacklistsPath/$listName.txt" );
		@list = @ipList;
		untie @list;
		&zenlog( "IPs of '$listName' were modificated.", "info", "IPDS" );
		$output = 0;
	}

	return $output;
}

=begin nd
Function: setBLAddSource

	Add a source from a list

Parameters:
	list	- ip list name
	source	- new source to add

Returns:
=cut

sub setBLAddSource
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $listName, $source ) = @_;

	my $ipset          = &getGlobalConfiguration( 'ipset' );
	my $blacklistsPath = &getGlobalConfiguration( 'blacklistsPath' );
	my $policy         = &getBLParam( $listName, 'policy' );
	my $error;

	require Zevenet::Lock;
	&ztielock( \my @list, "$blacklistsPath/$listName.txt" );
	push @list, $source;
	untie @list;

	if ( &getBLIpsetStatus( $listName ) eq 'up' )
	{
		$error = &setIPDSPolicyParam( 'element', $source, $listName );
	}

	&zenlog( "$source was added to $listName", "info", "IPDS" ) if ( !$error );

	return $error;
}

=begin nd
Function: setBLModifSource

	Modify a source from a list

Parameters:
	list	- ip list name
	id		- line to modificate
	source	- new value

Returns:
=cut

sub setBLModifSource
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $listName, $id, $source ) = @_;

	my $policy         = &getBLParam( $listName, 'policy' );
	my $ipset          = &getGlobalConfiguration( 'ipset' );
	my $blacklistsPath = &getGlobalConfiguration( 'blacklistsPath' );
	my $err;

	require Zevenet::Lock;
	&ztielock( \my @list, "$blacklistsPath/$listName.txt" );
	my $oldSource = splice @list, $id, 1, $source;
	untie @list;

	if ( &getBLIpsetStatus( $listName ) eq 'up' )
	{
		$err = system ( "$ipset del $listName $oldSource >/dev/null 2>&1" );
		$err = system ( "$ipset add $listName $source >/dev/null 2>&1" ) if ( !$err );
	}

	&zenlog( "$oldSource was replaced for $source in the list $listName",
			 "info", "IPDS" )
	  if ( !$err );

	return $err;
}

=begin nd
Function: setBLDeleteSource

	Delete a source from a list

Parameters:
	list	- ip list name
	id		- line to delete

Returns:

=cut

sub setBLDeleteSource
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $listName, $id ) = @_;

	my $policy         = &getBLParam( $listName, 'policy' );
	my $ipset          = &getGlobalConfiguration( 'ipset' );
	my $blacklistsPath = &getGlobalConfiguration( 'blacklistsPath' );
	my $err;

	require Zevenet::Lock;
	&ztielock( \my @list, "$blacklistsPath/$listName.txt" );
	my $source = splice @list, $id, 1;
	untie @list;

	if ( &getBLIpsetStatus( $listName ) eq 'up' )
	{
		$err = system ( "$ipset del $listName $source >/dev/null 2>&1" );
	}

	&zenlog( "$source was deleted from $listName", "info", "IPDS" ) if ( !$err );

	return $err;
}

1;
