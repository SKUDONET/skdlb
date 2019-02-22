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

include 'Zevenet::IPDS::Blacklist::Core';
include 'Zevenet::IPDS::Blacklist::Config';

sub initIPDSModule
{
	include 'Zevenet::IPDS::Blacklist::Actions';
	include 'Zevenet::IPDS::DoS::Config';
	include 'Zevenet::IPDS::RBL::Config';
	include 'Zevenet::IPDS::WAF::Actions';

	&initBLModule();
	&initDOSModule();
	&initWAFModule();
	&initRBLModule();
}

sub migrate_blacklist_names
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	# migration hash
	my $migration = shift;

	foreach my $key ( keys %{ $migration } )
	{
		my $newlist = $migration->{ $key }->{ name };
		$newlist =~ s/\.txt$//;

		foreach my $oldlist ( @{ $migration->{ $key }->{ old_names } } )
		{
			$oldlist =~ s/\.txt$//;

			#if exists migrate it
			if ( &getBLExists( $oldlist ) )
			{
				# rename first one
				if ( !&getBLExists( $newlist ) )
				{
					&setBLParam( $oldlist, 'name', $newlist );
				}
				else

				  # delete others one
				{
					&setBLDeleteList( $oldlist );
				}
			}
		}
	}
}

sub remove_blacklists
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my @lists_to_remove = @_;

	foreach my $list ( @lists_to_remove )
	{
		if ( &getBLExists( $list ) && !@{ &getBLParam( $list, 'farms' ) } )
		{
			&setBLDeleteList( $list );
		}
	}
}

sub rename_blacklists
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my @list_to_rename = @_;

	foreach my $list ( @list_to_rename )
	{
		if (    &getBLExists( $list->{ name } )
			 && &getBLParam( $list->{ name }, 'preload' ) eq "true" )
		{
			&setBLParam( $list->{ name }, 'name', $list->{ new_name } );
		}
	}
}

# populate status parameter for blacklist rules
sub set_blacklists_status
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	require Config::Tiny;

	my $blacklistsConf = "/usr/local/zevenet/config/ipds/blacklists/lists.conf";
	my $fileHandle     = Config::Tiny->read( $blacklistsConf );

	foreach my $list ( keys %{ $fileHandle } )
	{
		next if ( exists $fileHandle->{ $list }->{ status } );

		if ( $fileHandle->{ $list }->{ farms } =~ /\w/ )
		{
			$fileHandle->{ $list }->{ status } = "up";
		}
		else
		{
			$fileHandle->{ $list }->{ status } = "down";
		}
	}

	$fileHandle->write( $blacklistsConf );
}

# populate status parameter for dos rules
sub set_dos_status
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	require Config::Tiny;

	my $dosConf    = "/usr/local/zevenet/config/ipds/dos/dos.conf";
	my $fileHandle = Config::Tiny->read( $dosConf );

	foreach my $rule ( keys %{ $fileHandle } )
	{
		next if ( exists $fileHandle->{ $rule }->{ status } );

		if ( $fileHandle->{ $rule }->{ farms } =~ /\w/ )
		{
			$fileHandle->{ $rule }->{ status } = "up";
		}
		else
		{
			$fileHandle->{ $rule }->{ status } = "down";
		}
	}

	$fileHandle->write( $dosConf );
}

1;
