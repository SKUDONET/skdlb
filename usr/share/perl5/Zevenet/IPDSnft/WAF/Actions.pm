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
include 'Zevenet::IPDS::WAF::Core';

my $wafSetDir = &getWAFSetDir();

=begin nd
Function: initWAFModule

	Create configuration files and run all needed commands requested to WAF module

Parameters:
	None - .

Returns:
	None - .

=cut

sub initWAFModule
{
	use File::Path qw(make_path);

	#~ my $touch     = &getGlobalConfiguration( "touch" );

	my $deleted_rules = &getWAFDelRegisterDir();

	make_path( $wafSetDir )     if ( !-d $wafSetDir );
	make_path( $deleted_rules ) if ( !-d $deleted_rules );
}

use Tie::File;
my $preload_sets = &getWAFDir() . "/preload_sets.conf";
my $waf_pkg_dir  = &getGlobalConfiguration( 'templatedir' ) . "/waf";

=begin nd
Function: listWAFSetPreload

	Return a list with all the preloaded set has been added to the configuration directory

Parameters:
	None - .

Returns:
	Array - list of set names

=cut

sub listWAFSetPreload
{
	my @list_sets = ();
	tie my @array, 'Tie::File', $preload_sets
	  or &zenlog( "the file $preload_sets could not be opened", "warning", "waf" );
	if ( @array )
	{
		@list_sets = @array;
		untie @array;
	}

	return @list_sets;
}

=begin nd
Function: addWAFSetPreload

	Add a set name to the list of preloaded set already loaded in the config directory

Parameters:
	Set - Set name

Returns:
	Integer - 0 on sucess or 1 on failure

=cut

sub addWAFSetPreload
{
	my $set = shift;

	tie my @array, 'Tie::File', $preload_sets or return 1;

	push @array, $set;
	untie @array;

	return 0;
}

=begin nd
Function: delWAFSetPreload

	Delete a set of the preloaded list.

Parameters:
	Set - Set name

Returns:
	Integer - 0 on success or 1 on failure

=cut

sub delWAFSetPreload
{
	my $set = shift;

	tie my @array, 'Tie::File', $preload_sets or return 1;

	for my $it ( 0 .. $#array )
	{
		if ( $array[$it] eq $set )
		{
			splice @array, $it, 1;
			last;
		}
	}

	untie @array;
	return 0;
}

=begin nd
Function: getWAFSetPreloadPkg

	Return a list with all the set path in the template directory

Parameters:
	None - .

Returns:
	Array - list of paths

=cut

sub getWAFSetPreloadPkg
{
	opendir my $dir, $waf_pkg_dir;
	my @files = readdir $dir;
	closedir $dir;

	return @files;
}

=begin nd
Function: updateWAFSetPreload

	Main function to update the preloaded sets. It applies the following changes:
	- Remove a preloaded set that is not used and it has been deleted from the ipds package
	- Replace the set in the config directory
	- Delete de rules that has been deleted o modfied by the user
	- Add the rules that has been created, moved or modified by the use

Parameters:
	None - .

Returns:
	Integer - 0 on success or 1 on failure

=cut

sub updateWAFSetPreload
{
	my $err        = 0;
	my $err_global = 0;

	include 'Zevenet::IPDS::WAF::Actions';
	include 'Zevenet::IPDS::WAF::Config';
	use File::Copy qw(copy);

	my @prel_path = &getWAFSetPreloadPkg();

	# deleting deprecated sets
	foreach my $set ( &listWAFSetPreload() )
	{
		# do not to delete it if it is in the package
		next if ( grep ( /^$waf_pkg_dir\/${set}\.conf$/, @prel_path ) );

		# Delete it only if it is not used by any farm
		next if ( &listWAFBySet( $set ) );

		# delete it
		$err = &deleteWAFSet( $set );

# delete it from the register log. Only add and delete entries in Preload file the migration process
		$err = &delWAFSetPreload( $set );

		&zenlog( "The WAF set $set has been deleted properly", 'info', 'waf' )
		  if !$err;
		&zenlog( "Error deleting the WAF set $set", 'error', 'waf' ) if $err;
	}
	return $err if $err;

	# add and modify the sets
	foreach my $pre_set ( @prel_path )
	{
		# get data of the test
		my $setname  = "";
		my $filename = "";
		my $set_file;
		my $cur_set;
		my $file_type = "";

		if ( $err )
		{
			$err_global++;
			$err = 0;
		}

		# the file is a file with rules
		if ( $pre_set =~ /([\w-]+)\.conf$/ )
		{
			$setname   = $1;
			$file_type = "sets";
			$set_file  = &getWAFSetFile( $setname );

			# load the current set
			$cur_set = &getWAFSet( $setname ) if ( -f $set_file );
		}

		# the file is a file with data
		elsif ( $pre_set =~ /([\w-]+\.\w+)$/ )
		{
			$setname  = $1;
			$set_file = "$wafSetDir/$setname";
		}

		# the file is not recognoized
		else
		{
			&zenlog( "Set name does not correct in the string $pre_set", "debug", "WAF" );
			next;
		}

		# copy template to the config directory, overwritting the set
		copy( "$waf_pkg_dir/$pre_set" => $set_file );

		# finish if the rule is not
		next if ( $file_type ne 'sets' );

		# open the new created set
		my $new_set = &getWAFSet( $setname );
		my $index   = 0;
		foreach my $rule ( @{ $new_set->{ rules } } )
		{
			if ( &checkWAFDelRegister( $setname, $rule->{ raw } ) )
			{
				splice @{ $new_set->{ rules } }, $index, 1;
			}
			else
			{
				$index++;
			}
		}

		# if set already exists, migrate the configuration
		if ( defined $cur_set )
		{
			require Zevenet::Arrays;

			# add the rules are been created by de user and move it of position
			my $ind   = 0;
			my @rules = @{ $cur_set->{ rules } };

			foreach my $rule ( @rules )
			{
				if ( $rule->{ modified } eq 'yes' )
				{
					push @{ $new_set->{ rules } }, $rule;
					&moveByIndex( $new_set->{ rules }, scalar @{ $new_set->{ rules } } - 1, $ind );
				}
				$ind++;
			}

			# add the configuration
			$new_set->{ configuration } = $cur_set->{ configuration };
		}
		else
		{
			# log the new set in the register to know is a preloaded set
			$err = &addWAFSetPreload( $setname );
		}

		# save set
		$err = &buildWAFSet( $setname, $new_set ) if !$err;

		if ( !$err )
		{
			&zenlog( "The WAF set $setname has been created properly", 'info', 'waf' );
		}
		else
		{
			&zenlog( "There was a error loading $setname", "error", "waf" );
		}
	}

	return $err_global;
}

1;
