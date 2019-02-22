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

# The goal of this file is keep the needed functions to apply start, stop or
# restart actions to blacklist rules

use strict;

use Zevenet::Farm::Base;
include 'Zevenet::IPDS::Blacklist::Runtime';

my $blacklistsPath = &getGlobalConfiguration( 'blacklistsPath' );
my $blacklistsConf = &getGlobalConfiguration( 'blacklistsConf' );

=begin nd
Function: runBLStartModule

	Enable all blacklists rules

Parameters: None.

Returns: None.
=cut

sub runBLStartModule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $blacklistsConf = &getGlobalConfiguration( 'blacklistsConf' );

	my $touch          = &getGlobalConfiguration( 'touch' );
	my $blacklistsPath = &getGlobalConfiguration( 'blacklistsPath' );

	if ( !-d $blacklistsPath )
	{
		system ( &getGlobalConfiguration( 'mkdir' ) . " -p $blacklistsPath" );
		&zenlog( "Created $blacklistsPath directory.", "info", "IPDS" );
	}

	# create list config if doesn't exist
	if ( !-e $blacklistsConf )
	{
		system ( "$touch $blacklistsConf" );
		&zenlog( "Created $blacklistsConf file.", "info", "IPDS" );
	}

	my $allLists = Config::Tiny->read( $blacklistsConf );

	# load lists
	foreach my $list ( keys %{ $allLists } )
	{
		next if ( &getBLParam( $list, 'status' ) eq "down" );

		# run cron process
		if ( &getBLParam( $list, 'type' ) eq "remote" )
		{
			&setBLCronTask( $list );
		}

		my $farms = &getBLParam( $list, "farms" );
		next if ( !$farms );

		my @farms = @{ $farms };

		# create cmd  for all farms where are applied the list and  they are running
		foreach my $farm ( @farms )
		{
			if ( &getFarmBootStatus( $farm ) eq 'up' )
			{
				if ( &getBLIpsetStatus( $list ) eq "down" )
				{
					# load in memory the list
					&setBLRunList( $list );
				}
				&zenlog( "Creating rules for the list $list and farm $farm.", "info", "IPDS" );
				&setBLCreateRule( $farm, $list );
			}
		}
	}
}

=begin nd
Function: runBLStopModule

	Disable all blacklists rules

Parameters:

Returns:

=cut

sub runBLStopModule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $output;

	include 'Zevenet::IPDS::Core';
	include 'Zevenet::IPDS::Balcklist::Core';

	my @lists = &getBLAllLists();

	foreach my $rule ( @lists )
	{
		&setBLDestroyList( $rule );
	}

	$output = &delIPDSPolicy( 'policies', undef, undef );

	return $output;
}

=begin nd
Function: runBLRestartModule

	Stop the module

Parameters:

Returns:

=cut

sub runBLRestartModule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	&runBLStopModule;
	&runBLStartModule;
}

=begin nd
Function: runBLStartByRule

	Start the runtime of a blacklist rule and link with all farm that are using this rule.

Parameters:
	Rule - Rule name

Returns:
	integer - number of farms running with the rule applied

=cut

sub runBLStartByRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $ruleName ) = @_;

	my $error = 0;
	my @farms = @{ &getBLParam( $ruleName, 'farms' ) };

	foreach my $farmName ( @farms )
	{
		if ( &runBLStart( $ruleName, $farmName ) != 0 )
		{
			&zenlog( "Error running the rule $ruleName in the farm $farmName.",
					 "error", "IPDS" );
		}
		else
		{
			$error++;
		}
	}

	# check error
	$error = 1 if ( &getBLIpsetStatus( $ruleName ) eq "down" );

	# run cron process
	if ( &getBLParam( $ruleName, 'type' ) eq "remote" )
	{
		&setBLCronTask( $ruleName );
	}

	return $error;
}

=begin nd
Function: runBLStopByRule

	Stop the runtime of a blacklist rule  and unlink with all farm that are using this rule.

Parameters:
	Rule - Rule name

Returns:
	integer - 0 on success or other value on failure

=cut

sub runBLStopByRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $ruleName ) = @_;

	my $error = 0;

	if ( &getBLParam( $ruleName, 'type' ) eq "remote" )
	{
		&delBLCronTask( $ruleName );
	}

	return if ( &getBLIpsetStatus( $ruleName ) eq 'down' );

	foreach my $farmName ( @{ &getBLParam( $ruleName, 'farms' ) } )
	{
		if ( &runBLStop( $ruleName, $farmName ) != 0 )
		{
			&zenlog( "Error stopping the rule $ruleName in the farm $farmName.",
					 "error", "IPDS" );
		}
	}

	return $error;
}

=begin nd
Function: runBLRestartByRule

	Restart the runtime of a blacklist rule.
	It is useful when a the rule will be modified.

Parameters:
	Rule - Rule name

Returns:
	integer - 0 on success or other value on failure

=cut

sub runBLRestartByRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $rule ) = @_;

	my $error = &runBLStopByRule( $rule );

	if ( !$error )
	{
		$error = &runBLStartByRule( $rule );
	}

	return $error;
}

=begin nd
Function: runBLStart

	Start the runtime of a blacklist rule and link with a farm that are using this rule.

Parameters:
	Rule - Rule name
	Farmanme - Farm name

Returns:
	integer - 0 on success or other value on failure

=cut

sub runBLStart
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $list, $farm ) = @_;
	my $error;

	# if the rule is disabled, not run it
	return 0 if ( &getBLParam( $list, 'status' ) eq "down" );

	if ( &getFarmBootStatus( $farm ) eq 'up' )
	{
		if ( &getBLIpsetStatus( $list ) eq "down" )
		{
			# load in memory the list
			$error = &setBLRunList( $list );
		}
		if ( !$error )
		{
			&zenlog( "Creating rules for the list $list and farm $farm.", "info", "IPDS" );
			$error = &setBLCreateRule( $farm, $list );
		}
	}

	return $error;
}

=begin nd
Function: runBLStop

	Stop the runtime of a blacklist rule and link with a farm that are using this rule.

Parameters:
	Rule - Rule name
	Farmname - Farm name

Returns:
	integer - 0 on success or other value on failure

=cut

sub runBLStop
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $rule, $farm ) = @_;

	&setBLDeleteRule( $farm, $rule );

	if ( !&getBLListNoUsed( $rule ) )
	{
		if ( &getBLIpsetStatus( $rule ) eq 'up' )
		{
			&setBLDestroyList( $rule );
		}
	}
}

=begin nd
Function: initBLModule

	Create configuration files and run all needed commands requested to blacklist module

Parameters:
	None - .

Returns:
	None - .

=cut

sub initBLModule
{
	my $blacklistsConf = &getGlobalConfiguration( 'blacklistsConf' );
	my $touch          = &getGlobalConfiguration( 'touch' );
	my $blacklistsPath = &getGlobalConfiguration( 'blacklistsPath' );

	# blacklists
	if ( !-d $blacklistsPath )
	{
		system ( &getGlobalConfiguration( 'mkdir' ) . " -p $blacklistsPath" );
		&zenlog( "Created $blacklistsPath directory." );
	}

	# create list config if doesn't exist
	if ( !-e $blacklistsConf )
	{
		system ( "$touch $blacklistsConf" );
		&zenlog( "Created $blacklistsConf file." );
	}
}

1;
