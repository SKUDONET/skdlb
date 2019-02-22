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

use Zevenet::Farm::Base;
include 'Zevenet::IPDS::DoS::Runtime';

=begin nd
Function: runDOSStartModule

	Boot all DoS rules-

Parameters:

Returns:
	== 0	- Successful
	!= 0	- Number of rules didn't boot
=cut

sub runDOSStartModule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	include 'Zevenet::IPDS::DoS::Config';

	my $confFile = &getGlobalConfiguration( 'dosConf' );
	my $output;

	&zenlog( "Booting dos system... ", "info", "IPDS" );
	&initDOSModule();

	my $fileHandle = Config::Tiny->read( $confFile );
	foreach my $ruleName ( keys %{ $fileHandle } )
	{
		# It is disabled
		next if ( &getDOSStatusRule( $ruleName ) eq "down" );

		if ( $fileHandle->{ $ruleName }->{ 'type' } eq 'farm' )
		{
			my $farmList = $fileHandle->{ $ruleName }->{ 'farms' };
			my @farms = split ( ' ', $farmList );
			foreach my $farmName ( @farms )
			{
				# run rules of running farms
				if ( &getFarmBootStatus( $farmName ) eq 'up' )
				{
					if ( &runDOSStart( $ruleName, $farmName ) != 0 )
					{
						&zenlog( "Error running the rule $ruleName in the farm $farmName.",
								 "error", "IPDS" );
					}
				}
			}
		}
		else
		{
			if ( &runDOSStart( $ruleName ) != 0 )
			{
				&zenlog( "Error, running the rule $ruleName.", "error", "IPDS" );
			}
		}
	}

	# This block is a bugfix. When ssh_brute_force rule doesn't show the port
	if ( !&setDOSParam( 'ssh_brute_force', 'port' ) )
	{
		include 'Zevenet::System::SSH';

		my $sshconf = &getSsh();
		my $port    = $sshconf->{ 'port' };
		&setDOSParam( 'ssh_brute_force', 'port', $port );
	}

	return $output;
}

=begin nd
        Function: runDOStopModule

        Stop all DoS rules

        Parameters:

        Returns:
			== 0	- Successful
            != 0	- Number of rules didn't Stop

=cut

sub runDOStopModule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $output   = 0;
	my $confFile = &getGlobalConfiguration( 'dosConf' );

	if ( -e $confFile )
	{
		my $fileHandle = Config::Tiny->read( $confFile );
		foreach my $rule ( keys %{ $fileHandle } )
		{
			# Applied to farm
			if ( $fileHandle->{ $rule }->{ 'type' } eq "farm" )
			{
				if ( $fileHandle->{ $rule }->{ 'farms' } )
				{
					my $farmList = $fileHandle->{ $rule }->{ 'farms' };
					my @farms = split ( ' ', $farmList );
					foreach my $farmName ( @farms )
					{
						$output |= &runDOSStop( $rule, $farmName );
					}
				}
			}

			# Applied to balancer
			elsif ( $fileHandle->{ $rule }->{ 'type' } eq 'system' )
			{
				if ( $fileHandle->{ $rule }->{ 'status' } eq 'up' )
				{
					$output |= &runDOSStop( $rule );
				}
			}
		}
	}
	return $output;
}

=begin nd
Function: runDOSStartByRule

	Start the runtime of a DOS rule and link with all farm that are using this rule.

Parameters:
	Rule - Rule name

Returns:
	integer - 0 on success or other value on failure

=cut

sub runDOSStartByRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $ruleName ) = @_;
	my $error = 0;

	return 0 if ( &getDOSStatusRule( $ruleName ) eq 'down' );

	if ( &getDOSParam( $ruleName, 'type' ) eq "system" )
	{
		&runDOSStart( $ruleName );
	}
	else
	{
		my @farms = @{ &getDOSParam( $ruleName, 'farms' ) };
		foreach my $farmName ( @farms )
		{
			# run rules of running farms
			if ( &getFarmBootStatus( $farmName ) eq 'up' )
			{
				if ( &runDOSStart( $ruleName, $farmName ) != 0 )
				{
					&zenlog( "Error running the rule $ruleName in the farm $farmName.",
							 "error", "IPDS" );
				}
			}
		}
	}

	return $error;
}

=begin nd
Function: runDOSStopByRule

	Stop the runtime of a DOS rule  and unlink with all farm that are using this rule.

Parameters:
	Rule - Rule name

Returns:
	integer - 0 on success or other value on failure

=cut

sub runDOSStopByRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $ruleName ) = @_;
	my $error = 0;

	if ( &getDOSParam( $ruleName, 'type' ) eq "system" )
	{
		&setDOSStopRule( $ruleName );
	}
	else
	{
		foreach my $farmName ( @{ &getDOSParam( $ruleName, 'farms' ) } )
		{
			if ( &setDOSStopRule( $ruleName, $farmName ) != 0 )
			{
				&zenlog( "Error stopping the rule $ruleName in the farm $farmName.",
						 "error", "IPDS" );
			}
		}
	}

	return $error;
}

=begin nd
Function: runDOSRestartByRule

	Restart the runtime of a DOS rule.
	It is useful when a the rule will be modified.

Parameters:
	Rule - Rule name

Returns:
	integer - 0 on success or other value on failure

=cut

sub runDOSRestartByRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $rule ) = @_;

	my $error = &runDOSStopByRule( $rule );

	if ( !$error )
	{
		$error = &runDOSStartByRule( $rule );
	}

	return $error;
}

=begin nd
Function: runDOSStart

	Start the runtime of a DOS rule and link with a farm that are using this rule.

Parameters:
	Rule - Rule name
	Farmanme - Farm name

Returns:
	integer - 0 on success or other value on failure

=cut

sub runDOSStart
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $rule, $farm ) = @_;
	my $error;

	if ( &getDOSStatusRule( $rule ) eq 'up' )
	{
		$error = &setDOSRunRule( $rule, $farm );
	}
	return $error;
}

=begin nd
Function: runDOSStop

	Stop the runtime of a DOS rule and link with a farm that are using this rule.

Parameters:
	Rule - Rule name
	Farmname - Farm name

Returns:
	integer - 0 on success or other value on failure

=cut

sub runDOSStop
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $rule, $farm ) = @_;
	my $error = &setDOSStopRule( $rule, $farm );
	return $error;
}

1;
