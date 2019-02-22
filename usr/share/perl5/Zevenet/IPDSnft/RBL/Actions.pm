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
include 'Zevenet::IPDS::RBL::Runtime';

=begin nd
Function: runRBLStartModule

	Boot the RBL module

Parameters:

Returns:

=cut

# this function has to create the tmp directory /tmp/IPDS/<module> and start all rules applied to UP farms.
# when start a module load the blocked sources from logs
sub runRBLStartModule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	include 'Zevenet::IPDS::RBL::Config';

	# create config directory if it doesn't exist and config file
	my $error = &initRBLModule();

	# Run all rules
	foreach my $rule ( &getRBLRuleList() )
	{
		&runRBLStartByRule( $rule );
	}
}

=begin nd
Function: runRBLStopModule

	Stop the module

Parameters:

Returns:

=cut

# this function has to remove the tmp directory /tmp/IPDS/<module> and stop all rules in /tmp/IPDS/<module> directory
sub runRBLStopModule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	# stop all rules
	foreach my $rule ( &getRBLRuleList() )
	{
		&runRBLStopByRule( $rule );
	}
}

=begin nd
Function: runRBLStartByRule

	Start the runtime of a RBL rule and link with all farm that are using this rule.

Parameters:
	Rule - Rule name

Returns:
	integer - 0 on success or other value on failure

=cut

sub runRBLStartByRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $rule ) = @_;

	my $error = 0;
	my @farms = @{ &getRBLObjectRuleParam( $rule, 'farms' ) };

	if ( !@farms )
	{
		return -1;
	}

	# Check if the rule is disabled
	if ( &getRBLObjectRuleParam( $rule, 'status' ) eq 'down' )
	{
		return 0;
	}

	my $flag = 0;
	foreach my $farmname ( @farms )
	{
		&runRBLStart( $rule, $farmname );
	}

	return $error;
}

=begin nd
Function: runRBLStopByRule

	Stop the runtime of a RBL rule  and unlink with all farm that are using this rule.

Parameters:
	Rule - Rule name

Returns:
	integer - 0 on success or other value on failure

=cut

sub runRBLStopByRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $rule ) = @_;
	my $error = 0;

	foreach my $farmname ( @{ &getRBLObjectRuleParam( $rule, 'farms' ) } )
	{
		$error = &runRBLStop( $rule, $farmname );
	}

	return $error;
}

=begin nd
Function: runRBLRestartByRule

	Restart the runtime of a RBL rule.
	It is useful when a the rule will be modified.

Parameters:
	Rule - Rule name

Returns:
	integer - 0 on success or other value on failure

=cut

sub runRBLRestartByRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $rule ) = @_;

	my $error = &runRBLStopByRule( $rule );

	if ( !$error )
	{
		$error = &runRBLStartByRule( $rule );
	}

	return $error;
}

=begin nd
Function: runRBLStart

	Start the runtime of a RBL rule and link with a farm that are using this rule.

Parameters:
	Rule - Rule name
	Farmanme - Farm name

Returns:
	integer - 0 on success or other value on failure

=cut

sub runRBLStart
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $rule, $farm ) = @_;
	my $error = 0;

	require Zevenet::Farm::Base;

	# Check if the rule is disabled
	if ( &getRBLObjectRuleParam( $rule, 'status' ) eq 'down' )
	{
		return 0;
	}

	# to start a rule the farm has to be up
	if ( &getFarmBootStatus( $farm ) ne 'up' )
	{
		return 0;
	}

	# not run if the farm is not applied to the rule
	if ( !grep ( /^$farm$/, @{ &getRBLObjectRuleParam( $rule, 'farms' ) } ) )
	{
		return -1;
	}

	# to start a RBL rule it is necessary that the rule has almost one domain
	if ( !@{ &getRBLObjectRuleParam( $rule, 'domains' ) } )
	{
		return -1;
	}

	# if the process is not running, start it
	if ( &getRBLStatusRule( $rule ) eq "down" )
	{
		$error = &runRBLStartPacketbl( $rule );
	}

	# if all is success link with the farm
	if ( !$error )
	{
		$error = &runRBLFarmRule( $rule, $farm, 'add' );
	}

	return $error;
}

=begin nd
Function: runRBLStop

	Stop the runtime of a RBL rule and link with a farm that are using this rule.

Parameters:
	Rule - Rule name
	Farmname - Farm name

Returns:
	integer - 0 on success or other value on failure

=cut

sub runRBLStop
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $rule, $farm ) = @_;
	my $error = 0;

	require Zevenet::Farm::Base;

	&runRBLFarmRule( $rule, $farm, 'delete' );

	# if are not another farm using this rule, the rule is stopped
	if ( !&getRBLRunningFarmList( $rule ) )
	{
		&runRBLStopPacketbl( $rule );
	}

	return $error;
}

=begin nd
Function: runRBLRestart

	Restart the runtime of a RBL rule with a farm.

Parameters:
	Rule - Rule name
	Farmname - Farm name

Returns:
	integer - 0 on success or other value on failure

=cut

sub runRBLRestart
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $rule, $farm ) = @_;

	my $error = &runRBLStop( $rule, $farm );

	if ( !$error )
	{
		$error = &runRBLStart( $rule, $farm );
	}

	return $error;
}

1;
