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
use Config::Tiny;
use Zevenet::Core;
use Zevenet::Debug;

=begin nd
Function: getDOSExists

	Get if a rule already exists

Parameters:
	Farmname -  Farm name

Returns:
	Integer - return 1 if the rule already exists or 0 if it is not exist

=cut

sub getDOSExists
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $name = shift;

	my $output     = 0;
	my $confFile   = &getGlobalConfiguration( 'dosConf' );
	my $fileHandle = Config::Tiny->read( $confFile );

	$output = 1 if ( exists $fileHandle->{ $name } );

	return $output;
}

=begin nd
Function: getDOSParam

	Get information about a DoS rule saved in the config file.
	If it is indicated a parameter, only that parameter will be returned,
	else a hash with all parameters will be returned.

	These are the available values depend on the DoS type rule

	bogustcpflags: farms, type, name, rule
	limitconns: farms, limit_conns, type, name, rule
	limitrst: farms, limit, limit_burst, type, name, rule
	limitsec: farms, limit, limit_burst, type, name, rule
	sshbruteforce: status, hits, port, time, type, name, rule

	type is where the rule is applied: "farm" or "system"
	rule identifies the type of rule: sshbruteforce, limitsec, limitconns...


Parameters:
	Rule 	- DoS rule
	Parameter - Parameter of the rule. The possible values are:

Returns:
	scalar or hash - return scalar when it is request a unique parameter,
		return a hash when no parameter is requested

=cut

sub getDOSParam
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $ruleName = shift;
	my $param    = shift;

	my $output;
	my $confFile   = &getGlobalConfiguration( 'dosConf' );
	my $fileHandle = Config::Tiny->read( $confFile );

	$output = $fileHandle->{ $ruleName }->{ $param };
	if ( $param eq 'farms' )
	{
		my @aux = split ( ' ', $output );
		$output = \@aux;
	}

	return $output;
}

=begin nd
	Function: getDOSLookForRule

	Look for a:
		- global name 				( key )
		- set of rules applied a farm 	( key, farmName )

	Parameters:
		key		 - id that indetify a rule
		farmName - farm name

	Returns:
		== 0	- don't find any rule
		@out	- Array with reference hashs
				- out[i]= {
						line  => num,
						table => string,
						chain => string
					  }
=cut

sub getDOSLookForRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $ruleName, $farmName ) = @_;

	require Zevenet::Validate;
	include 'Zevenet::IPDS::Core';

	my @output;

	return \@output;
}

=begin nd
Function: getDOSStatusRule

	Check if a DoS rule is applied

Parameters:
	String - Rule name

Returns:
	String - "up" if the rule is running or "down" if it is not running

=cut

sub getDOSStatusRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $rule = shift;

	# check system rules
	my $status = &getDOSParam( $rule, 'status' );
	$status = "down" if ( $status !~ /^(down|up)$/ );

	return $status;
}

=begin nd
Function: getDOSZapiRule

	Get a standard output of a rule object for the zapi

Parameters:
	String - Rule name

Returns:
	hash ref - The output depend on the rule

=cut

sub getDOSZapiRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $ruleName = shift;
	my $output;

	my $confFile   = &getGlobalConfiguration( 'dosConf' );
	my $fileHandle = Config::Tiny->read( $confFile );

	# get all params
	my %hash = %{ $fileHandle->{ $ruleName } };

	# return in integer format if this value is a number
	# It is neccessary for zapi
	foreach my $key ( keys %hash )
	{
		$hash{ $key } += 0 if ( $hash{ $key } =~ /^\d+$/ );
	}

	# replace farms string for a array reference
	if ( exists $fileHandle->{ $ruleName }->{ 'farms' } )
	{
		my @aux = split ( ' ', $fileHandle->{ $ruleName }->{ 'farms' } );
		$hash{ 'farms' } = \@aux;
	}

	$output = \%hash;

	return $output;
}

sub setDOSLockConfigFile
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	require Zevenet::Lock;

	my $lockfile = "/tmp/dos.lock";

	return &openlock( $lockfile, 'w' );
}

sub setDOSUnlockConfigFile
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $lock_fd = shift;

	close $lock_fd;
}

1;
