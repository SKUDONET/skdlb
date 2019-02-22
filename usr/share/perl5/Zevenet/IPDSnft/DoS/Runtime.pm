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

use Zevenet::Nft;
include 'Zevenet::IPDS::Core';
include 'Zevenet::IPDS::DoS::Core';

=begin nd
Function: setDOSRunRule

	Wrapper that get the farm values and launch the necessary function to
	run the rule

Parameters:
	rule	 - Rule name
	farmname - farm name

Returns:
	Integer - Error code: 0 on success or other value on failure

=cut

sub setDOSRunRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $ruleName = shift;
	my $farmName = shift;

	include 'Zevenet::IPDS::Core';

	my $output = -2;
	my $value  = 0;

	return 1 if ( $farmName eq "" );

	my $rule = &getDOSParam( $ruleName, "rule" );

	if ( $rule eq 'sshbruteforce' )
	{
		return 0;
	}
	elsif ( $rule eq 'dropicmp' )
	{
		return 0;
	}
	elsif ( $rule eq 'limitconns' )
	{
		$value = &getDOSParam( $ruleName, 'limit_conns' );
		$output = &setIPDSFarmParam( 'limitconns', $value, $farmName );
	}
	elsif ( $rule eq 'limitsec' )
	{
		$value = &getDOSParam( $ruleName, 'limit' );
		$output = &setIPDSFarmParam( 'limitsec', $value, $farmName );
		$value = &getDOSParam( $ruleName, 'limit_burst' );
		$output = &setIPDSFarmParam( 'limitsecbrst', $value, $farmName ) || $output;
	}
	elsif ( $rule eq 'limitrst' )
	{
		$value = &getDOSParam( $ruleName, 'limit' );
		$output = &setIPDSFarmParam( 'limitrst', $value, $farmName );
		$value = &getDOSParam( $ruleName, 'limit_burst' );
		$output = &setIPDSFarmParam( 'limitrstbrst', $value, $farmName ) || $output;
	}
	elsif ( $rule eq 'bogustcpflags' )
	{
		$output = &setIPDSFarmParam( 'bogustcpflags', 'on', $farmName );
	}
	else
	{
		&zenlog( "Unknown type rule: $rule", "warning", "IPDS" );
		return -1;
	}

	return $output;
}

=begin nd
Function: setDOSStopRule

	Remove RBL rules per farm

Parameters:
	ruleName	- id that indetify a rule, ( rule = 'farms' to remove rules from farm )
	farmname 	- farm name

Returns:
	Integer - Error code, 0 on success or other value on failure

=cut

sub setDOSStopRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $ruleName, $farmName ) = @_;
	my $output;

	return 1 if ( $farmName eq "" );

	my $rule = &getDOSParam( $ruleName, "rule" );

	include 'Zevenet::IPDS::Core';

	if ( $rule eq 'sshbruteforce' )
	{
		#TODO	&setDOSSshBruteForceRule()
	}
	if ( $rule eq 'dropicmp' )
	{
		#TODO	setDOSDropIcmpRule()
	}
	elsif ( $rule eq 'limitconns' )
	{
		$output = &setIPDSFarmParam( 'limitconns', '0', $farmName );
	}
	elsif ( $rule eq 'limitsec' )
	{
		$output = &setIPDSFarmParam( 'limitsec', '0', $farmName );
		$output = &setIPDSFarmParam( 'limitsecbrst', '0', $farmName ) || $output;
	}
	elsif ( $rule eq 'limitrst' )
	{
		$output = &setIPDSFarmParam( 'limitrst', '0', $farmName );
		$output = &setIPDSFarmParam( 'limitrstbrst', '0', $farmName ) || $output;
	}
	elsif ( $rule eq 'bogustcpflags' )
	{
		$output = &setIPDSFarmParam( 'bogustcpflags', 'off', $farmName );
	}
	else
	{
		&zenlog( "Unknown type rule: $rule", "warning", "IPDS" );
		return -1;
	}

	return $output;
}

=begin nd
Function: setDOSApplyRule

	Enable a DoS rule for rules of farm or system type
	Farm type: Link a DoS rule with a farm
	System type: Put rule in up status

Parameters:
	rule	- Rule name
	farmname - Farm name

Returns:
	Integer - Error code. 0 on succes or other value on failure.

=cut

sub setDOSApplyRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $ruleName, $farmName ) = @_;

	require Zevenet::Farm::Base;
	require Config::Tiny;

	my $output;
	my $confFile = &getGlobalConfiguration( 'dosConf' );
	my $rule     = &getDOSParam( $ruleName, 'rule' );
	my $protocol = &getFarmProto( $farmName );

	my $lock       = &setDOSLockConfigFile();
	my $fileHandle = Config::Tiny->read( $confFile );
	my $farmList   = $fileHandle->{ $ruleName }->{ 'farms' };
	if ( $farmList !~ /(^| )$farmName( |$)/ )
	{
		$fileHandle = Config::Tiny->read( $confFile );
		$fileHandle->{ $ruleName }->{ 'farms' } = "$farmList $farmName";
		$fileHandle->write( $confFile );
		close $lock;
	}
	else
	{
		close $lock;
		&zenlog( "Rule $ruleName already is applied", "warning", "IPDS" );
		return 0;
	}

	# dos system rules
	if ( &getDOSParam( $ruleName, 'status' ) eq "up" )
	{
		if ( &getFarmBootStatus( $farmName ) eq "up" || !$farmName )
		{
			$output = &setDOSRunRule( $ruleName, $farmName );
			if ( $output )
			{
				&zenlog( "Error, running rule $ruleName", "error", "IPDS" );
			}
		}
	}

	return $output;
}

=begin nd

Function: setDOSUnsetRule

	Enable a DoS rule for rules of farm or system type
	Farm type: Unlink a DoS rule with a farm
	System type: Put rule in down status

Parameters:
	rule	- Rule name
	farmname - Farm name

Returns:
	Integer - Error code. 0 on succes or other value on failure.

=cut

sub setDOSUnsetRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $ruleName, $farmName ) = @_;

	require Config::Tiny;

	my $confFile = &getGlobalConfiguration( 'dosConf' );
	my $output = &setDOSStopRule( $ruleName, $farmName );

	if ( !$output )
	{
		my $fileHandle = Config::Tiny->read( $confFile );
		my $lock       = &setDOSLockConfigFile();
		$fileHandle->{ $ruleName }->{ 'farms' } =~ s/(^| )$farmName( |$)/ /;

		# put down if there is not more farms applied
		if ( $fileHandle->{ $ruleName }->{ 'farms' } !~ /\w/ )
		{
			$fileHandle->{ $ruleName }->{ 'status' } =~ "down";
		}
		$fileHandle->write( $confFile );

		close $lock;
	}

	return $output;
}

1;
