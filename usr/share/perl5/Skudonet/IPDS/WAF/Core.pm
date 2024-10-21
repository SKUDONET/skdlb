#!/usr/bin/perl
###############################################################################
#
#    Skudonet Software License
#    This file is part of the Skudonet Load Balancer software package.
#
#    Copyright (C) 2014-today SKUDONET SL, Sevilla (Spain)
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
use warnings;

use Skudonet::Core;

my $configdir  = &getGlobalConfiguration( 'configdir' );
my $wafConfDir = &getGlobalConfiguration( 'wafConfDir' );
my $wafSetDir  = &getGlobalConfiguration( 'wafSetDir' );

sub getWAFDir
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	return $wafConfDir;
}

=begin nd
Function: getWAFSetDir

	It returns the WAF configruation directory.

Parameters:
	None - .

Returns:
	String - It is the path.

=cut

sub getWAFSetDir
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	return $wafSetDir;
}

=begin nd
Function: getWAFSetFile

	It returns the configuration file for a set.

Parameters:
	Set - It is the set name.

Returns:
	String - It is the path.

=cut

sub getWAFSetFile
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $set = shift;
	return "$wafSetDir/${set}.conf";
}

=begin nd
Function: getWAFSetByFile

	It returns the set name for a configuration file.

Parameters:
	set_filename - It is the configuration filename.

Returns:
	String - It is the Set name

=cut

sub getWAFSetByFile
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $set_filename = shift;
	my $set_name;

	require Skudonet::Validate;
	my $waf_file_format = &getValidFormat( 'waf_file' );

	if ( $set_filename =~ /^($waf_file_format)\.conf$/ )
	{
		$set_name = $1;
	}
	return $set_name;
}

=begin nd
Function: getWAFSetStructConf

	It returns a object with the common configuration for a WAF set.

Parameters:
	none - .

Returns:
	Hash ref - It is a object with the configuration.

	The possible keys and values are:
		audit: on, off or RelevantOnly;
		process_request_body: true or false;
		process_response_body: true or false;
		request_body_limit: a interger;
		status: on, off, DetectionOnly;
		disable_rules: it is an array of integers, each integer is a rule id;
		default_action: pass, allow, deny or redirect:url;
		default_log: true, false or blank;
		default_phase: 1-5;

=cut

sub getWAFSetStructConf
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $set_ref = {
			   process_request_body  => 'true',     # SecRequestBodyAccess on|off
			   process_response_body => 'false',    # SecResponseBodyAccess on|off
			   request_body_limit    => 0,          # SecRequestBodyNoFilesLimit SIZE
			   status                => 'false',    # SecRuleEngine on|off|DetectionOnly
			   default_action        => 'pass',
			   default_log           => 'true',
			   default_phase         => 2,
	};
	return $set_ref;
}

=begin nd
Function: listWAFSet

	It returns all existing WAF sets in the system.

Parameters:
	none - .

Returns:
	Array - It is a list of set names.

=cut

sub listWAFSet
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my @listSet = ();

	opendir ( my $fd, $wafSetDir ) or return @listSet;
	@listSet = readdir ( $fd );
	@listSet = grep ( !/^\./, @listSet );
	closedir $fd;
	@listSet = grep ( s/\.conf$//, @listSet );

	return @listSet;
}

=begin nd
Function: existWAFSet

	It checks if a WAF set already exists in the system.

Parameters:
	Set - It is the set name.

Returns:
	Integer - It returns 1 if the set already exists or 0 if it is not exist

=cut

sub existWAFSet
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $set = shift;
	return ( grep ( /^$set$/, &listWAFSet() ) ) ? 1 : 0;
}

sub getWAFSetStatus
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $set = shift;

	my $file = &getWAFSetFile( $set );
	my $find;

	# looking for the "SecRuleEngine" directive
	require Skudonet::Lock;
	my $fh = &openlock( $file, 'r' );
	if ( $fh )
	{
		$find = grep ( /SecRuleEngine\s+(on|DetectionOnly)/, <$fh> );
		close $fh;
	}

	return ( $find ) ? "up" : "down";
}

=begin nd
Function: listWAFByFarm

	List all WAF sets that are applied to a farm.

Parameters:
	Farm - It is the farm id.

Returns:
	Array - It is a list with the set names.

=cut

sub listWAFByFarm
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farm  = shift;
	my @rules = ();

	require Skudonet::Farm::Core;
	require Skudonet::Lock;

	my $configdir = &getGlobalConfiguration( 'configdir' );
	my $farm_file = &getFarmFile( $farm );

	my $fh = &openlock( "$configdir/$farm_file", 'r' );
	@rules =
	  grep ( s/^[\s#]*WafRules\s+\"\Q$wafSetDir\E\/([^\/]+).conf\"$/$1/, <$fh> );
	chomp @rules;
	close $fh;

	return @rules;
}

=begin nd
Function: listWAFBySet

	It list all farms where a WAF set is applied.

Parameters:
	Set - It is the set name.

Returns:
	Array - It is a list with farm names.

=cut

sub listWAFBySet
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $set   = shift;
	my @farms = ();
	my $farm_file;
	my $fh;
	my $find;

	require Skudonet::Farm::Core;
	require Skudonet::Lock;

	my $confdir   = &getGlobalConfiguration( 'configdir' );
	my $set_file  = &getWAFSetFile( $set );
	my @httpfarms = &getFarmsByType( 'http' );
	push @httpfarms, &getFarmsByType( 'https' );

	foreach my $farm ( @httpfarms )
	{
		$farm_file = &getFarmFile( $farm );
		$fh = &openlock( "$confdir/$farm_file", 'r' );

		$find = grep ( /WafRules\s+"$set_file"/, <$fh> );
		close $fh;

		push @farms, $farm if $find;
	}

	return @farms;
}

=begin nd
Function: getIPDSWAFRules

	Gather all the IPDS WAF rules

Parameters:
	none

Returns:
	scalar - array reference of hashes in the form of ('name', 'rule', 'type')

=cut

sub getIPDSWAFRules
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	require Config::Tiny;

	my @rules = ();

	foreach my $ru ( sort &listWAFSet() )
	{
		push @rules,
		  {
			'name'   => $ru,
			'rule'   => 'waf',
			'status' => &getWAFSetStatus( $ru ),
		  };
	}

	return \@rules;
}

=begin nd
Function: getIPDSWAFFarmRules

	Gather all the IPDS rules applied to a given farm

Parameters:
	farmName - farm name to get its IPDS rules

Returns:
	scalar - array reference of array reference ('waf') hashes in the form of ('name', 'rule', 'type')

=cut

sub getIPDSWAFFarmRules
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farmName = shift;

	require Config::Tiny;

	my $rules;

	$rules = { waf => [] };

	# add waf if the rule is HTTP
	if ( &getFarmType( $farmName ) =~ /http/ )
	{
		require Skudonet::Farm::Core;
		foreach my $ru ( &listWAFByFarm( $farmName ) )
		{
			push @{ $rules->{ waf } },
			  { 'name' => $ru, 'status' => &getWAFSetStatus( $ru ) };
		}
	}

	return $rules;
}

1;

