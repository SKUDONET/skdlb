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

# rbl configuration path
my $rblPath              = &getGlobalConfiguration( 'configdir' ) . "/ipds/rbl";
my $rblConfigFile        = "$rblPath/rbl.conf";
my $preloadedDomainsFile = "$rblPath/preloaded_domains.conf";
my $userDomainsFile      = "$rblPath/user_domains.conf";

=begin nd
Function: getRBLFarm

	Return all farms where the rule is applied

Parameters:
	Rule - Rule name

Returns:
	Array ref - List with all farms where this rule is applied

=cut

sub getRBLFarm
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $rule ) = @_;

	return &getRBLObjectRuleParam( $rule, 'farms' );
}

=begin nd
Function: getRBLExists

	Get if a RBL rule with this name exists

Parameters:
	Rule - Rule name

Returns:
	Integer - 1 if it exists or 0 if it doesn't exist

=cut

sub getRBLExists
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $rule   = shift;
	my $output = 0;

	$output = 1 if ( grep ( /^$rule$/, &getRBLRuleList() ) );

	return $output;
}

=begin nd
Function: getRBLRuleList

	Get an array with all RBL rule names

Parameters:

Returns:
	Array - RBL name list

=cut

sub getRBLRuleList
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	require Config::Tiny;
	my $fileHandle = Config::Tiny->read( $rblConfigFile );

	my @rules = keys %{ $fileHandle };

	return @rules;
}

=begin nd
Function: getRBLObjectRule

	Get parameters of a RBL rule

Parameters:

Returns:
	hash ref - Struct with the RBL rule data

	{
		domains = [ domain1, domain2... ],
		farms = [ farm1, farm2... ],
		name = rule_name,
		nf_queue_number	= queue_number,			# this parameter is transparent to user
		cache_size	= cache_size,
		cache_time	= cache_time,
		queue_size	= queue_size,
		threadmax	= thread_maximum,
		local_traffic	= local_traffic,
	}

=cut

sub getRBLObjectRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $rule = shift;

	require Config::Tiny;
	my $fileHandle = Config::Tiny->read( $rblConfigFile );

	my $output  = $fileHandle->{ $rule };
	my @domains = split ( ' ', $fileHandle->{ $rule }->{ 'domains' } );
	my @farms   = split ( ' ', $fileHandle->{ $rule }->{ 'farms' } );

	$output->{ 'domains' } = \@domains;
	$output->{ 'farms' }   = \@farms;

	return $output;
}

=begin nd
Function: getRBLObjectRuleParam

	Get the value of a parameter (only one).
	The available parameters are: "name" is the RBL rule name, "cache_size" is the size of the cache, "cache_time" is the time that a source is blocked
	by the cache, "nf_queue_number" is the queue where the rule is applied, "domains" are the domains that the RBL rule does requests and "farms" are the farms
	where the RBL rule is applied.

Parameters:
	Rule - Rule name
	Key - Requested parameter

Returns:
	String - if the requested parameter is "name"
	Integer - if the requested parameter is "cache_size", "cache_time", "queue_size", "threadmax" or "nf_queue_number"
	yes/no - if the requested parameter is "local_traffic"
	Array ref - if the requested parameter is "domains" of "farms"

=cut

sub getRBLObjectRuleParam
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $rule = shift;
	my $key  = shift;

	my $obj = &getRBLObjectRule( $rule );

	return $obj->{ $key };
}

=begin nd
Function: getRBLRunningFarmList

	Return a list with all farms that are using currently this rule.

Parameters:
	Rule - Rule name

Returns:
	Array - List of farm names

=cut

sub getRBLRunningFarmList
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $rule = shift;

	require Zevenet::Validate;
	include 'Zevenet::IPDS::Core';

	#TODO: implement this

	my @farms;

	return @farms;
}

=begin nd
Function: getRBLUserDomains

	Get a list with the domains added by the user

Parameters:

Returns:
	Array ref - Domain list

=cut

sub getRBLUserDomains
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my @domains;

	require Tie::File;

	tie my @list, 'Tie::File', $userDomainsFile;
	@domains = @list;
	untie @list;

	return \@domains;
}

=begin nd
Function: getRBLPreloadedDomains

	Get a list with the preloaded domains

Parameters:

Returns:
	Array ref - Domain list

=cut

sub getRBLPreloadedDomains
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my @domains;

	require Tie::File;

	tie my @list, 'Tie::File', $preloadedDomainsFile;
	@domains = @list;
	untie @list;

	return \@domains;
}

=begin nd
Function: getRBLDomains

	Get a list with all existing domains.

Parameters:

Returns:
	Array ref - Domain list

=cut

sub getRBLDomains
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my @domains;

	push @domains, @{ &getRBLPreloadedDomains };
	push @domains, @{ &getRBLUserDomains };

	return \@domains;
}

=begin nd
Function: getRBLPacketblPid

	Get the packetbl pid file of a RBL rule

Parameters:
	String - Rule name

Returns:
	Integer - Return the packetbl pid

=cut

sub getRBLPacketblPid
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $rule = shift;
	my $pid;

	my $ps      = &getGlobalConfiguration( 'ps' );
	my @process = `$ps x`;
	if ( @process = grep ( /\/packetbl_$rule\.conf/, @process ) )
	{
		$pid = $1 if ( $process[0] =~ /^\s*(\d+)\s/ );
	}

	return $pid;
}

=begin nd
Function: getRBLPacketblConfig

	Get the configuration file of a RBL rule

Parameters:
	String - Rule name

Returns:
	String - Return a chain with packetbl configuration file of a RBL rule

=cut

sub getRBLPacketblConfig
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $rule = shift;
	return "$rblPath/packetbl_$rule.conf";
}

=begin nd
Function: getRBLZapi

	Create a array with zapi output formats of all rbl rules

Parameters:

Returns:
	Array ref -

	{
		"cache_size" : 8192,
		"cache_time" : 3600,
		"domains" : [
			"ssh.rbl.zevenet.com",
			"sip.rbl.zevenet.com"
		],
		"farms" : [
			"cookiefarm"
		],
		"local_traffic" : "false",
		"log_level" : 4,
		"name" : "protection_ssh",
		"only_logging" : "false",
		"queue_size" : 64538,
		"status" : "down",
		"threadmax" : 700
	}

=cut

sub getRBLZapi
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my @all_rules;

	foreach my $rule ( sort &getRBLRuleList )
	{
		my $output = &getRBLZapiRule( $rule );

		push @all_rules, $output;
	}

	return \@all_rules;
}

=begin nd
Function: getRBLStatusRule

	Check if a RBL rule is running. Check packetbl pid file.

Parameters:
	String - Rule name

Returns:
	String - "up" if the rule is running or "down" if it is not running

=cut

sub getRBLStatusRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $rule = shift;

	my $status = "down";

	if ( &getRBLPacketblPid( $rule ) )
	{
		$status = "up";
	}

	return $status;
}

=begin nd
Function: getRBLZapiRule

	Create zapi output formats of a rbl rule for ZAPI

Parameters:
	Rule - rule name

Returns:
	Hash ref - Hash with the rbl parameters

	{
		"cache_size" : 8192,
		"cache_time" : 3600,
		"domains" : [
			"ssh.rbl.zevenet.com",
			"sip.rbl.zevenet.com"
		],
		"farms" : [
			"cookiefarm"
		],
		"local_traffic" : "false",
		"log_level" : 4,
		"name" : "protection_ssh",
		"only_logging" : "false",
		"queue_size" : 64538,
		"status" : "down",
		"threadmax" : 700
	}

=cut

sub getRBLZapiRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $rule = shift;

	require Config::Tiny;

	my $fileHandle = Config::Tiny->read( $rblConfigFile );

	my $output = $fileHandle->{ $rule };

	my @domains = split ( ' ', $fileHandle->{ $rule }->{ 'domains' } );
	my @farms   = split ( ' ', $fileHandle->{ $rule }->{ 'farms' } );

	my @format_domains;
	foreach my $domain ( @domains )
	{
		push @format_domains, { 'domain' => $domain };
	}

	$output->{ 'domains' } = \@format_domains;
	$output->{ 'farms' }   = \@farms;

	$output->{ 'name' } = $rule;

	if ( $output->{ 'local_traffic' } eq 'yes' )
	{
		$output->{ 'local_traffic' } = "true";
	}
	else
	{
		$output->{ 'local_traffic' } = "false";
	}
	if ( $output->{ 'only_logging' } eq 'yes' )
	{
		$output->{ 'only_logging' } = "true";
	}
	else
	{
		$output->{ 'only_logging' } = "false";
	}

	foreach my $key ( keys %{ $output } )
	{
		$output->{ $key } += 0 if ( $output->{ $key } =~ /^\d+$/ );
	}

	delete $output->{ 'nf_queue_number' };

	return $output;
}

sub setRBLLockConfigFile
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	require Zevenet::Lock;

	my $lockfile = "/tmp/rbl.lock";

	return &openlock( $lockfile, 'w' );
}

1;
