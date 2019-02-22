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

# rbl configuration path
my $rblPath              = &getGlobalConfiguration( 'configdir' ) . "/ipds/rbl";
my $rblConfigFile        = "$rblPath/rbl.conf";
my $preloadedDomainsFile = "$rblPath/preloaded_domains.conf";
my $userDomainsFile      = "$rblPath/user_domains.conf";

=begin nd
Function: initRBLModule

	This function creates the RBL directory and RBL config file if they are not exist.

Parameters:

Returns:
	none - .

=cut

sub initRBLModule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	if ( !-d $rblPath )
	{
		&logAndRun( &getGlobalConfiguration( 'mkdir' ) . " -p $rblPath" );
		&zenlog( "Created $rblPath directory." );
	}

	# create list config if doesn't exist
	if ( !-e $rblConfigFile )
	{
		&logAndRun( &getGlobalConfiguration( 'touch' ) . " $rblConfigFile" );
		&zenlog( "Created $rblConfigFile file." );
	}

	# create list config if doesn't exist
	if ( !-e $userDomainsFile )
	{
		&logAndRun( &getGlobalConfiguration( 'touch' ) . " $userDomainsFile" );
		&zenlog( "Created $userDomainsFile file." );
	}
}

=begin nd
Function: setRBLInitialParams

	This function return a struct used as template to create a RBL object

Parameters:

Returns:
	hash ref - Struct with default values for a rbl rule

=cut

sub getRBLInitialParams
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $initial = {

# save a list of farms split by space character. These farms are the farms where this rule is applied
		'farms' => '',

		# save a list of domains split by space character
		'domains' => '',

# this value is written with a nf_queue is assignate to this rule. The maximum nf_queue value is 256
		'nf_queue_number' => '',

		# Cache size, parameter "CacheSize"
		'cache_size' => 8192,

		# Cache time, parameter "CacheTTL"
		'cache_time' => 3600,

		# maximum number of packet in the queue
		'queue_size' => 64538,

# Log lvl, syslog log levels from 0 to 7: 0 Emergency, 1 Alert, 2 Critical, 3 Error, 4 Warning, 5 Notice, 6 Informational, or 7 Debug
		'log_level' => 5,

		# This mode logs the action but non blocking the packet
		'only_logging' => 'no',

		# maximum number of threads for packetbl
		'threadmax' => 0,

		# Scan local traffic
		'local_traffic' => 'no',

		# rule status
		'status' => 'down',
	};

	return $initial;
}

=begin nd
Function: addRBLCreateObjectRule

	Create a object through its configuration file

Parameters:
	Rule - Rule name

Returns:
	Integer - 0 on success or -1 on failure

=cut

sub addRBLCreateObjectRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $rule = shift;

	# check that the rule is not exist
	if ( &getRBLExists( $rule ) )
	{
		return -1;
	}

	# Get default parameters
	my $params = &getRBLInitialParams();

	# Add rule name
	$params->{ 'name' } = $rule;

	require Config::Tiny;

	my $lock       = &setRBLLockConfigFile();
	my $fileHandle = Config::Tiny->read( $rblConfigFile );
	$fileHandle->{ $rule } = $params;
	$fileHandle->write( $rblConfigFile );
	close $lock;

	&zenlog( "The RBL rule \"$rule\" was successfully created." );

	return 0;
}

=begin nd
Function: setRBLObjectRuleParam

	Set the value of a parameter (only one)

Parameters:
	Rule - Rule name
	Key - Parameter to set a value
	Value - Value for the parameter

Returns:
	Integer - 0 on success or -1 on failure

=cut

sub setRBLObjectRuleParam
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $name  = shift;
	my $key   = shift;
	my $value = shift;

	require Config::Tiny;

	my $lock       = &setRBLLockConfigFile();
	my $fileHandle = Config::Tiny->read( $rblConfigFile );

	my $action = "";

	# if command has a action, split it
	# key-action
	# possible actions are 'add' or 'delete'
	if ( $key =~ /(\w+)(?:-(\w+))?/ )
	{
		$key    = $1;
		$action = $2;
	}

	if ( 'add' eq $action )
	{
		if ( $fileHandle->{ $name }->{ $key } !~ /(^| )$value( |$)/ )
		{
			$fileHandle->{ $name }->{ $key } .= " $value";
		}
	}
	elsif ( 'del' eq $action )
	{
		$fileHandle->{ $name }->{ $key } =~ s/(^| )$value( |$)/ /;
	}
	else
	{
		$fileHandle->{ $name }->{ $key } = $value;
	}

	$fileHandle->write( $rblConfigFile );
	close $lock;

	return 0;
}

=begin nd
Function: addRBLDomains

	Get a list with the preloaded domains. Only it is possible to add a new domain of the user domain list

Parameters:
	Domain - String with a domain

Returns:
	none - .

=cut

sub addRBLDomains
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $new_domain = shift;

	require Zevenet::Lock;

	&ztielock( \my @domains, "$userDomainsFile" );
	push @domains, $new_domain;
	untie @domains;
}

=begin nd
Function: setRBLDomains

	Modify a domain of the domain list. Only it is possible to replace a domain of the user domain list

Parameters:
	Domain - Domain to remove from the list
	Domain_new - New domain for the list

Returns:
	none - .

=cut

sub setRBLDomains
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $domain     = shift;
	my $new_domain = shift;

	&delRBLDomains( $domain );
	&addRBLDomains( $new_domain );
}

=begin nd
Function: delRBLDomains

	Modify a domain of the domain list. Only it is possible to remove a domain of the user domain list

Parameters:
	Domain - Domain to remove from the list
	Domain_new - New domain for the list

Returns:
	Integer - Error code, 0 on success or -1 on failure.

=cut

sub delRBLDomains
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $domain = shift;

	require Zevenet::Lock;

	my $error = -1;
	my $it    = 0;

	&ztielock( \my @domains, "$userDomainsFile" );

	foreach my $item ( @domains )
	{
		if ( $item =~ /^$domain$/ )
		{
			splice @domains, $it, 1;
			$error = 0;
			last;
		}
		$it += 1;
	}
	untie @domains;

	return $error;
}

=begin nd
Function: addRBLCopyObjectRule

	Copy a object through its configuration file but deleting its associated farms

Parameters:
	Rule - Rule name

Returns:
	Integer - 0 on success or -1 on failure

=cut

sub addRBLCopyObjectRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $rule    = shift;
	my $newrule = shift;

	# check if the rule already exists
	if ( &getRBLExists( $newrule ) )
	{
		return -1;
	}

	# Get default parameters
	my $params = &getRBLObjectRule( $rule );

	# Add rule name
	$params->{ 'name' }            = $newrule;
	$params->{ 'farms' }           = '';
	$params->{ 'nf_queue_number' } = '';
	$params->{ 'domains' }         = join ( " ", @{ $params->{ 'domains' } } );

	require Config::Tiny;

	my $lock       = &setRBLLockConfigFile();
	my $fileHandle = Config::Tiny->read( $rblConfigFile );
	$fileHandle->{ $newrule } = $params;
	$fileHandle->write( $rblConfigFile );
	close $lock;

	return 0;
}

=begin nd
Function: addRBLFarm

	Associate a farm with a IPDS object, adding the farm to the configuration file of the rule. If the farm is up, apply the rule

Parameters:
	Farmname - Farm name
	Rule - Rule name

Returns:
	None - .

=cut

sub addRBLFarm
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farmname, $rule ) = @_;
	my $error;

	if ( &getRBLObjectRuleParam( $rule, 'status' ) ne 'up' )
	{
		return $error;
	}

	require Zevenet::Farm::Base;

	# if the farm is in UP status, apply the rule
	if ( &getFarmStatus( $farmname ) ne 'up' )
	{
		return $error;
	}

	# to start a RBL rule it is necessary that the rule has almost one domain
	if ( !@{ &getRBLObjectRuleParam( $rule, 'domains' ) } )
	{
		&zenlog( "RBL rule, $rule, was not started because doesn't have any domain." );
		return -1;
	}

	include 'Zevenet::IPDS::RBL::Runtime';

	# if rule is not running, start it
	if ( &getRBLStatusRule( $rule ) eq 'down' )
	{
		$error = &runRBLStartPacketbl( $rule );
	}

	$error = $error || &runRBLFarmRule( $rule, $farmname, 'add' );

	# Add to configuration file
	$error = $error || &setRBLObjectRuleParam( $rule, 'farms-add', $farmname );

	return $error;
}

=begin nd
Function: delRBLFarm

	Disassociate a farm from a IPDS object, removing the farm from the configuration file of the rule. If the farm is up, stop the rule

Parameters:
	Rule - Rule name
	Farmname - Farm name

Returns:
	None - .

=cut

sub delRBLFarm
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farmname, $rule ) = @_;
	my $error;

	include 'Zevenet::IPDS::RBL::Runtime';

	$error = &runRBLFarmRule( $rule, $farmname, 'delete' );

	# if another farm is not using this rule, the rule is stopped
	if ( !$error && !&getRBLRunningFarmList( $rule ) )
	{
		$error = &runRBLStopPacketbl( $rule );
	}

	# Remove from configuration file
	&setRBLObjectRuleParam( $rule, 'farms-del', $farmname );

	# Disable rule if it is not applied to any farm
	if ( !@{ &getRBLFarm( $rule ) } )
	{
		&setRBLObjectRuleParam( $rule, 'status', 'down' );
	}

	return $error;
}

=begin nd
Function: setRBLRenameObjectRule

	Rename a RBL rule. The farm must be stopped.

Parameters:
	Rule - Rule name
	NewRule - New name for the rule

Returns:
	Integer - 0 on success or -1 on failure

=cut

sub setRBLRenameObjectRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $rule    = shift;
	my $newname = shift;

	# check that the rule is not exist
	if ( &getRBLExists( $newname ) )
	{
		return -1;
	}

	# get applied farms
	my @farms = @{ &getRBLObjectRuleParam( $rule, 'farms' ) };

	# copy object
	&addRBLCopyObjectRule( $rule, $newname );

	# apply to farms
	foreach my $farm ( @farms )
	{
		&addRBLFarm( $farm, $newname );
	}

	# Remove old object
	&delRBLDeleteObjectRule( $rule );

	return 0;
}

=begin nd
Function: addRBLCopyObjectRule

	Delete a object through its configuration file

Parameters:
	Rule - Rule name

Returns:
	Integer - 0 on success or -1 on failure

=cut

sub delRBLDeleteObjectRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $rule = shift;

	# check that the rule is not exist
	if ( !&getRBLExists( $rule ) )
	{
		&zenlog( "Error, the RBL rule \"$rule\" doesn't exist." );
		return -1;
	}

	require Config::Tiny;

	my $lock       = &setRBLLockConfigFile();
	my $fileHandle = Config::Tiny->read( $rblConfigFile );
	delete $fileHandle->{ $rule };
	$fileHandle->write( $rblConfigFile );
	close $lock;

	# Remove packetbl config file
	my $config_file = &getRBLPacketblConfig( $rule );
	unlink $config_file if ( -f $config_file );

	&zenlog( "The RBL rule \"$rule\" was successfully removed." );

	return 0;
}

1;
