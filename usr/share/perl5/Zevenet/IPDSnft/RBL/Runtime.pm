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

include 'Zevenet::IPDS::RBL::Core';

# rbl configuration path
my $rblPath              = &getGlobalConfiguration( 'configdir' ) . "/ipds/rbl";
my $rblConfigFile        = "$rblPath/rbl.conf";
my $preloadedDomainsFile = "$rblPath/preloaded_domains.conf";
my $userDomainsFile      = "$rblPath/user_domains.conf";

=begin nd
Function: runRBLFarmRule

	Create RBL rules for a farm with an action

Parameters:
	Rulename -  Rule name
	Farmname -  Farm name. If farm name is in blank, the rule applies to all destine IPs and ports
	Action - Action to apply rules. The available options are: 'add' to set a new queue for a farm;
	  or 'delete' to remove the queue for a farm

Returns:
	Integer - 0 on success or other value on failure

=cut

sub runRBLFarmRule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $rule, $farmname, $action ) = @_;
	my $error;
	my $nfqueue = "";

	include 'Zevenet::IPDS::Core';

	if ( $action eq "add" )
	{
		my $nfqueue = &getRBLObjectRuleParam( $rule, 'nf_queue_number' );
		return 0 if ( $nfqueue !~ /\d+/ );
	}
	elsif ( $action eq "delete" )
	{
		$nfqueue = '-1';
	}
	else
	{
		&zenlog( "Wrong action to create the rule ", "error", "IPDS" );
		return -1;
	}

	$error = &setIPDSFarmParam( 'nfqueue', $nfqueue, $farmname );

	return $error;
}

=begin nd
Function: runRBLStart

	Run packetbl binary

Parameters:
	String - Rule name

Returns:
	integer - 0 on success or other value on failure

=cut

sub runRBLStartPacketbl
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $rule = shift;

	# Get packetbl bin
	my $packetbl = &getGlobalConfiguration( "packetbl_bin" );

# WARNING: to not choose a new nt queue if it exists. This is a bugfix for backup node
	if ( &getRBLObjectRuleParam( $rule, "nf_queue_number" ) eq "" )
	{
		# Look for a not used nf queue and assign it to this rule
		&setRBLCreateNfqueue( $rule );
	}

	# Create packetbl config file
	&setRBLPacketblConfig( $rule );

	# Get packetbl configuration file
	my $configfile = &getRBLPacketblConfig( $rule );

	# Run packetbl
	my $error = system ( "bash", "-c",
						 ". /etc/profile_packetbl && $packetbl -f $configfile" );
	&zenlog( "Error, starting packetbl", "error", "IPDS" ) if ( $error );
	return $error;
}

=begin nd
Function: runRBLStopPacketbl

	Stop packetbl bin

Parameters:
	String - Rule name

Returns:

FIXME:
	if packetbl is stopped without delete its pid file, the rule will appear in UP status

=cut

sub runRBLStopPacketbl
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $rule  = shift;
	my $error = 0;

	# Remove associated nfqueue from configfile
	&setRBLRemoveNfqueue( $rule );

	# exec kill
	my $pid = &getRBLPacketblPid( $rule );

	if ( $pid )
	{
		$error = &logAndRun( "kill $pid" );
	}

	return $error;
}

=begin nd
Function: setRBLPacketblConfig

	before than exec packetbl, configure a new config file with rule configuration and overwrite the existing one

Parameters:
	String - Rule name

Returns:
	Integer - 0 on success or other value on failure

=cut

sub setRBLPacketblConfig
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $rule = shift;

	require Zevenet::Lock;

	my $params = &getRBLObjectRule( $rule );
	my $error  = 0;

	# filling config file
	my $fileContent = "
<host>";

	# not review local traffic
	if ( $params->{ 'local_traffic' } eq 'no' )
	{
		$fileContent .= "
	whitelist	192.168.0.0/16
	whitelist	169.254.0.0/16
	whitelist	172.16.0.0/12
	whitelist	10.0.0.0/8";
	}

	foreach my $domain ( @{ $params->{ 'domains' } } )
	{
		$fileContent .= "\n\tblacklistbl\t$domain";
	}

	$fileContent .= "
</host>
FallthroughAccept	yes
AllowNonPort25		yes
AllowNonSyn			no
DryRun			$params->{'only_logging'}
CacheSize	$params->{'cache_size'}
CacheTTL		$params->{'cache_time'}
LogFacility	daemon
AlternativeDomain		rbl.zevenet.com
AlternativeResolveFile	usr/local/zevenet/config/ipds/rbl/zevenet_nameservers.conf
Queueno		$params->{'nf_queue_number'}
Queuesize	$params->{'queue_size'}
Threadmax	$params->{'threadmax'}
LogLevel	$params->{'log_level'}
";

	# save file
	my $fh;
	my $filename = &getRBLPacketblConfig( $rule );
	$fh = &openlock( $filename, 'w' );

	unless ( $fh )
	{
		&zenlog( "Could not open file $filename: $!", "error", "IPDS" );
		return -1;
	}

	print $fh $fileContent;
	close $fh;

	return $error;
}

=begin nd
Function: setRBLCreateNfqueue

	Looking for a not used nf queue and assigned it to a RBL rule

Parameters:
	String - Rule name

Returns:
	integer - netfilter queue number

=cut

sub setRBLCreateNfqueue
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $rule = shift;

	require Config::Tiny;
	include 'Zevenet::IPDS::RBL::Config';

	my $queue_num  = 0;
	my @rules      = &getRBLRuleList();
	my $fileHandle = Config::Tiny->read( $rblConfigFile );
	my @queue_list;

	foreach my $rule ( @rules )
	{
		if ( $fileHandle->{ $rule }->{ 'nf_queue_number' } ne "" )
		{
			push @queue_list, $fileHandle->{ $rule }->{ 'nf_queue_number' };
		}
	}

	# Increase $queue_num until to find one is not used
	while ( $queue_num < 65000 )
	{
		last if ( !grep ( /^$queue_num$/, @queue_list ) );
		$queue_num = $queue_num + 1;
	}

	# Save this queue
	&setRBLObjectRuleParam( $rule, 'nf_queue_number', $queue_num );

	return $queue_num;
}

=begin nd
Function: setRBLRemoveNfqueue

	Remove the associated netfilter queue for a rule

Parameters:
	String - Rule name

Returns:
	none - .

=cut

sub setRBLRemoveNfqueue
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $rule = shift;

	include 'Zevenet::IPDS::RBL::Config';
	&setRBLObjectRuleParam( $rule, 'nf_queue_number', '' );
}

1;
