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
include 'Zevenet::IPDS::Core';

=begin nd
Function: runIPDSStartModule

	Boot the IPDS module

Parameters:

Returns:
	none - .

=cut

sub runIPDSStartModule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	include 'Zevenet::Cluster';
	include 'Zevenet::IPDS::RBL::Actions';
	include 'Zevenet::IPDS::DoS::Actions';
	include 'Zevenet::IPDS::Blacklist::Actions';

	# Add cluster exception not to block traffic from the other node of cluster
	&setZClusterIptablesException( "insert" );
	&runBLStartModule();
	&runRBLStartModule();
	&runDOSStartModule();
}

=begin nd
Function: runIPDSStopModule

	Stop the IPDS module

Parameters:

Returns:
	none - .

=cut

sub runIPDSStopModule
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	include 'Zevenet::Cluster';
	include 'Zevenet::IPDS::RBL::Actions';
	include 'Zevenet::IPDS::DoS::Actions';
	include 'Zevenet::IPDS::Blacklist::Actions';

	&runRBLStopModule();
	&runBLStopModule();
	&runDOStopModule();

	# Remove cluster exception not to block traffic from the other node of cluster
	&setZClusterIptablesException( "delete" );
}

actions_by_farm:

=begin nd
Function: runIPDSStartByFarm

	Link a farm with all its IPDS rules. If some rule is not been used by another farm, the rule is run.
	It is useful when a farm is started, stopped or modified

Parameters:
	Farmname - Farm name

Returns:
	none - .

=cut

sub runIPDSStartByFarm
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farmname = shift;

	include 'Zevenet::Farm::Base';
	return 0 if ( &getFarmBootStatus( $farmname ) eq "down" );

	# get rules and perl modules
	my $rules = &getIPDSfarmsRules( $farmname );

	include 'Zevenet::IPDS::Blacklist::Actions' if ( @{ $rules->{ blacklists } } );
	include 'Zevenet::IPDS::DoS::Actions'       if ( @{ $rules->{ dos } } );
	include 'Zevenet::IPDS::RBL::Actions'       if ( @{ $rules->{ rbl } } );
	include 'Zevenet::IPDS::WAF::Runtime'       if ( @{ $rules->{ waf } } );

	my $name;

	# start BL rules
	foreach my $rule ( @{ $rules->{ blacklists } } )
	{
		next if ( $rule->{ status } eq "down" );
		$name = $rule->{ name };
		&zenlog( Dumper( $rule ) );
		&runBLStart( $name, $farmname );
	}

	# start dos rules
	foreach my $rule ( @{ $rules->{ dos } } )
	{
		$name = $rule->{ name };
		&runDOSStart( $name, $farmname );
	}

	# start rbl rules
	foreach my $rule ( @{ $rules->{ rbl } } )
	{
		$name = $rule->{ name };
		&runRBLStart( $name, $farmname );
	}

	# start waf rules
	# it is not necesssary start WAF. It is started automaticaly with the farms
}

=begin nd
Function: runIPDSStopByFarm

	Unlink a farm with all its IPDS rules. If no more farm is using the rule, stop it.
	It is useful when a farm is stopped or remove from rule

Parameters:
	Farmname - Farm name

Returns:
	none - .

=cut

sub runIPDSStopByFarm
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farmname = shift;

	# get rules and perl modules
	my $rules = &getIPDSfarmsRules( $farmname );

	include 'Zevenet::IPDS::Blacklist::Actions' if ( @{ $rules->{ blacklists } } );
	include 'Zevenet::IPDS::DoS::Actions'       if ( @{ $rules->{ dos } } );
	include 'Zevenet::IPDS::RBL::Actions'       if ( @{ $rules->{ rbl } } );

	my $name;

	# start BL rules
	foreach my $rule ( @{ $rules->{ blacklists } } )
	{
		$name = $rule->{ name };
		&runBLStop( $name, $farmname );
	}

	# start dos rules
	foreach my $rule ( @{ $rules->{ dos } } )
	{
		$name = $rule->{ name };
		&runDOSStop( $name, $farmname );
	}

	# start rbl rules
	foreach my $rule ( @{ $rules->{ rbl } } )
	{
		$name = $rule->{ name };
		&runRBLStop( $name, $farmname );
	}
}

=begin nd
Function: runIPDSRestartByFarm

	Reload all IPDS rules to a farm.
	It is useful when a farm is modified

Parameters:
	Farmname - Farm name

Returns:
	none - .

=cut

sub runIPDSRestartByFarm
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farmname = shift;

	require Zevenet::Farm::Base;
	return 0 if ( &getFarmBootStatus( $farmname ) eq "down" );

	# get rules and perl modules
	my $rules = &getIPDSfarmsRules( $farmname );

	include 'Zevenet::IPDS::Blacklist::Actions' if ( @{ $rules->{ blacklists } } );
	include 'Zevenet::IPDS::DoS::Actions'       if ( @{ $rules->{ dos } } );
	include 'Zevenet::IPDS::RBL::Actions'       if ( @{ $rules->{ rbl } } );

	my $name;

	# start BL rules
	foreach my $rule ( @{ $rules->{ blacklists } } )
	{
		$name = $rule->{ name };
		&runBLStop( $name, $farmname );
		&runBLStart( $name, $farmname );
	}

	# start dos rules
	foreach my $rule ( @{ $rules->{ dos } } )
	{
		$name = $rule->{ name };
		&runDOSStop( $name, $farmname );
		&runDOSStart( $name, $farmname );
	}

	# start rbl rules
	foreach my $rule ( @{ $rules->{ rbl } } )
	{
		$name = $rule->{ name };
		&runRBLStop( $name, $farmname );
		&runRBLStart( $name, $farmname );
	}
}

=begin nd
Function: runIPDSDeleteByFarm

	Unset a farm from all farms where it is linked

Parameters:
	Farmname - Farm name

Returns:
	none - .

=cut

sub runIPDSDeleteByFarm
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farmname = shift;

	# get rules and perl modules
	my $rules = &getIPDSfarmsRules( $farmname );

	include 'Zevenet::IPDS::Blacklist::Runtime' if ( @{ $rules->{ blacklists } } );
	include 'Zevenet::IPDS::DoS::Runtime'       if ( @{ $rules->{ dos } } );
	include 'Zevenet::IPDS::RBL::Config'        if ( @{ $rules->{ rbl } } );

	my $name;

	# start BL rules
	foreach my $rule ( @{ $rules->{ blacklists } } )
	{
		$name = $rule->{ name };
		&setBLRemFromFarm( $farmname, $name );
	}

	# start dos rules
	foreach my $rule ( @{ $rules->{ dos } } )
	{
		$name = $rule->{ name };
		&setDOSUnsetRule( $name, $farmname );
	}

	# start rbl rules
	foreach my $rule ( @{ $rules->{ rbl } } )
	{
		$name = $rule->{ name };
		&delRBLFarm( $farmname, $name );
	}
}

=begin nd
Function: runIPDSRenameByFarm

	When a farm is renamed, link ipds rules with new farm name

Parameters:
	Farmname - Farm name
	New farmname - New farm name

Returns:
	none - .

=cut

sub runIPDSRenameByFarm
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farmname = shift;
	my $newname  = shift;

	# get rules and perl modules
	my $rules = &getIPDSfarmsRules( $farmname );

	include 'Zevenet::IPDS::Blacklist::Config' if ( @{ $rules->{ blacklists } } );
	include 'Zevenet::IPDS::DoS::Config'       if ( @{ $rules->{ dos } } );
	include 'Zevenet::IPDS::RBL::Config'       if ( @{ $rules->{ rbl } } );

	my $name;

	# start BL rules
	foreach my $rule ( @{ $rules->{ blacklists } } )
	{
		$name = $rule->{ name };
		&setBLParam( $name, 'farms-del', $farmname );
		&setBLParam( $name, 'farms-add', $newname );
	}

	# start dos rules
	foreach my $rule ( @{ $rules->{ dos } } )
	{
		$name = $rule->{ name };
		&setDOSParam( $name, 'farms-del', $farmname );
		&setDOSParam( $name, 'farms-add', $newname );
	}

	# start rbl rules
	foreach my $rule ( @{ $rules->{ rbl } } )
	{
		$name = $rule->{ name };
		&setRBLObjectRuleParam( $name, 'farms-del', $farmname );
		&setRBLObjectRuleParam( $name, 'farms-add', $newname );
	}
}

1;
