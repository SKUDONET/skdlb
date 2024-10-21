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
require Skudonet::API40::HTTP;


require Skudonet::IPDS::WAF::Core;
require Skudonet::IPDS::WAF::Config;

#GET /ipds/waf
sub list_waf_sets
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my @sets = &listWAFSet();
	my $desc = "List the WAF sets";

	my @out = ();


	foreach my $set ( sort @sets )
	{
		my $status  = &getWAFSetStatus( $set );
		my @farms   = &listWAFBySet( $set );
		my $out_ref = { name => $set, status => $status, farms => \@farms };


		push @out, $out_ref;
	}

	return &httpResponse(
				   { code => 200, body => { description => $desc, params => \@out } } );
}

#  GET /ipds/waf/<set>
sub get_waf_set
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $set = shift;

	my $desc = "Get the WAF set $set";

	unless ( &existWAFSet( $set ) )
	{
		my $msg = "Requested set $set does not exist.";
		return &httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	my $set_st;
		$set_st = &getZapiWAFSetConf( $set );
	my @farms = &listWAFBySet( $set );
	$set_st->{ farms } = \@farms;
	my $body = { description => $desc, params => $set_st };

	return &httpResponse( { code => 200, body => $body } );
}

#  PUT ipds/waf/<set>
sub modify_waf_set
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $json_obj = shift;
	my $set      = shift;

	require Skudonet::IPDS::WAF::Config;

	my $desc = "Modify the WAF set $set";

	unless ( &existWAFSet( $set ) )
	{
		my $msg = "Requested set $set does not exist.";
		return &httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}
	my $params = &getZAPIModel( "waf-modify.json" );

	# Check allowed parameters
	my $error_msg = &checkZAPIParams( $json_obj, $params, $desc );
	return &httpErrorResponse( code => 400, desc => $desc, msg => $error_msg )
	  if ( $error_msg );


	if ( exists $json_obj->{ default_action }
		 and $json_obj->{ default_action } ne 'redirect' )
	{
		$json_obj->{ redirect_url } = "";
	}

	#
	if ( exists $json_obj->{ only_logging }
		 and $json_obj->{ only_logging } eq 'true' )
	{
		if ( &getWAFSetStatus( $set ) eq 'down' )
		{
			my $msg =
			  "It is necessary to start the set before configuring the 'only logging' work mode.";
			return &httpErrorResponse( code => 400, desc => $desc, msg => $msg );
		}
	}

	my $err;
		$err = &setWAFSetConf( $set, $json_obj );
	if ( $err )
	{
		my $msg = "Some errors happened trying to modify the set:$err.";
		return &httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	my $set_st;
		$set_st = &getZapiWAFSetConf( $set );

	my $msg = "The set has been modified successfuly.";
	my $body = { description => $desc, params => $set_st, message => $msg };

	return &httpResponse( { code => 200, body => $body } );

}

#  POST /farms/<farm>/ipds/waf
sub add_farm_waf_set
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $json_obj = shift;
	my $farm     = shift;
	my $error    = 0;
	my $msg      = "";

	require Skudonet::Farm::Core;
	require Skudonet::IPDS::WAF::Runtime;

	my $desc = "Apply a WAF set to a farm";

	if ( !&getFarmExists( $farm ) )
	{
		$msg = "$farm does not exist.";
		return &httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	my $params = &getZAPIModel( "waf_to_farm-add.json" );

	# Check allowed parameters
	my $error_msg = &checkZAPIParams( $json_obj, $params, $desc );
	return &httpErrorResponse( code => 400, desc => $desc, msg => $error_msg )
	  if ( $error_msg );

	unless ( &existWAFSet( $json_obj->{ name } ) )
	{
		$msg = "Requested set $json_obj->{name} does not exist.";
		return &httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	if ( grep ( /^$json_obj->{ name }$/, &listWAFByFarm( $farm ) ) )
	{
		$msg = "$json_obj->{ name } is already applied to $farm.";
		return &httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	if ( &getFarmType( $farm ) !~ /http/ )
	{
		$msg = "The farm must be of type HTTP.";
		return &httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

		my $out = &addWAFsetToFarm( $farm, $json_obj->{ name } );
		$error = $out->{ error };
		$msg   = $out->{ message };
	if ( $error )
	{
		$msg = "Applying $json_obj->{ name } to $farm" if $msg eq "";
		return &httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}


	$msg = "WAF set $json_obj->{ name } was applied properly to the farm $farm.";
	my $body = {
				 description => $desc,
				 success     => "true",
				 message     => $msg
	};
	return &httpResponse( { code => 200, body => $body } );
}

#  DELETE /farms/<farm>/ipds/waf
sub remove_farm_waf_set
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farm  = shift;
	my $set   = shift;
	my $error = 0;
	my $msg   = "";

	require Skudonet::Farm::Core;
	require Skudonet::IPDS::WAF::Runtime;

	my $desc = "Unset a WAF set from a farm";

	if ( !&getFarmExists( $farm ) )
	{
		my $msg = "$farm does not exist.";
		return &httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	if ( !&existWAFSet( $set ) )
	{
		my $msg = "The set $set does not exist.";
		return &httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	if ( !grep ( /^$set$/, &listWAFByFarm( $farm ) ) )
	{
		my $msg = "Not found the set $set in the farm $farm.";
		return &httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

		$error = &removeWAFSetFromFarm( $farm, $set );

	if ( $error )
	{
		$msg = "Error, removing the set $set from the farm $farm." if $msg eq "";
		return &httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}


	$msg = "The WAF set $set was removed successfully from the farm $farm.";
	my $body = {
				 description => $desc,
				 success     => "true",
				 message     => $msg,
	};
	return &httpResponse( { code => 200, body => $body } );
}

#  POST /farms/<farm>/ipds/waf/<set>/actions
sub move_farm_waf_set
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $json_obj = shift;
	my $farm     = shift;
	my $set      = shift;
	my $err;

	require Skudonet::Farm::Core;
	my $desc = "Move a set in farm";

	# check if the set exists
	if ( !&getFarmExists( $farm ) )
	{
		my $msg = "The farm $farm does not exist";
		return &httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	# check if the set exists
	if ( !&existWAFSet( $set ) )
	{
		my $msg = "The WAF set $set does not exist";
		return &httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	my $params = &getZAPIModel( "waf-move.json" );

	# Check allowed parameters
	my $error_msg = &checkZAPIParams( $json_obj, $params, $desc );
	return &httpErrorResponse( code => 400, desc => $desc, msg => $error_msg )
	  if ( $error_msg );

	# check if the set exists
	my @sets = &listWAFByFarm( $farm );
	my $size = scalar @sets;
	if ( !grep ( /^$set$/, @sets ) )
	{
		my $msg = "Not found the set $set in the farm $farm.";
		return &httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	if ( $sets[$json_obj->{ position }] eq $set )
	{
		my $msg = "The set $set is already in the position $json_obj->{position}.";
		return &httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	if ( $json_obj->{ position } >= $size )
	{
		my $ind = $size - 1;
		my $msg = "The biggest index for the farm $farm is $ind.";
		return &httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	$err = &moveWAFSet( $farm, $set, $json_obj->{ position } );
	if ( $err )
	{
		my $msg = "Error moving the set $set";
		return &httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}


	my $msg = "The set was moved properly to the position $json_obj->{ position }.";
	my $body = { description => $desc, message => $msg };

	return &httpResponse( { code => 200, body => $body } );
}

# POST /ipds/waf/<set>/actions
sub actions_waf
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $json_obj = shift;
	my $set      = shift;
	my $error;

	require Skudonet::IPDS::WAF::Runtime;

	my $desc = "Apply an action to the set rule $set";
	my $msg  = "Error, applying the action to the set rule.";

	# check if the set exists
	if ( !&existWAFSet( $set ) )
	{
		my $msg = "The WAF set $set does not exist";
		return &httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	my $params = &getZAPIModel( "waf-action.json" );

	# Check allowed parameters
	my $error_msg = &checkZAPIParams( $json_obj, $params, $desc );
	return &httpErrorResponse( code => 400, desc => $desc, msg => $error_msg )
	  if ( $error_msg );

	my $set_status;

	if (    $json_obj->{ action } eq 'stop'
		 or $json_obj->{ action } eq 'start'
		 or $json_obj->{ action } eq 'restart' )
	{

		# set the status
		my $rule_param->{ status } =
		  ( $json_obj->{ action } eq 'start' or $json_obj->{ action } eq 'restart' )
		  ? 'true'
		  : 'false';
			$error = &setWAFSetConf( $set, $rule_param );

		if ( $error )
		{
			my $msg =
			  "Error, applying the action '$json_obj->{ action }' to the Ruleset '$set':$error.";
			return &httpErrorResponse( code => 400, desc => $desc, msg => $msg );
		}

		# reload the set
		$set_status = $rule_param->{ status } eq "true" ? "up" : "down";
	}

	$error = &reloadWAFByRule( $set, $set_status );
	return &httpErrorResponse( code => 400, desc => $desc, msg => $msg ) if $error;


	my $status = &getWAFSetStatus( $set );
	if (    $json_obj->{ action } eq 'stop'
		 or $json_obj->{ action } eq 'start'
		 or $json_obj->{ action } eq 'restart' )
	{
		if (    ( $status ne 'up' and $json_obj->{ action } eq 'start' )
			 or ( $status ne 'down' and $json_obj->{ action } eq 'stop' ) )
		{
			return &httpErrorResponse( code => 400, desc => $desc, msg => $msg );
		}
	}

	$msg = "The $set WAF ruleset has been restarted successfully"
	  if ( $json_obj->{ action } eq 'restart' );
	$msg = "The $set WAF ruleset has been started successfully"
	  if ( $json_obj->{ action } eq 'start' );
	$msg = "The $set WAF ruleset has been stopped successfully"
	  if ( $json_obj->{ action } eq 'stop' );

	my $body = {
				 description => $desc,
				 success     => "true",
				 params      => { status => $status },
				 message     => $msg
	};

	return &httpResponse( { code => 200, body => $body } );
}

sub getZapiWAFSetConf
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $set = shift;

	require Skudonet::IPDS::WAF::Config;

	my $set_st = &getWAFSetConf( $set );

	my $conf = $set_st->{ configuration };
	$conf->{ default_action } //= 'pass';
	$conf->{ default_log } =
	  ( $conf->{ default_log } ne 'false' ) ? 'true' : 'false';
	$conf->{ default_phase }         //= 2;
	$conf->{ process_request_body }  //= 'false';
	$conf->{ process_response_body } //= 'false';
	$conf->{ request_body_limit }    //= 0;
	$conf->{ status } = ( $conf->{ status } eq 'false' ) ? 'down' : 'up';
	$conf->{ only_logging } = $conf->{ only_logging };

	return $set_st;
}

1;

