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
use Skudonet::Farm::Core;


# PUT /farms/<farmname>/actions Set an action in a Farm
sub farm_actions    # ( $json_obj, $farmname )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $json_obj = shift;
	my $farmname = shift;

	require Skudonet::Farm::Action;
	require Skudonet::Farm::Base;

	my $desc = "Farm actions";

	# validate FARM NAME
	if ( !&getFarmExists( $farmname ) )
	{
		my $msg = "The farmname $farmname does not exist.";
		&httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	if ( &getFarmType( $farmname ) =~ /http/ )
	{
		require Skudonet::Farm::HTTP::Config;
		my $err_msg = &getHTTPFarmConfigErrorMessage( $farmname );

		if ( $err_msg )
		{
			&httpErrorResponse( code => 400, desc => $desc, msg => $err_msg );
		}
	}

	my $params = &getZAPIModel( "farm-action.json" );

	# Check allowed parameters
	my $error_msg = &checkZAPIParams( $json_obj, $params, $desc );
	return &httpErrorResponse( code => 400, desc => $desc, msg => $error_msg )
	  if ( $error_msg );

	if ( $json_obj->{ action } eq "stop" )
	{
		my $status = &runFarmStop( $farmname, "true" );

		if ( $status != 0 )
		{
			my $msg = "Error trying to set the action stop in farm $farmname.";
			&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
		}
	}
	elsif ( $json_obj->{ action } eq "start" )
	{
		require Skudonet::Net::Interface;

		# check if the ip exists in any interface
		my $ip = &getFarmVip( "vip", $farmname );

		if ( !&getIpAddressExists( $ip ) )
		{
			my $msg = "The virtual ip $ip is not defined in any interface.";
			&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
		}

		require Skudonet::Farm::Base;
		require Skudonet::Farm::Action;
		if ( &getFarmRestartStatus( $farmname ) )
		{
			my $msg = "The farm has changes pending of applying, it has to be restarted.";
			&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
		}

		require Skudonet::Farm::Core;
		my $farm_type = &getFarmType( $farmname );
		if ( $farm_type ne "datalink" )
		{
			my $if_name = &getInterfaceByIp( $ip );
			my $if_ref  = &getInterfaceConfig( $if_name );
			if ( &getInterfaceSystemStatus( $if_ref ) ne "up" )
			{
				my $msg = "The virtual IP '$ip' is not UP";
				&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
			}
			if ( $farm_type eq "http" or $farm_type eq "https" )
			{
				require Skudonet::Farm::HTTP::Action;
				&checkFarmHTTPSystemStatus( $farmname, "down", "true" );
			}

			my $port = &getFarmVip( "vipp", $farmname );
			if ( !&validatePort( $ip, $port, undef, $farmname ) )
			{
				my $msg = "There is another farm using the ip '$ip' and the port '$port'";
				&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
			}
		}

		my $status = &runFarmStart( $farmname, "true" );

		if ( $status )
		{
			my $msg = "Error trying to set the action start in farm $farmname.";
			&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
		}
	}
	elsif ( $json_obj->{ action } eq "restart" )
	{
		my $status = &runFarmStop( $farmname, "true" );

		if ( $status )
		{
			my $msg =
			  "Error trying to stop the farm in the action restart in farm $farmname.";
			&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
		}

		require Skudonet::Net::Interface;

		# check if the ip exists in any interface
		my $ip = &getFarmVip( "vip", $farmname );

		if ( !&getIpAddressExists( $ip ) )
		{
			my $msg = "The virtual ip $ip is not defined in any interface.";
			&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
		}

		require Skudonet::Farm::Core;
		my $farm_type = &getFarmType( $farmname );
		if ( $farm_type ne "datalink" )
		{
			my $if_name = &getInterfaceByIp( $ip );
			my $if_ref  = &getInterfaceConfig( $if_name );
			if ( &getInterfaceSystemStatus( $if_ref ) ne "up" )
			{
				my $msg = "The virtual IP '$ip' is not UP";
				&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
			}

			my $port = &getFarmVip( "vipp", $farmname );
			if ( !&validatePort( $ip, $port, undef, $farmname ) )
			{
				my $msg = "There is another farm using the ip '$ip' and the port '$port'";
				&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
			}
		}

		$status = &runFarmStart( $farmname, "true" );

		if ( $status )
		{
			my $msg =
			  "ZAPI error, trying to start the farm in the action restart in farm $farmname.";
			&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
		}
	}

	my $msg =
	  "The action $json_obj->{ action } has been performed in farm $farmname.";

	&zenlog( "Success, $msg", "info", "FARMS" );


	my $body = {
				 description => "Set a new action in $farmname",
				 params      => {
							 "action" => $json_obj->{ action },
							 "status" => &getFarmVipStatus( $farmname ),
				 },
				 message => $msg
	};

	&httpResponse( { code => 200, body => $body } );
}

# Set an action in a backend of http|https farm
# PUT /farms/<farmname>/services/<service>/backends/<backend>/maintenance
sub service_backend_maintenance # ( $json_obj, $farmname, $service, $backend_id )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $json_obj   = shift;
	my $farmname   = shift;
	my $service    = shift;
	my $backend_id = shift;

	require Skudonet::Farm::Base;
	require Skudonet::Farm::HTTP::Config;
	require Skudonet::Farm::HTTP::Service;
	require Skudonet::Farm::HTTP::Backend;

	my $desc = "Set service backend status";

	# validate FARM NAME
	if ( !&getFarmExists( $farmname ) )
	{
		my $msg = "The farmname $farmname does not exist.";
		&httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	# validate FARM TYPE
	if ( &getFarmType( $farmname ) !~ /^https?$/ )
	{
		my $msg = "Only HTTP farm profile supports this feature.";
		&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	# validate SERVICE
	my @services = &getHTTPFarmServices( $farmname );
	my $found_service;

	foreach my $service_name ( @services )
	{
		if ( $service eq $service_name )
		{
			$found_service = 1;
			last;
		}
	}

	if ( !$found_service )
	{
		my $msg = "Could not find the requested service.";
		&httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	# validate BACKEND
	my $be_aref = &getHTTPFarmBackends( $farmname, $service );
	my $be      = $be_aref->[$backend_id - 1];

	if ( !$be )
	{
		my $msg = "Could not find a service backend with such id.";
		&httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	my $params = &getZAPIModel( "farm_http_service_backend-maintenance.json" );
	if ( $json_obj->{ action } ne 'maintenance' )
	{
		delete $params->{ "mode" };
	}

	# Check allowed parameters
	my $error_msg = &checkZAPIParams( $json_obj, $params, $desc );
	return &httpErrorResponse( code => 400, desc => $desc, msg => $error_msg )
	  if ( $error_msg );

   # Do not allow to modify the maintenance status if the farm needs to be restarted
	require Skudonet::Farm::Action;
	if ( &getFarmRestartStatus( $farmname ) )
	{
		my $msg = "The farm needs to be restarted before to apply this action.";
		&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	# validate STATUS
	if ( $json_obj->{ action } eq "maintenance" )
	{
		my $maintenance_mode = $json_obj->{ mode } // "drain";    # default

		my $status =
		  &setHTTPFarmBackendMaintenance( $farmname, $backend_id, $maintenance_mode,
										  $service );

		if ( $status )
		{
			my $msg = "Errors found trying to change status backend to maintenance";
			&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
		}
	}
	elsif ( $json_obj->{ action } eq "up" )
	{
		my $status =
		  &setHTTPFarmBackendNoMaintenance( $farmname, $backend_id, $service );

		if ( $status )
		{
			my $msg = "Errors found trying to change status bbackend to up";
			&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
		}
	}

	my $msg =
	  "The action $json_obj->{ action } has been performed in farm $farmname.";

	my $body = {
				 description => $desc,
				 params      => {
							 action => $json_obj->{ action },
							 farm   => {
									   status => &getFarmVipStatus( $farmname ),
							 },
							 message => $msg
				 },
	};


	&httpResponse( { code => 200, body => $body } );
}

# PUT backend in maintenance
# PUT /farms/<farmname>/backends/<backend>/maintenance
sub backend_maintenance    # ( $json_obj, $farmname, $backend_id )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $json_obj   = shift;
	my $farmname   = shift;
	my $backend_id = shift;

	require Skudonet::Farm::Backend::Maintenance;
	require Skudonet::Farm::Backend;
	require Skudonet::Farm::Base;

	my $desc = "Set backend status";

	# validate FARM NAME
	if ( !&getFarmExists( $farmname ) )
	{
		my $msg = "The farmname $farmname does not exist.";
		&httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	# validate FARM TYPE
	unless ( &getFarmType( $farmname ) eq 'l4xnat' )
	{
		my $msg = "Only L4xNAT farm profile supports this feature.";
		&httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	# validate BACKEND
	require Skudonet::Farm::L4xNAT::Backend;

	my $backends = &getL4FarmServers( $farmname );
	my $exists   = &getFarmServer( $backends, $backend_id );

	if ( !$exists )
	{
		my $msg = "Could not find a backend with such id.";
		&httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	my $params = &getZAPIModel( "farm_l4xnat_service_backend-maintenance.json" );

	if ( $json_obj->{ action } ne 'maintenance' )
	{
		delete $params->{ "mode" };
	}

	# Check allowed parameters
	my $error_msg = &checkZAPIParams( $json_obj, $params, $desc );
	return &httpErrorResponse( code => 400, desc => $desc, msg => $error_msg )
	  if ( $error_msg );

	# validate STATUS
	if ( $json_obj->{ action } eq "maintenance" )
	{
		my $maintenance_mode = $json_obj->{ mode } // "drain";    # default

		my $status =
		  &setFarmBackendMaintenance( $farmname, $backend_id, $maintenance_mode );

		if ( $status != 0 )
		{
			my $msg = "Errors found trying to change status backend to maintenance";
			&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
		}
	}
	elsif ( $json_obj->{ action } eq "up" )
	{
		my $status = &setFarmBackendNoMaintenance( $farmname, $backend_id );

		if ( $status )
		{
			my $msg = "Errors found trying to change status backend to up";
			&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
		}
	}

	my $msg =
	  "The action $json_obj->{ action } has been performed in farm $farmname.";

	# no error found, send successful response
	my $body = {
				 description => $desc,
				 params      => {
							 action => $json_obj->{ action },
							 farm   => {
									   status => &getFarmVipStatus( $farmname ),
							 },
							 message => $msg
				 },
	};


	&httpResponse( { code => 200, body => $body } );
}

1;

