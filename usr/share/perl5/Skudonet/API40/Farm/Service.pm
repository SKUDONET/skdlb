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


# POST
sub new_farm_service    # ( $json_obj, $farmname )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $json_obj = shift;
	my $farmname = shift;

	require Skudonet::Farm::Service;

	my $desc = "New service";

	# Check if the farm exists
	if ( !&getFarmExists( $farmname ) )
	{
		my $msg = "The farmname $farmname does not exist.";
		&httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	# check if the service exists
	if ( grep ( /^$json_obj->{id}$/, &getFarmServices( $farmname ) ) )
	{
		my $msg = "Error, the service $json_obj->{id} already exist.";
		&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	my $type = &getFarmType( $farmname );

	# validate farm profile
		if ( $type !~ /^https?$/ )
		{
			my $msg = "The farm profile $type does not support services actions.";
			&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
		}

	my $params = &getZAPIModel( "farm_http_service-create.json" );

	# Check allowed parameters
	my $error_msg = &checkZAPIParams( $json_obj, $params, $desc );
	return &httpErrorResponse( code => 400, desc => $desc, msg => $error_msg )
	  if ( $error_msg );

	# HTTP profile
	require Skudonet::API40::Farm::Get::HTTP;
	require Skudonet::Farm::Base;
	require Skudonet::Farm::HTTP::Service;

	my $result = &setFarmHTTPNewService( $farmname, $json_obj->{ id } );

	# check if a service with such name already exists
	if ( $result == 1 )
	{
		my $msg = "Service name " . $json_obj->{ id } . " already exists.";
		&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	# check if the service name has invalid characters
	if ( $result == 3 )
	{
		my $msg =
		  "Service name is not valid, only allowed numbers, letters and hyphens.";
		&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	# Return 0 on success
	if ( $result )
	{
		my $msg = "Error creating the service $json_obj->{ id }.";
		&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	# no error found, return successful response
	&zenlog(
		"Success, a new service has been created in farm $farmname with id $json_obj->{id}.",
		"info", "FARMS"
	);

	my $body = {
		   description => $desc,
		   params      => { id => $json_obj->{ id } },
		   message     =>
			 "A new service has been created in farm $farmname with id $json_obj->{id}."
	};

	if ( &getFarmStatus( $farmname ) ne 'down' )
	{
		require Skudonet::Farm::Action;
		if ( &getGlobalConfiguration( 'proxy_ng' ) ne 'true' )
		{
			&setFarmRestart( $farmname );
			$body->{ status } = 'needed restart';
		}
		else
		{
			require Skudonet::Farm::HTTP::Config;
			my $config_error = &getHTTPFarmConfigErrorMessage( $farmname );
			if ( $config_error ne "" )
			{
				$body->{ warning } = "Farm '$farmname' config error: $config_error";
			}
			else
			{
				&runFarmReload( $farmname );
			}
		}
	}

	&httpResponse( { code => 201, body => $body } );
}

# GET

#GET /farms/<name>/services/<service>
sub farm_services
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farmname, $servicename ) = @_;

	require Skudonet::API40::Farm::Get::HTTP;
	require Skudonet::Farm::Config;
	require Skudonet::Farm::HTTP::Service;

	my $desc = "Get services of a farm";

	# Check if the farm exists
	if ( !&getFarmExists( $farmname ) )
	{
		my $msg = "The farmname $farmname does not exist.";
		&httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	my $type = &getFarmType( $farmname );

	# check the farm type is supported
	if ( $type !~ /http/i )
	{
		my $msg = "This functionality only is available for HTTP farms.";
		&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	my @services = &getHTTPFarmServices( $farmname );

	# check if the service is available
	if ( !grep { $servicename eq $_ } @services )
	{
		my $msg = "The required service does not exist.";
		&httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	# no error found, return successful response
	my $service = &getHTTPServiceStruct( $farmname, $servicename );

#Fix Me: getHTTPServiceStruct should not return these parameters if 'proxy_ng' ne 'true' .
	if ( &getGlobalConfiguration( 'proxy_ng' ) ne 'true' )
	{
		delete ( $service->{ replacerequestheader } );
		delete ( $service->{ replaceresponseheader } );
		delete ( $service->{ rewritelocation } );
		delete ( $service->{ rewriteurl } );
		delete ( $service->{ pinnedconnection } );
		delete ( $service->{ routingpolicy } );
	}
	else
	{
		require Skudonet::Farm::HTTP::Sessions;
		$service->{ sessions } = &listL7FarmSessions( $farmname, $servicename );
	}

	my $body = {
				 description => $desc,
				 params      => $service,
	};

	&httpResponse( { code => 200, body => $body } );
}

# PUT

sub modify_services    # ( $json_obj, $farmname, $service )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $json_obj, $farmname, $service ) = @_;

	require Skudonet::Farm::Base;
	require Skudonet::Farm::Config;
	require Skudonet::Farm::Service;

	my $desc = "Modify service";
	my $output_params;
	my $bk_msg = "";

	# validate FARM NAME
	if ( !&getFarmExists( $farmname ) )
	{
		my $msg = "The farmname $farmname does not exist.";
		&httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	# validate FARM TYPE
	my $type = &getFarmType( $farmname );

	unless ( $type eq 'gslb' || $type eq 'http' || $type eq 'https' )
	{
		my $msg = "The $type farm profile does not support services settings.";
		&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	# validate SERVICE
	my @services      = &getFarmServices( $farmname );
	my $found_service = grep { $service eq $_ } @services;

	if ( not $found_service )
	{
		my $msg = "Could not find the requested service.";
		&httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}


	my $params = &getZAPIModel( "farm_http_service-modify.json" );

	# Check allowed parameters
	my $error_msg = &checkZAPIParams( $json_obj, $params, $desc );
	return &httpErrorResponse( code => 400, desc => $desc, msg => $error_msg )
	  if ( $error_msg );

	# translate params
	if ( exists $json_obj->{ persistence }
		 and $json_obj->{ persistence } eq 'NONE' )
	{
		$json_obj->{ persistence } = "";
	}

	# modifying params
	if ( exists $json_obj->{ vhost } )
	{
		&setFarmVS( $farmname, $service, "vs", $json_obj->{ vhost } );
	}

	if ( exists $json_obj->{ urlp } )
	{
		&setFarmVS( $farmname, $service, "urlp", $json_obj->{ urlp } );
	}

	if ( exists $json_obj->{ redirect } )
	{
		my $redirect = $json_obj->{ redirect };

		&setFarmVS( $farmname, $service, "redirect", $redirect );

		# delete service's backends if redirect has been configured
		if ( $redirect )
		{
			require Skudonet::Farm::HTTP::Backend;
			my $backends = scalar @{ &getHTTPFarmBackends( $farmname, $service ) };
			if ( $backends )
			{
				$bk_msg = "The backends of $service have been deleted.";
				for ( my $id = $backends - 1 ; $id >= 0 ; $id-- )
				{
					&runHTTPFarmServerDelete( $id, $farmname, $service );
				}
			}
		}
	}

	if ( exists $json_obj->{ redirecttype } )
	{
		my $redirecttype = $json_obj->{ redirecttype };
		&setFarmVS( $farmname, $service, "redirecttype", $redirecttype );
	}

	if ( exists $json_obj->{ leastresp } )
	{
		if ( $json_obj->{ leastresp } eq "true" )
		{
			&setFarmVS( $farmname, $service, "dynscale", $json_obj->{ leastresp } );
		}
		elsif ( $json_obj->{ leastresp } eq "false" )
		{
			&setFarmVS( $farmname, $service, "dynscale", "" );
		}
	}

	if ( exists $json_obj->{ persistence } )
	{
		my $session = $json_obj->{ persistence };
		$session = 'nothing' if $session eq "";

		my $error = &setFarmVS( $farmname, $service, "session", $session );
		if ( $error )
		{
			my $msg = "It's not possible to change the persistence parameter.";
			&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
		}
	}

	my $session = &getFarmVS( $farmname, $service, "sesstype" );

	# It is necessary evaluate first session, next ttl and later persistence
	if ( exists $json_obj->{ sessionid } )
	{
		if ( $session =~ /^(URL|COOKIE|HEADER)$/ )
		{
			&setFarmVS( $farmname, $service, "sessionid", $json_obj->{ sessionid } );
		}
	}

	if ( exists $json_obj->{ ttl } )
	{
		if ( $session =~ /^(IP|BASIC|URL|PARM|COOKIE|HEADER)$/ )
		{
			my $error = &setFarmVS( $farmname, $service, "ttl", "$json_obj->{ttl}" );
			if ( $error )
			{
				my $msg = "Could not change the ttl parameter.";
				&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
			}
		}
	}

	# Cookie insertion
	if ( scalar grep ( /^cookie/, keys %{ $json_obj } ) )
	{
			my $msg = "Cookie insertion feature not available.";
			&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	if ( exists $json_obj->{ httpsb } )
	{
		if (
			 $json_obj->{ httpsb } ne &getFarmVS( $farmname, $service, 'httpsbackend' ) )
		{
			if ( $json_obj->{ httpsb } eq "true" )
			{
				&setFarmVS( $farmname, $service, "httpsbackend", $json_obj->{ httpsb } );
			}
			elsif ( $json_obj->{ httpsb } eq "false" )
			{
				&setFarmVS( $farmname, $service, "httpsbackend", "" );

			}
		}
	}

	# Redirect code
	if ( exists $json_obj->{ redirect_code } )
	{
			my $msg = "Redirect code feature not available.";
			&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	if ( exists $json_obj->{ pinnedconnection } )
	{
		if ( &getGlobalConfiguration( 'proxy_ng' ) eq 'true' )
		{
			my $error = &setFarmVS( $farmname, $service, "pinnedConnection",
									"$json_obj->{pinnedconnection}" );
			if ( $error )
			{
				my $msg = "Could not change the pinned connection parameter.";
				&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
			}
		}
	}

	if ( exists $json_obj->{ routingpolicy } )
	{
		if ( &getGlobalConfiguration( 'proxy_ng' ) eq 'true' )
		{
			my $error = &setFarmVS( $farmname, $service, "routingPolicy",
									"$json_obj->{routingpolicy}" );
			if ( $error )
			{
				my $msg = "Could not change the routing policy parameter.";
				&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
			}
		}
	}

	if ( exists $json_obj->{ rewritelocation } )
	{
		if ( &getGlobalConfiguration( 'proxy_ng' ) eq 'true' )
		{
			my $error = &setFarmVS( $farmname, $service, "rewriteLocation",
									"$json_obj->{rewritelocation}" );
			if ( $error )
			{
				my $msg = "Could not change the rewrite location parameter.";
				&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
			}
		}
	}



	# no error found, return succesful response
	require Skudonet::API40::Farm::Get::HTTP;
	$output_params = &get_http_service_struct( $farmname, $service );

	if ( &getGlobalConfiguration( 'proxy_ng' ) ne 'true' )
	{
		delete ( $output_params->{ replaceRequestHeader } );
		delete ( $output_params->{ replaceResponseHeader } );
		delete ( $output_params->{ rewriteLocation } );
		delete ( $output_params->{ rewriteUrl } );
	}

	&zenlog(
		"Success, some parameters have been changed in service $service in farm $farmname.",
		"info", "FARMS"
	);

	my $body = {
				 description => "Modify service $service in farm $farmname",
				 params      => $output_params,
	};

	$body->{ message } =
	  $bk_msg ? $bk_msg : "The service $service has been updated successfully.";

	if ( &getFarmStatus( $farmname ) ne 'down' )
	{
		require Skudonet::Farm::Action;
		if ( &getGlobalConfiguration( 'proxy_ng' ) ne 'true' )
		{
			&setFarmRestart( $farmname );
			$body->{ status } = 'needed restart';
		}
		else
		{
			require Skudonet::Farm::HTTP::Config;
			my $config_error = &getHTTPFarmConfigErrorMessage( $farmname );
			if ( $config_error ne "" )
			{
				$body->{ warning } = "Farm '$farmname' config error: $config_error";
			}
			else
			{
				&runFarmReload( $farmname );
			}
		}
	}

	&httpResponse( { code => 200, body => $body } );
}

# DELETE

# DELETE /farms/<farmname>/services/<servicename> Delete a service of a Farm
sub delete_service    # ( $farmname, $service )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farmname, $service ) = @_;

	my $desc = "Delete service";

	# Check if the farm exists
	if ( !&getFarmExists( $farmname ) )
	{
		my $msg = "The farmname $farmname does not exist.";
		&httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	# check the farm type is supported
	my $type = &getFarmType( $farmname );

		if ( $type !~ /^https?$/ )
		{
			my $msg = "The farm profile $type does not support services actions.";
			&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
		}

	require Skudonet::Farm::Base;
	require Skudonet::Farm::HTTP::Service;

	# Check that the provided service is configured in the farm
	my @services = &getHTTPFarmServices( $farmname );
	my $found    = 0;

	foreach my $farmservice ( @services )
	{
		if ( $service eq $farmservice )
		{
			$found = 1;
			last;
		}
	}

	unless ( $found )
	{
		my $msg = "Invalid service name, please insert a valid value.";
		&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	my $error = &delHTTPFarmService( $farmname, $service );

	# check if the service is in use
	if ( $error == -2 )
	{
		my $msg = "The service is used by a zone.";
		&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	# check if the service could not be deleted
	if ( $error )
	{
		my $msg = "Service $service in farm $farmname hasn't been deleted.";
		&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	# no errors found, returning successful response
	&zenlog( "Success, the service $service has been deleted in farm $farmname.",
			 "info", "FARMS" );

	my $message = "The service $service has been deleted in farm $farmname.";
	my $body = {
				 description => $desc,
				 success     => "true",
				 message     => $message,
	};

	if ( &getFarmStatus( $farmname ) ne 'down' )
	{
		require Skudonet::Farm::Action;

		if ( &getGlobalConfiguration( 'proxy_ng' ) ne 'true' )
		{
			&setFarmRestart( $farmname );
			$body->{ status } = 'needed restart';
		}
		else
		{
			require Skudonet::Farm::HTTP::Config;
			my $config_error = &getHTTPFarmConfigErrorMessage( $farmname );
			if ( $config_error ne "" )
			{
				$body->{ warning } = "Farm '$farmname' config error: $config_error";
			}
			else
			{
				&runFarmReload( $farmname );
			}
		}
	}

	&httpResponse( { code => 200, body => $body } );
}

1;

