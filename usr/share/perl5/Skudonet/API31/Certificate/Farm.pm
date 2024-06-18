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
use Skudonet::Farm::Base;


	require Skudonet::Farm::HTTP::HTTPS;

# POST /farms/FARM/certificates (Add certificate to farm)
sub add_farm_certificate    # ( $json_obj, $farmname )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $json_obj = shift;
	my $farmname = shift;

	my $desc = "Add certificate to farm '$farmname'";

	# Check if the farm exists
	if ( !&getFarmExists( $farmname ) )
	{
		my $msg = "Farm not found";
		&httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	my $certdir     = &getGlobalConfiguration( 'certdir' );
	my $cert_pem_re = &getValidFormat( 'cert_pem' );

	# validate certificate filename and format
	unless ( -f $certdir . "/" . $json_obj->{ file }
			 && &getValidFormat( 'cert_pem', $json_obj->{ file } ) )
	{
		my $msg = "Invalid certificate name, please insert a valid value.";
		&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	my $cert_in_use;
		$cert_in_use = &getFarmCertificate( $farmname ) eq $json_obj->{ file };

	if ( $cert_in_use )
	{
		my $msg = "The certificate already exists in the farm.";
		&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	# FIXME: Show error if the certificate is already in the list
	my $status;
		$status = &setFarmCertificate( $json_obj->{ file }, $farmname );

	if ( $status )
	{
		my $msg =
		  "It's not possible to add the certificate with name $json_obj->{file} for the $farmname farm";

		&zenlog( "It's not possible to add the certificate.", "warning", "LSLB" );
		&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	# no errors found, return succesful response
	&zenlog( "Success, trying to add a certificate to the farm.", "info", "LSLB" );

	my $message =
	  "The certificate $json_obj->{file} has been added to the farm $farmname, you need restart the farm to apply";

	my $body = {
				 description => $desc,
				 success     => "true",
				 message     => $message,
	};

	if ( &getFarmStatus( $farmname ) eq 'up' )
	{
		require Skudonet::Farm::Action;

		if ( &getGlobalConfiguration( 'proxy_ng' ) ne 'true' )
		{
			&setFarmRestart( $farmname );
			$body->{ status } = 'needed restart';
		}
		else
		{
			&runFarmReload( $farmname );
		}
	}

	&httpResponse( { code => 200, body => $body } );
}

# DELETE /farms/FARM/certificates/CERTIFICATE
sub delete_farm_certificate    # ( $farmname, $certfilename )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farmname     = shift;
	my $certfilename = shift;

	my $desc = "Delete farm certificate";

		my $msg = "HTTPS farm without certificate is not allowed.";
		&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
}

1;
