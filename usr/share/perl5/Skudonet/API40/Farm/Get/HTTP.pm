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
use Skudonet::Farm::HTTP::Config;


# GET /farms/<farmname> Request info of a http|https Farm
sub farms_name_http    # ( $farmname )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farmname = shift;

	# Get farm reference
	require Skudonet::API40::Farm::Output::HTTP;
	my $farm_ref = &getHTTPOutFarm( $farmname );

	# Get farm services reference
	require Skudonet::Farm::HTTP::Service;
	my $services_ref = &getHTTPOutService( $farmname );

	# Output
	my $body = {
				 description => "List farm $farmname",
				 params      => $farm_ref,
				 services    => $services_ref,
	};

		require Skudonet::IPDS::WAF::Core;
		$body->{ ipds } = &getIPDSWAFFarmRules( $farmname );

	&httpResponse( { code => 200, body => $body } );
}

# GET /farms/<farmname>/summary
sub farms_name_http_summary
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farmname = shift;

	# Get farm reference
	require Skudonet::API40::Farm::Output::HTTP;
	my $farm_ref = &getHTTPOutFarm( $farmname );

	# Services
	require Skudonet::Farm::HTTP::Service;

	my $services_ref = &get_http_all_services_summary_struct( $farmname );

	my $body = {
				 description => "List farm $farmname",
				 params      => $farm_ref,
				 services    => $services_ref,
	};

		require Skudonet::IPDS::WAF::Core;
		$body->{ ipds } = &getIPDSWAFFarmRules( $farmname );

	&httpResponse( { code => 200, body => $body } );
}

1;

