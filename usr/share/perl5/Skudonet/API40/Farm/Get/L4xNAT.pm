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
use Skudonet::FarmGuardian;
use Skudonet::Farm::Config;
use Skudonet::Farm::Backend;
use Skudonet::Farm::L4xNAT::Config;


# GET /farms/<farmname> Request info of a l4xnat Farm
sub farms_name_l4    # ( $farmname )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farmname = shift;

	my $out_p;

	my $farm   = &getL4FarmStruct( $farmname );
	my $status = &getFarmVipStatus( $farmname );

	require Skudonet::Farm::L4xNAT::Sessions;
	$out_p = {
		status      => $status,
		vip         => $farm->{ vip },
		vport       => $farm->{ vport },
		algorithm   => $farm->{ lbalg },
		nattype     => $farm->{ nattype },
		persistence => $farm->{ persist },
		ttl         => $farm->{ ttl } + 0,
		protocol    => $farm->{ vproto },

		farmguardian => &getFGFarm( $farmname ),
		listener     => 'l4xnat',
		sessions     => &listL4FarmSessions( $farmname )
	};


	# Backends
	my $out_b = &getFarmServers( $farmname );
	&getAPIFarmBackends( $out_b, 'l4xnat' );

	my $body = {
				 description => "List farm $farmname",
				 params      => $out_p,
				 backends    => $out_b,
	};


	&httpResponse( { code => 200, body => $body } );
}

1;

