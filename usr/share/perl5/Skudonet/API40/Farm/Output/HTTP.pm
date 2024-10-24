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

# farm parameters
sub getHTTPOutFarm
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	require Skudonet::Farm::Config;
	my $farmname = shift;
	my $farm_ref = &getFarmStruct( $farmname );

	# Remove useless fields
	delete ( $farm_ref->{ name } );
	return $farm_ref;
}

sub getHTTPOutService
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	require Skudonet::Farm::HTTP::Service;
	my $farmname      = shift;
	my @services_list = ();

	foreach my $service ( &getHTTPFarmServices( $farmname ) )
	{
		my $service_ref = &getHTTPServiceStruct( $farmname, $service );
		push @services_list, $service_ref;
	}

	return \@services_list;
}

sub getHTTPOutBackend
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

}

1;

