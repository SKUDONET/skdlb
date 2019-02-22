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
use Zevenet::Farm::HTTP::Config;

# farm parameters
sub getHTTPOutFarm
{
	require Zevenet::Farm::Config;
	my $farmname = shift;
	my $farm_ref = &getFarmStruct( $farmname );
	return $farm_ref;
}

sub getHTTPOutService
{
	require Zevenet::Farm::HTTP::Service;
	my $farmname     = shift;
	my $services_ref = &get_http_all_services_struct( $farmname );
	return $services_ref;
}

sub getHTTPOutBackend
{

}

1;
