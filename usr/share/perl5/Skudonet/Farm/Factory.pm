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


=begin nd
Function: runFarmCreate

	Create a farm

Parameters:
	type - Farm type. The available options are: "http", "https", "datalink", "l4xnat" or "gslb"
	vip - Virtual IP where the virtual service is listening
	port - Virtual port where the virtual service is listening
	farmname - Farm name
	type - Specify if farm is HTTP or HTTPS
	iface - Inteface wich uses the VIP. This parameter is only used in datalink farms

Returns:
	Integer - return 0 on success or different of 0 on failure

FIXME:
	Use hash to pass the parameters
=cut

sub runFarmCreate    # ($farm_type,$vip,$vip_port,$farm_name,$fdev)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_type, $vip, $vip_port, $farm_name, $fdev ) = @_;

	my $output        = -1;
	my $farm_filename = &getFarmFile( $farm_name );

	if ( $farm_filename != -1 )
	{
		# the farm name already exists
		$output = -2;
		return $output;
	}

	my $status = 'up';
	if ( $farm_type ne 'datalink' )
	{
		require Skudonet::Net::Interface;
		$status = 'down'
		  if ( !&validatePort( $vip, $vip_port, $farm_type, $farm_name ) );
	}

	&zenlog( "running 'Create' for $farm_name farm $farm_type", "info", "LSLB" );

	if ( $farm_type =~ /^HTTPS?$/i )
	{
		require Skudonet::Farm::HTTP::Factory;
		$output =
		  &runHTTPFarmCreate( $vip, $vip_port, $farm_name, $farm_type, $status );
	}
	elsif ( $farm_type =~ /^DATALINK$/i )
	{
		require Skudonet::Farm::Datalink::Factory;
		$output = &runDatalinkFarmCreate( $farm_name, $vip, $fdev );
	}
	elsif ( $farm_type =~ /^L4xNAT$/i )
	{
		require Skudonet::Farm::L4xNAT::Factory;
		$output = &runL4FarmCreate( $vip, $farm_name, $vip_port, $status );
	}

	return $output;
}

=begin nd
Function: runFarmCreateFrom

	Function that does a copy of a farm and set the new virtual ip and virtual port.
	Apply the same farguardians to the services and the same ipds rules.

Parameters:
	params - hash reference. The hash has to contain the following keys:
		profile: is the type of profile is going to be copied
		farmname: the name of the new farm
		copy_from: it is the name of the farm from is copying
		vip: the new virtual ip for the new farm
		vport: the new virtual port for the new farm. This parameters is skipped in datalink farms
		interface: it is the interface for the new farm. This parameter is for datalink farms

Returns:
	Integer - Error code: return 0 on success or another value on failure

=cut

sub runFarmCreateFrom
{
	my $params = shift;
	my $err    = 0;

	# lock farm
	require Skudonet::Lock;
	my $lock_file = &getLockFile( $params->{ farmname } );
	my $lock_fh   = &openlock( $lock_file, 'w' );


	# create file
	require Skudonet::Farm::Action;
	$err = &copyFarm( $params->{ copy_from }, $params->{ farmname } );

	# add fg
	require Skudonet::FarmGuardian;
	if ( $params->{ profile } eq 'l4xnat' )
	{
		my $fg = &getFGFarm( $params->{ copy_from } );
		&linkFGFarm( $fg, $params->{ farmname } );
	}
	elsif ( $params->{ profile } ne 'datalink' )
	{
		my $fg;
		require Skudonet::Farm::Service;
		foreach my $s ( &getFarmServices( $params->{ farmname } ) )
		{
			$fg = &getFGFarm( $params->{ copy_from }, $s );
			&linkFGFarm( $fg, $params->{ farmname }, $s );
		}
	}

	# unlock farm
	close $lock_fh;

	# modify vport, vip, interface
	if ( $params->{ profile } ne 'datalink' )
	{
		require Skudonet::Farm::Config;
		$err = &setFarmVirtualConf(
									$params->{ vip },
									$params->{ vport },
									$params->{ farmname }
		);
	}
	else
	{
		require Skudonet::Farm::Datalink::Config;
		$err = &setDatalinkFarmVirtualConf(
											$params->{ vip },
											$params->{ interface },
											$params->{ farmname }
		);
	}


	if ( ( $params->{ profile } eq 'l4xnat' ) and ( !$err ) )
	{
		require Skudonet::Net::Interface;
		if (
			 &validatePort(
							$params->{ vip },
							$params->{ vport },
							'l4xnat',
							$params->{ farmname }
			 )
		  )
		{
			$err = &startL4Farm( $params->{ farmname } );
		}
	}

	return $err;
}

1;

