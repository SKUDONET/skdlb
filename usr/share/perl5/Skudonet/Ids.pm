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

use Skudonet::Log;
use Skudonet::Config;
use Config::Tiny;


# string to use when a branch of the id tree finishes
my $FIN = undef;

sub getIdsTree
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	require Skudonet::Farm::Core;
	require Skudonet::FarmGuardian;
	require Skudonet::Net::Interface;
	require Skudonet::Certificate;
	require Skudonet::Backup;
	require Skudonet::System::Log;

	my $l4_default_srv_tag = "default_service";

	my $tree = $FIN;

	$tree->{ 'farms' } = $FIN;
	foreach my $type ( 'https', 'http', 'l4xnat', 'gslb', 'datalink' )
	{
		my @farms = &getFarmsByType( $type );

		# add farm
		foreach my $f ( @farms )
		{
			require Skudonet::Farm::Service;
			$tree->{ 'farms' }->{ $f }->{ 'services' } = $FIN;

			# add srv
			my @srv =
			  ( $type =~ /http|gslb/ ) ? &getFarmServices( $f ) : ( $l4_default_srv_tag );
			foreach my $s ( @srv )
			{
				require Skudonet::Farm::Backend;

				$tree->{ 'farms' }->{ $f }->{ 'services' }->{ $s }->{ 'backends' } = $FIN;

				# add bk
				my $bks = &getFarmServerIds( $f, $s );

				foreach my $b ( @{ $bks } )
				{
					$tree->{ 'farms' }->{ $f }->{ 'services' }->{ $s }->{ 'backends' }->{ $b } =
					  $FIN;
				}

				my $fg = &getFGFarm( $f, ( $type =~ /datalink|l4xnat/ ) ? undef : $s );
				$tree->{ 'farms' }->{ $f }->{ 'services' }->{ $s }->{ 'fg' }->{ $fg } = $FIN
				  if ( $fg ne '' );
			}

			# add certificates
			if ( $type =~ /http/ )
			{
				my @cnames;
					require Skudonet::Farm::HTTP::HTTPS;
					@cnames = ( &getFarmCertificate( $f ) );
				$tree->{ 'farms' }->{ $f }->{ 'certificates' } = &addIdsArrays( \@cnames );
			}

		}
	}

	# add fg
	my @fg = &getFGList();
	$tree->{ 'farmguardians' } = &addIdsArrays( \@fg );

	# add ssl certs
	my @certs = &getCertFiles();
	$tree->{ 'certificates' } = &addIdsArrays( \@certs );

	# add interfaces
	my @if_list = ( 'nic', 'vlan', 'virtual' );
	foreach my $type ( @if_list )
	{
		my $if_key;
			$if_key = $type;

		$tree->{ 'interfaces' }->{ $if_key } = $FIN;

		my @list = &getInterfaceTypeList( $type );
		foreach my $if ( @list )
		{
			$tree->{ 'interfaces' }->{ $if_key }->{ $if->{ name } } = $FIN;
		}
	}


	# add backups
	my $backups = &getBackup();
	foreach my $b ( @{ $backups } )
	{
		$tree->{ 'system' }->{ 'backup' }->{ $b->{ name } } = $FIN;
	}

	# add logs
	my $logs = &getLogs();
	$tree->{ 'system' }->{ 'logs' } = $FIN;
	foreach my $l ( @{ $logs } )
	{
		$tree->{ 'system' }->{ 'logs' }->{ $l->{ file } } = $FIN;
	}

	return $tree;
}

sub addIdsKeys
{
	my $hash_ref = shift;
	my @arr_keys = keys %{ $hash_ref };
	return &addIdsArrays( \@arr_keys );
}

sub addIdsArrays
{
	my $arr = shift;
	my $out = {};

	foreach my $it ( @{ $arr } )
	{
		$out->{ $it } = $FIN;
	}

	return ( !keys %{ $out } ) ? undef : $out;
}

1;

