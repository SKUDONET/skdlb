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
use Skudonet::Config;
use Skudonet::Farm::Core;
use Skudonet::Farm::Base;


#GET /farms
sub farms    # ()
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	require Skudonet::Farm::Base;

	my @out;
	my @files = &getFarmList();

	foreach my $file ( @files )
	{
		my $name   = &getFarmName( $file );
		my $type   = &getFarmType( $name );
		my $status = &getFarmVipStatus( $name );
		my $vip    = &getFarmVip( 'vip',  $name );
		my $port   = &getFarmVip( 'vipp', $name );

		push @out,
		  {
			farmname => $name,
			profile  => $type,
			status   => $status,
			vip      => $vip,
			vport    => $port
		  };
	}

	my $body = {
				 description => "List farms",
				 params      => \@out,
	};

	&httpResponse( { code => 200, body => $body } );
}

# GET /farms/LSLBFARM
sub farms_lslb    # ()
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	require Skudonet::Farm::Base;

	my @out;
	my @files = &getFarmList();

	foreach my $file ( @files )
	{
		my $name = &getFarmName( $file );
		my $type = &getFarmType( $name );
		next unless $type =~ /^(?:https?|l4xnat)$/;
		my $status = &getFarmVipStatus( $name );
		my $vip    = &getFarmVip( 'vip',  $name );
		my $port   = &getFarmVip( 'vipp', $name );

		push @out,
		  {
			farmname => $name,
			profile  => $type,
			status   => $status,
			vip      => $vip,
			vport    => $port
		  };
	}


	my $body = {
				 description => "List LSLB farms",
				 params      => \@out,
	};

	&httpResponse( { code => 200, body => $body } );
}

# GET /farms/DATALINKFARM
sub farms_dslb    # ()
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	require Skudonet::Farm::Base;

	my @out;
	my @files = &getFarmList();

	foreach my $file ( @files )
	{
		my $name = &getFarmName( $file );
		my $type = &getFarmType( $name );
		next unless $type eq 'datalink';
		my $status = &getFarmVipStatus( $name );
		my $vip    = &getFarmVip( 'vip',  $name );
		my $iface  = &getFarmVip( 'vipp', $name );

		push @out,
		  {
			farmname  => $name,
			status    => $status,
			vip       => $vip,
			interface => $iface
		  };
	}


	my $body = {
				 description => "List DSLB farms",
				 params      => \@out,
	};

	&httpResponse( { code => 200, body => $body } );
}

#GET /farms/<name>/summary
sub farms_name_summary    # ( $farmname )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farmname = shift;

	my $desc = "Show farm $farmname";

	# Check if the farm exists
	if ( !&getFarmExists( $farmname ) )
	{
		my $msg = "Farm not found.";
		&httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	my $type = &getFarmType( $farmname );
	if ( $type =~ /https?/ )
	{
		require Skudonet::API40::Farm::Get::HTTP;
		&farms_name_http_summary( $farmname );
	}
	else
	{
		&farms_name( $farmname );
	}
}

#GET /farms/<name>
sub farms_name    # ( $farmname )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farmname = shift;

	my $desc = "Show farm $farmname";

	# Check if the farm exists
	if ( !&getFarmExists( $farmname ) )
	{
		my $msg = "Farm not found.";
		&httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	my $type = &getFarmType( $farmname );

	if ( $type =~ /https?/ )
	{
		require Skudonet::API40::Farm::Get::HTTP;
		&farms_name_http( $farmname );
	}
	if ( $type eq 'l4xnat' )
	{
		require Skudonet::API40::Farm::Get::L4xNAT;
		&farms_name_l4( $farmname );
	}
	if ( $type eq 'datalink' )
	{
		require Skudonet::API40::Farm::Get::Datalink;
		&farms_name_datalink( $farmname );
	}
}

#GET /farms/<name>/status
sub farms_name_status    # ( $farmname )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farmname = shift;

	my $desc = "Show farm $farmname status";

	# Check if the farm exists
	if ( !&getFarmExists( $farmname ) )
	{
		my $msg = "Farm not found.";
		&httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	my $status = &getFarmVipStatus( $farmname );

	# Output
	my $body = {
				 description => $desc,
				 params      => { status => $status },
	};

	&httpResponse( { code => 200, body => $body } );
}

# function to standarizate the backend output
sub getAPIFarmBackends
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $out_b        = shift;
	my $type         = shift;
	my $add_api_keys = shift // [];
	my $translate    = shift // {};
	my @api_keys     = @{ $add_api_keys };

	require Skudonet::Farm::Backend;

	# Backends
	die "Waiting a hash input" if ( !ref $out_b );

	# filters:
	if ( $type eq 'l4xnat' )
	{
		push @api_keys, qw(id weight port ip priority status max_conns);
	}
	elsif ( $type eq 'datalink' )
	{
		push @api_keys, qw(id weight ip priority status interface);
	}
	elsif ( $type =~ /http/ )
	{
		if ( &getGlobalConfiguration( 'proxy_ng' ) eq 'true' )
		{
			push @api_keys, qw(id ip port priority status timeout weight connection_limit);
		}
		else
		{
			push @api_keys, qw(id ip port weight status timeout);
		}
	}

	# add static translations
	$translate->{ status } = { "fgdown" => "down", "undefined" => "up" };

	&buildAPIParams( $out_b, \@api_keys, $translate );


	return undef;
}

# GET /farms/modules/summary
sub farms_module_summary
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	require Skudonet::Farm::Service;
	my $out = { lslb => [], dslb => [], };

	my $action_srv = 0;
	foreach my $farm_name ( &getFarmNameList() )
	{
		my $type = &getFarmType( $farm_name );
		$type =~ s/https/http/;
		my $it = {
				   name    => $farm_name,
				   profile => $type,
		};

		$action_srv = 1 if ( $type eq 'http' );
		if ( $action_srv )
		{
			my @srv = &getFarmServices( $farm_name );
			$it->{ services } = \@srv;
		}

		if ( $type eq 'datalink' ) { push @{ $out->{ dslb } }, $it; }
		else { push @{ $out->{ lslb } }, $it; }
		$action_srv = 0;
	}

	my $body = {
				 description => "Farm Modules summary",
				 params      => $out,
	};
	return &httpResponse( { code => 200, body => $body } );
}

1;

