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


sub get_farm_struct
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farmname = shift;
	my $output_params;

	my @out_cn;
	my $connto          = 0 + &getFarmConnTO( $farmname );
	my $timeout         = 0 + &getHTTPFarmTimeout( $farmname );
	my $alive           = 0 + &getHTTPFarmBlacklistTime( $farmname );
	my $client          = 0 + &getFarmClientTimeout( $farmname );
	my $rewritelocation = &getFarmRewriteL( $farmname );
	my $httpverb        = 0 + &getFarmHttpVerb( $farmname );

	if    ( $httpverb == 0 ) { $httpverb = "standardHTTP"; }
	elsif ( $httpverb == 1 ) { $httpverb = "extendedHTTP"; }
	elsif ( $httpverb == 2 ) { $httpverb = "standardWebDAV"; }
	elsif ( $httpverb == 3 ) { $httpverb = "MSextWebDAV"; }
	elsif ( $httpverb == 4 ) { $httpverb = "MSRPCext"; }
	elsif ( $httpverb == 5 ) { $httpverb = "optionsHTTP"; }

	my $type = &getFarmType( $farmname );
	my $certname;
	my $cipher  = '';
	my $ciphers = 'all';
	my @cnames;

	if ( $type eq "https" )
	{
		require Skudonet::Farm::HTTP::HTTPS;

			@cnames = ( &getFarmCertificate( $farmname ) );

		for ( my $i = 0 ; $i < scalar @cnames ; $i++ )
		{
			push @out_cn, { file => $cnames[$i], id => $i + 1 };
		}

		$cipher  = &getFarmCipherList( $farmname );
		$ciphers = &getFarmCipherSet( $farmname );
		chomp ( $ciphers );

		# adapt "ciphers" to required interface values
		if ( $ciphers eq "cipherglobal" )
		{
			$ciphers = "all";
		}
		elsif ( $ciphers eq "cipherssloffloading" )
		{
			$ciphers = "cipherssloffloading";
		}
		elsif ( $ciphers eq "cipherpci" )
		{
			$ciphers = "highsecurity";
		}
		else
		{
			$ciphers = "customsecurity";
		}
	}

	my $vip   = &getFarmVip( "vip", $farmname );
	my $vport = 0 + &getFarmVip( "vipp", $farmname );

	my $err414 = &getFarmErr( $farmname, "414" );
	my $err500 = &getFarmErr( $farmname, "500" );
	my $err501 = &getFarmErr( $farmname, "501" );
	my $err503 = &getFarmErr( $farmname, "503" );

	my $status = &getFarmVipStatus( $farmname );

	my $output_params = {
						  status          => $status,
						  restimeout      => $timeout,
						  contimeout      => $connto,
						  resurrectime    => $alive,
						  reqtimeout      => $client,
						  rewritelocation => $rewritelocation,
						  httpverb        => $httpverb,
						  listener        => $type,
						  vip             => $vip,
						  vport           => $vport,
						  error500        => $err500,
						  error414        => $err414,
						  error501        => $err501,
						  error503        => $err503
	};

	#translate 100 continue parameter
	my $ignore_100_continue = &getHTTPFarm100Continue( $farmname );
	$output_params->{ ignore_100_continue } =
	  ( $ignore_100_continue eq "pass" ) ? "false" : "true";

	if ( $type eq "https" )
	{
		$output_params->{ certlist } = \@out_cn;
		$output_params->{ ciphers }  = $ciphers;
		$output_params->{ cipherc }  = $cipher;
		$output_params->{ disable_sslv2 } =
		  ( &getHTTPFarmDisableSSL( $farmname, "SSLv2" ) ) ? "true" : "false";
		$output_params->{ disable_sslv3 } =
		  ( &getHTTPFarmDisableSSL( $farmname, "SSLv3" ) ) ? "true" : "false";
		$output_params->{ disable_tlsv1 } =
		  ( &getHTTPFarmDisableSSL( $farmname, "TLSv1" ) ) ? "true" : "false";
		$output_params->{ disable_tlsv1_1 } =
		  ( &getHTTPFarmDisableSSL( $farmname, "TLSv1_1" ) ) ? "true" : "false";
		$output_params->{ disable_tlsv1_2 } =
		  ( &getHTTPFarmDisableSSL( $farmname, "TLSv1_2" ) ) ? "true" : "false";
	}

	return $output_params;
}

# GET /farms/<farmname> Request info of a http|https Farm
sub farms_name_http    # ( $farmname )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farmname = shift;

	require Skudonet::Farm::HTTP::Service;
	require Skudonet::FarmGuardian;

	my $farm_st = &get_farm_struct( $farmname );
	my @out_s;

	delete $farm_st->{ replacerequestheader };
	delete $farm_st->{ replaceresponseheader };
	delete $farm_st->{ errorWAF };

	# Services
	my @serv = &getHTTPFarmServices( $farmname );

	foreach my $s ( @serv )
	{
		my $serviceStruct = &getZapiHTTPServiceStruct( $farmname, $s );

		delete $serviceStruct->{ addrequestheader };
		delete $serviceStruct->{ addresponseheader };
		delete $serviceStruct->{ removerequestheader };
		delete $serviceStruct->{ removeresponseheader };
		delete $serviceStruct->{ replacerequestheader };
		delete $serviceStruct->{ replaceresponseheader };
		delete $serviceStruct->{ rewriteurl };
		delete $serviceStruct->{ rewritelocation };
		delete $serviceStruct->{ pinnedconnection };
		delete $serviceStruct->{ routingpolicy };

		# Remove backend status 'undefined', it is for news api versions
		foreach my $be ( @{ $serviceStruct->{ 'backends' } } )
		{
			$be->{ 'status' } = 'up' if ( $be->{ 'status' } eq 'undefined' );
			delete $be->{ tag };
			delete $be->{ connection_limit };
		}
		push @out_s, $serviceStruct;
	}

	my $body = {
				 description => "List farm $farmname",
				 params      => $farm_st,
				 services    => \@out_s,
	};


	&httpResponse( { code => 200, body => $body } );
}

# GET /farms/<farmname>/summary
sub farms_name_http_summary
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farmname = shift;

	require Skudonet::Farm::HTTP::Service;

	my $farm_st = &get_farm_struct( $farmname );
	my @out_s;

	# Services
	my @serv = &getHTTPFarmServices( $farmname );

	foreach my $s ( @serv )
	{
		push @out_s, { 'id' => $s };
	}

	my $body = {
				 description => "List farm $farmname",
				 params      => $farm_st,
				 services    => \@out_s,
	};


	&httpResponse( { code => 200, body => $body } );
}

sub getZapiHTTPServiceStruct
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farmname, $service_name ) = @_;

	require Skudonet::FarmGuardian;
	require Skudonet::Farm::HTTP::Backend;

	my $service_ref = -1;

	# http services
	my @serv = &getHTTPFarmServices( $farmname );

	# return error if service is not found
	return $service_ref unless grep ( { $service_name eq $_ } @serv );

	my $vser         = &getHTTPFarmVS( $farmname, $service_name, "vs" );
	my $urlp         = &getHTTPFarmVS( $farmname, $service_name, "urlp" );
	my $redirect     = &getHTTPFarmVS( $farmname, $service_name, "redirect" );
	my $redirecttype = &getHTTPFarmVS( $farmname, $service_name, "redirecttype" );
	my $session      = &getHTTPFarmVS( $farmname, $service_name, "sesstype" );
	my $ttl          = &getHTTPFarmVS( $farmname, $service_name, "ttl" );
	my $sesid        = &getHTTPFarmVS( $farmname, $service_name, "sessionid" );
	my $dyns         = &getHTTPFarmVS( $farmname, $service_name, "dynscale" );
	my $httpsbe      = &getHTTPFarmVS( $farmname, $service_name, "httpsbackend" );

	if ( $dyns =~ /^$/ )
	{
		$dyns = "false";
	}
	if ( $httpsbe =~ /^$/ )
	{
		$httpsbe = "false";
	}

	my @fgconfig  = &getFarmGuardianConf( $farmname, $service_name );
	my $fgttcheck = $fgconfig[1] + 0;
	my $fgscript  = $fgconfig[2];
	my $fguse     = $fgconfig[3];
	my $fglog     = $fgconfig[4];

	# Default values for farm guardian parameters
	if ( !$fgttcheck ) { $fgttcheck = 5; }
	if ( !$fguse )     { $fguse     = "false"; }
	if ( !$fglog )     { $fglog     = "false"; }
	if ( !$fgscript )  { $fgscript  = ""; }

	$fgscript =~ s/\n//g;
	$fguse    =~ s/\n//g;

	my $backends = &getHTTPFarmBackends( $farmname, $service_name );

	$ttl       = 0 unless $ttl;
	$fgttcheck = 0 unless $fgttcheck;

	$service_ref = {
					 id           => $service_name,
					 vhost        => $vser,
					 urlp         => $urlp,
					 redirect     => $redirect,
					 redirecttype => $redirecttype,
					 persistence  => $session,
					 ttl          => $ttl + 0,
					 sessionid    => $sesid,
					 leastresp    => $dyns,
					 httpsb       => $httpsbe,
					 backends     => $backends,
					 fgtimecheck  => $fgttcheck,
					 fglog        => $fglog,
					 fgenabled    => $fguse,
					 fgscript     => $fgscript,
	};


	return $service_ref;
}

1;
