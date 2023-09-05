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

my $eload;
if ( eval { require Skudonet::ELoad; } )
{
	$eload = 1;
}

require Skudonet::System;

# show license
sub get_license
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $format = shift;

	my $desc = "Get license";
	my $licenseFile;

	if ( $format eq 'txt' )
	{
		$licenseFile = &getGlobalConfiguration( 'licenseFileTxt' );
	}
	elsif ( $format eq 'html' )
	{
		$licenseFile = &getGlobalConfiguration( 'licenseFileHtml' );
	}
	else
	{
		my $msg = "Not found license.";
		&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	my $file = &slurpFile( $licenseFile );

	&httpResponse( { code => 200, body => $file, type => 'text/plain' } );
}

sub get_supportsave
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $desc = "Get supportsave file";

	my $req_size = &checkSupportSaveSpace();
	if ( $req_size )
	{
		my $space = &getSpaceFormatHuman( $req_size );
		my $msg =
		  "Supportsave cannot be generated because '/tmp' needs '$space' Bytes of free space";
		return &httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	my $ss_filename = &getSupportSave();

	&httpDownloadResponse( desc => $desc, dir => '/tmp', file => $ss_filename );
}

# GET /system/version
sub get_version
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	require Skudonet::SystemInfo;

	my $desc       = "Get version";
	my $skudonet    = &getGlobalConfiguration( 'version' );
	my $kernel     = &getKernelVersion();
	my $hostname   = &getHostname();
	my $date       = &getDate();
	my $applicance = &getApplianceVersion();

	my $params = {
				   'kernel_version'    => $kernel,
				   'skudonet_version'   => $skudonet,
				   'hostname'          => $hostname,
				   'system_date'       => $date,
				   'appliance_version' => $applicance,
	};
	my $body = { description => $desc, params => $params };

	&httpResponse( { code => 200, body => $body } );
}

# GET /system/info
sub get_system_info
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	require Skudonet::SystemInfo;
	require Skudonet::User;
	require Skudonet::Zapi;

	my $desc = "Get the system information";

	my $skudonet       = &getGlobalConfiguration( 'version' );
	my $lang          = &getGlobalConfiguration( 'lang' );
	my $kernel        = &getKernelVersion();
	my $hostname      = &getHostname();
	my $date          = &getDate();
	my $applicance    = &getApplianceVersion();
	my $user          = &getUser();
	my @zapi_versions = &listZapiVersions();
	my $edition       = ( $eload ) ? "enterprise" : "community";
	my $platform      = &getGlobalConfiguration( 'cloud_provider' );

	my $params = {
				   'system_date'             => $date,
				   'appliance_version'       => $applicance,
				   'kernel_version'          => $kernel,
				   'skudonet_version'         => $skudonet,
				   'hostname'                => $hostname,
				   'user'                    => $user,
				   'supported_zapi_versions' => \@zapi_versions,
				   'last_zapi_version'       => $zapi_versions[-1],
				   'edition'                 => $edition,
				   'language'                => $lang,
				   'platform'                => $platform,
	};

	if ( $eload )
	{
		$params = &eload(
						  module => 'Skudonet::System::Ext',
						  func   => 'setSystemExtendZapi',
						  args   => [$params],
		);
	}

	my $body = { description => $desc, params => $params };
	&httpResponse( { code => 200, body => $body } );
}

#  POST /system/language
sub set_language
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $json_obj = shift;

	my $desc = "Modify the WebGUI language";

	my $params = &getZAPIModel( "system_language-modify.json" );

	# Check allowed parameters
	my $error_msg = &checkZAPIParams( $json_obj, $params, $desc );
	return &httpErrorResponse( code => 400, desc => $desc, msg => $error_msg )
	  if ( $error_msg );

	# Check allowed parameters
	&setGlobalConfiguration( 'lang', $json_obj->{ language } );

	&httpResponse(
				{
				  code => 200,
				  body => {
							description => $desc,
							params      => { language => &getGlobalConfiguration( 'lang' ) },
							message => "The WebGui language has been configured successfully"
				  }
				}
	);
}

#  GET /system/language
sub get_language
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	my $desc = "List the WebGUI language";
	my $lang = &getGlobalConfiguration( 'lang' ) // 'en';

	&httpResponse(
				   {
					 code => 200,
					 body => {
							   description => $desc,
							   params      => { lang => $lang },
					 }
				   }
	);
}

# GET /system/packages
sub get_packages_info
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	require Skudonet::System::Packages;
	my $desc = "Skudonet packages list info";
	my $output;

	$output = &getSystemPackagesUpdatesList();

	$output->{ number } += 0 if ( defined $output->{ number } );

	return &httpResponse(
				 { code => 200, body => { description => $desc, params => $output } } );
}

1;
