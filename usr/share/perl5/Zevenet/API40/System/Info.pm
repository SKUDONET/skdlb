#!/usr/bin/perl
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

require Zevenet::System;

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

	my $ss_filename = &getSupportSave();

	&httpDownloadResponse( desc => $desc, dir => '/tmp', file => $ss_filename );
}

# GET /system/version
sub get_version
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	require Zevenet::SystemInfo;
	require Zevenet::Certificate;

	my $desc    = "Get version";
	my $zevenet = &getGlobalConfiguration( 'version' );

	my $kernel     = &getKernelVersion();
	my $hostname   = &getHostname();
	my $date       = &getDate();
	my $applicance = &getApplianceVersion();

	my $params = {
				   'kernel_version'    => $kernel,
				   'zevenet_version'   => $zevenet,
				   'hostname'          => $hostname,
				   'system_date'       => $date,
				   'appliance_version' => $applicance,
	};
	my $body = { description => $desc, params => $params };

	&httpResponse( { code => 200, body => $body } );
}

sub set_factory_reset
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	my $json_obj = shift;
	my $desc     = "Apply a factory reset";

	my $params = {
				   "action" => {
								 'values'    => ["apply"],
								 'non_blank' => 'true',
								 'required'  => 'true',
				   },
				   "interface" => {
									'non_blank' => 'true',
									'required'  => 'true',
				   },
				   "remove_backups" => {
										 'values'    => ["true", "false"],
										 'non_blank' => 'true',
				   },
	};

	require Zevenet::Net::Interface;

	# Check allowed parameters
	my $error_msg = &checkZAPIParams( $json_obj, $params );
	return &httpErrorResponse( code => 400, desc => $desc, msg => $error_msg )
	  if ( $error_msg );

	## The interface must be of NIC type and it has to be configured
	my $if_ref = &getInterfaceConfig( $json_obj->{ interface } );
	if ( $if_ref->{ type } ne 'nic' )
	{
		my $msg = "The interface has to be of type NIC.";
		return &httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}
	elsif ( !$if_ref->{ addr } )
	{
		my $msg = "The interface has to be configured.";
		return &httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	my $remove_backups =
	  ( $json_obj->{ remove_backups } eq 'true' ) ? 'remove-backups' : '';
	if (
		 &applyFactoryReset( $json_obj->{ interface }, $json_obj->{ remove_backups } ) )
	{
		my $msg = "Some error occurred applying the factory reset.";
		return &httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	my $msg =
	  "The factroy reset was applied properly. The session will be lost. Please, try again in a while";
	my $body = { description => $desc, message => $msg };
	&httpResponse( { code => 200, body => $body } );
}

1;
