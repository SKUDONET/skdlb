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


my $configdir = &getGlobalConfiguration( 'configdir' );

=begin nd
Function: setFarmHTTPNewService

	Create a new Service in a HTTP farm

Parameters:
	farmname - Farm name
	service - Service name

Returns:
	Integer - Error code: 0 on success, other value on failure

FIXME:
	This function returns nothing, do error control

=cut

sub setFarmHTTPNewService    # ($farm_name,$service)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $service ) = @_;

	use File::Grep 'fgrep';
	require Tie::File;
	require Skudonet::Lock;
	require Skudonet::Farm::Config;

	my $output = -1;

	#first check if service name exist
	if ( $service =~ /(?=)/ && $service =~ /^$/ )
	{
		#error 2 eq $service is empty
		$output = 2;
		return $output;
	}

	if ( !fgrep { /^\s*Service "$service"/ } "$configdir/$farm_name\_proxy.cfg" )
	{
		#create service
		my @newservice;
		my $sw       = 0;
		my $count    = 0;
		my $proxytpl = &getGlobalConfiguration( 'proxytpl' );
		tie my @proxytpl, 'Tie::File', "$proxytpl";

		foreach my $line ( @proxytpl )
		{
			if ( $line =~ /Service \"\[DESC\]\"/ )
			{
				$sw = 1;
			}

			if ( $sw eq "1" )
			{
				push ( @newservice, $line );
			}

			if ( $line =~ /End/ )
			{
				$count++;
			}

			if ( $count eq "4" )
			{
				last;
			}
		}
		untie @proxytpl;

		$newservice[0] =~ s/#//g;
		$newservice[$#newservice] =~ s/#//g;

		my $lock_file = &getLockFile( $farm_name );
		my $lock_fh   = &openlock( $lock_file, 'w' );

		my @fileconf;
		if ( !fgrep { /^\s*Service "$service"/ } "$configdir/$farm_name\_proxy.cfg" )
		{
			tie @fileconf, 'Tie::File', "$configdir/$farm_name\_proxy.cfg";
			my $i         = 0;
			my $farm_type = "";
			$farm_type = &getFarmType( $farm_name );

			foreach my $line ( @fileconf )
			{
				if ( $line =~ /#ZWACL-END/ )
				{
					$output = 0;
					foreach my $lline ( @newservice )
					{
						if ( $lline =~ /\[DESC\]/ )
						{
							$lline =~ s/\[DESC\]/$service/;
						}
						if (    $lline =~ /StrictTransportSecurity/
							 && $farm_type eq "https" )
						{
							$lline =~ s/#//;
						}
						splice @fileconf, $i, 0, "$lline";
						$i++;
					}
					last;
				}
				$i++;
			}
		}
		untie @fileconf;
		close $lock_fh;
	}
	else
	{
		$output = 1;
	}

	return $output;
}

=begin nd
Function: setFarmHTTPNewServiceFirst

	Create a new Service in a HTTP farm on first position

Parameters:
	farmname - Farm name
	service - Service name

Returns:
	Integer - Error code: 0 on success, other value on failure

=cut

sub setFarmHTTPNewServiceFirst    # ($farm_name,$service)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $service ) = @_;

	use File::Grep 'fgrep';
	require Tie::File;
	require Skudonet::Lock;
	require Skudonet::Farm::Config;

	my $output = -1;

	#first check if service name exist
	if ( $service =~ /(?=)/ && $service =~ /^$/ )
	{
		#error 2 eq $service is empty
		$output = 2;
		return $output;
	}

	if ( !fgrep { /^\s*Service "$service"/ } "$configdir/$farm_name\_proxy.cfg" )
	{
		#create service
		my @newservice;
		my $sw       = 0;
		my $count    = 0;
		my $proxytpl = &getGlobalConfiguration( 'proxytpl' );
		tie my @proxytpl, 'Tie::File', "$proxytpl";

		foreach my $line ( @proxytpl )
		{
			if ( $line =~ /Service \"\[DESC\]\"/ )
			{
				$sw = 1;
			}

			if ( $sw eq "1" )
			{
				push ( @newservice, $line );
			}

			if ( $line =~ /End/ )
			{
				$count++;
			}

			if ( $count eq "4" )
			{
				last;
			}
		}
		untie @proxytpl;

		$newservice[0] =~ s/#//g;
		$newservice[$#newservice] =~ s/#//g;

		my $lock_file = &getLockFile( $farm_name );
		my $lock_fh   = &openlock( $lock_file, 'w' );

		my @fileconf;
		if ( !fgrep { /^\s*Service "$service"/ } "$configdir/$farm_name\_proxy.cfg" )
		{
			tie @fileconf, 'Tie::File', "$configdir/$farm_name\_proxy.cfg";
			my $i         = 0;
			my $farm_type = "";
			$farm_type = &getFarmType( $farm_name );

			foreach my $line ( @fileconf )
			{
				if ( $line =~ /#ZWACL-INI/ )
				{
					$output = 0;
					foreach my $lline ( @newservice )
					{
						if ( $lline =~ /\[DESC\]/ )
						{
							$lline =~ s/\[DESC\]/$service/;
						}
						if (    $lline =~ /StrictTransportSecurity/
							 && $farm_type eq "https" )
						{
							$lline =~ s/#//;
						}
						$i++;
						splice @fileconf, $i, 0, "$lline";
					}
					last;
				}
				$i++;
			}
		}
		untie @fileconf;
		close $lock_fh;
	}
	else
	{
		$output = 1;
	}

	return $output;
}

=begin nd
Function: delHTTPFarmService

	Delete a service in a Farm

Parameters:
	farmname - Farm name
	service - Service name

Returns:
	Integer - Error code: 0 on success, -1 on failure

=cut

sub delHTTPFarmService    # ($farm_name,$service)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $service ) = @_;

	require Tie::File;
	require Skudonet::Lock;
	require Skudonet::FarmGuardian;
	require Skudonet::Farm::HTTP::Service;
	require Skudonet::Farm::HTTP::Sessions;
	require Skudonet::Farm::Config;

	my $farm_filename = &getFarmFile( $farm_name );
	my $sw            = 0;
	my $output        = -1;
	my $farm_ref      = getFarmStruct( $farm_name );

	# Counter the Service's backends
	my $sindex     = &getFarmVSI( $farm_name, $service );
	my $backendsvs = &getHTTPFarmVS( $farm_name, $service, "backends" );
	my @be         = split ( "\n", $backendsvs );
	my $counter    = @be;

	# Stop FG service
	&delFGFarm( $farm_name, $service );

	my $lock_file = &getLockFile( $farm_name );
	my $lock_fh   = &openlock( $lock_file, 'w' );

	tie my @fileconf, 'Tie::File', "$configdir/$farm_filename";

	my $i = 0;
	for ( $i = 0 ; $i < $#fileconf ; $i++ )
	{
		my $line = $fileconf[$i];
		if ( $sw eq "1" && ( $line =~ /ZWACL-END/ || $line =~ /Service/ ) )
		{
			$output = 0;
			last;
		}

		if ( $sw == 1 )
		{
			if ( $line =~ /\s*NfMark\s*(.*)/ )
			{
				require Skudonet;
				require Skudonet::Farm::Backend;
				my $mark = sprintf ( "0x%x", $1 );
				&delMarks( "", $mark );
				&setBackendRule( "del", $farm_ref, $mark )
				  if ( &getGlobalConfiguration( 'mark_routing_L7' ) eq 'true' );
			}
			splice @fileconf, $i, 1,;
			$i--;
		}

		if ( $line =~ /Service "$service"/ )
		{
			$sw = 1;
			splice @fileconf, $i, 1,;
			$i--;
		}
	}


	untie @fileconf;
	close $lock_fh;

	# delete service's backends  in status file
	if ( $counter > -1 )
	{
		while ( $counter > -1 )
		{
			require Skudonet::Farm::HTTP::Backend;
			&runRemoveHTTPBackendStatus( $farm_name, $counter, $service );
			$counter--;
		}
	}

	# delete service's sessions from config file

	if ( &getGlobalConfiguration( 'proxy_ng' ) )
	{
		&deleteConfL7FarmAllSession( $farm_name, $service );
	}

# change the ID value of services with an ID higher than the service deleted (value - 1)
	tie my @contents, 'Tie::File', "$configdir\/$farm_name\_status.cfg";
	foreach my $line ( @contents )
	{
		my @params = split ( "\ ", $line );
		my $newval = $params[2] - 1;

		if ( $params[2] > $sindex )
		{
			$line =~
			  s/$params[0]\ $params[1]\ $params[2]\ $params[3]\ $params[4]/$params[0]\ $params[1]\ $newval\ $params[3]\ $params[4]/g;
		}
	}
	untie @contents;

	return $output;
}

=begin nd
Function: getHTTPFarmServices

	Get an array containing all service name configured in an HTTP farm.
	If Service name is sent, get an array containing the service name foundand index.

Parameters:
	farmname - Farm name
	servicename - Service name

Returns:
	Array - service names if service name param does not exist. 
	Hash ref  - Hash ref $service_ref if service name param exists.

Variable: $service_ref

	$service_ref->{ $service_name } - Service index

FIXME:
	&getHTTPFarmVS(farmname) does same but in a string

=cut

sub getHTTPFarmServices
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $service_name ) = @_;

	require Skudonet::Farm::Core;

	my $farm_filename = &getFarmFile( $farm_name );
	my @output        = ();

	open my $fh, '<', "$configdir\/$farm_filename";
	my @file = <$fh>;
	close $fh;

	my $index = 0;
	foreach my $line ( @file )
	{
		if ( $line =~ /^\s*Service\s+\"(.*)\"\s*$/ )
		{
			my $service = $1;
			if ( $service_name )
			{
				if ( $service_name eq $service )
				{
					return { $service => $index };
				}
				$index++;
			}
			else
			{
				push ( @output, $service );
			}
		}
	}

	return @output;
}

=begin nd
Function: getHTTPServiceBlocks

	Return a struct with configuration about the configuration farm and its services

Parameters:
	farmname - Farm name
	service - Service to move

Returns:
	Hash ref - Return 3 keys: farm, it is the part of the farm configuration file with the configuration; request, it is the block of code for the request service;
	services, it is a hash reference with the id service, the code of the service is appending from the id, it is excluid the request service from this list.

	example:

	{
		farm => [
			'######################################################################',
			'##GLOBAL OPTIONS                                                      ',
			'User		"root"                                                     ',
			'Group		"root"                                                     ',
			'Name		AAmovesrv                                                  ',
			'## allow PUT and DELETE also (by default only GET, POST and HEAD)?:   ',
			'#ExtendedHTTP	0                                                      ',
			'## Logging: (goes to syslog by default)                               ',
			'##	0	no logging                                                     ',
			'##	1	normal                                                         ',
			'...																   '
		],
		request => [
			'Service "sev3"											 ',
			'	##False##HTTPS-backend##                             ',
			'	#DynScale 1                                          ',
			'	#BackendCookie "ZENSESSIONID" "domainname.com" "/" 0 ',
			'	#HeadRequire "Host: "                                ',
			'	#Url ""                                              ',
			'	Redirect "https://SEFAwwwwwwwwwwFA.hf"               ',
			'	#StrictTransportSecurity 21600000                    ',
			'	#Session                                             ',
			'	...													 '
		],
		services => {
			'0' => [
				'Service "sev1"											 ',
				'	##False##HTTPS-backend##                             ',
				'	#DynScale 1                                          ',
				'	#BackendCookie "ZENSESSIONID" "domainname.com" "/" 0 ',
				'	#HeadRequire "Host: "                                ',
				'	#Url ""                                              ',
				'	Redirect "https://SEFAwwwwwwwwwwFA.hf"               ',
				'	#StrictTransportSecurity 21600000                    ',
				'	#Session                                             ',
				'	...													 '
			],
			'1' => [
				'Service "sev2"											 ',
				'	##False##HTTPS-backend##                             ',
				'	#DynScale 1                                          ',
				'	#BackendCookie "ZENSESSIONID" "domainname.com" "/" 0 ',
				'	#HeadRequire "Host: "                                ',
				'	#Url ""                                              ',
				'	Redirect "https://SEFAwwwwwwwwwwFA.hf"               ',
				'	#StrictTransportSecurity 21600000                    ',
				'	#Session                                             ',
				'	...													 '
			],
		}
	}

=cut

sub getHTTPServiceBlocks
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farm = shift;
	my $srv  = shift;
	my $out = {
				farm     => [],
				services => {},
				request  => [],
	};
	my $current_srv;
	my $srv_flag;
	my $farm_flag = 1;

	my $farm_filename = &getFarmFile( $farm );
	open my $fileconf, '<', "$configdir/$farm_filename";

	my $ind = 0;
	foreach my $line ( <$fileconf> )
	{
		if ( $line =~ /^\tService \"(.+)\"/ )
		{
			$srv_flag    = 1;
			$farm_flag   = 0;
			$current_srv = $1;
		}

		if ( $farm_flag )
		{
			push @{ $out->{ farm } }, $line;
		}
		if ( $srv_flag )
		{
			if ( $srv ne $current_srv )
			{
				push @{ $out->{ services }->{ $ind } }, $line;
			}
			else
			{
				push @{ $out->{ request } }, $line;
			}
		}
		if ( $line =~ /^\tEnd$/ and $srv_flag )
		{
			$srv_flag = 0;
			$ind++ if ( $srv ne $current_srv );
		}
	}

	return $out;
}

=begin nd
Function: getHTTPServiceStruct

	Get a struct with all parameters of a HTTP service

Parameters:
	farmname - Farm name
	service  - Farm name

Returns:
	hash ref - hash with service configuration

	Example output:
	{
	  "services" : {
      "backends" : [
         {
            "id" : 0,
            "ip" : "48.5.25.5",
            "port" : 70,
            "status" : "up",
            "timeout" : null,
            "weight" : null
         }
      ],
      "fgenabled" : "false",
      "fglog" : "false",
      "fgscript" : "",
      "fgtimecheck" : 5,
      "httpsb" : "false",
      "id" : "srv3",
      "leastresp" : "false",
      "persistence" : "",
      "redirect" : "",
      "redirecttype" : "",
      "sessionid" : "",
      "ttl" : 0,
      "urlp" : "",
      "vhost" : ""
      }
    };

	Enterprise Edition also includes:

      ...
      "cookiedomain" : "",
      "cookieinsert" : "false",
      "cookiename" : "",
      "cookiepath" : "",
      "cookiettl" : 0,
      ...

Notes:
	Similar to the function get_http_service_struct
=cut

sub getHTTPServiceStruct
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farmname, $service_name ) = @_;

	require Skudonet::FarmGuardian;
	require Skudonet::Farm::HTTP::Backend;

	my $proxy_ng = &getGlobalConfiguration( 'proxy_ng' );

	# http services
	my $services = &getHTTPFarmVS( $farmname, "", "" );
	my @serv     = split ( ' ', $services );

	# return error if service is not found
	return unless grep ( { $service_name eq $_ } @serv );

	my $vser         = &getHTTPFarmVS( $farmname, $service_name, "vs" );
	my $urlp         = &getHTTPFarmVS( $farmname, $service_name, "urlp" );
	my $redirect     = &getHTTPFarmVS( $farmname, $service_name, "redirect" );
	my $redirecttype = &getHTTPFarmVS( $farmname, $service_name, "redirecttype" );
	my $session      = &getHTTPFarmVS( $farmname, $service_name, "sesstype" );
	my $ttl          = &getHTTPFarmVS( $farmname, $service_name, "ttl" );
	my $sesid        = &getHTTPFarmVS( $farmname, $service_name, "sessionid" );
	my $dyns         = &getHTTPFarmVS( $farmname, $service_name, "dynscale" );
	my $httpsbe      = &getHTTPFarmVS( $farmname, $service_name, "httpsbackend" );
	my $pinnedConn = &getHTTPFarmVS( $farmname, $service_name, "pinnedConnection" );
	my $routingPol = &getHTTPFarmVS( $farmname, $service_name, "routingPolicy" );

	my $rewriteLocation =
	  &getHTTPFarmVS( $farmname, $service_name, "rewriteLocation" );

	$dyns    = "false" if $dyns eq '';
	$httpsbe = "false" if $httpsbe eq '';

	# Backends
	my $backends = &getHTTPFarmBackends( $farmname, $service_name );

	# Remove backend status 'undefined', it is for news api versions
	foreach my $be ( @{ $backends } )
	{
		$be->{ 'status' } = 'up' if $be->{ 'status' } eq 'undefined';
	}

	my $service_ref = {
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
	};

	if ( $proxy_ng eq 'true' )
	{
		$service_ref->{ pinnedconnection } = $pinnedConn;
		$service_ref->{ routingpolicy }    = $routingPol;
		$service_ref->{ rewritelocation }  = $rewriteLocation;
	}

	# add fg
	$service_ref->{ farmguardian } = &getFGFarm( $farmname, $service_name );


	return $service_ref;
}

sub getHTTPServiceId
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farmname, $service_name ) = @_;
	my $id = undef;

	my @services = getHTTPFarmServices( $farmname );

	my $index = 0;
	my $exist = 0;
	foreach my $service ( @services )
	{
		if ( $service eq $service_name )
		{
			$id    = $index;
			$exist = 1;
			last;
		}
		$index++;
	}
	return undef unless ( $exist );
	return $id;
}

=begin nd
Function: getHTTPFarmVS

	Return virtual server parameter

Parameters:
	farmname - Farm name
	service - Service name
	tag - Indicate which field will be returned. The options are: vs, urlp, redirect, redirecttype, dynscale, sesstype, ttl, sessionid, httpsbackend or backends

Returns:
	scalar - if service and tag is blank, return all services in a string: "service0 service1 ..." else return the parameter value

FIXME:
	return a hash with all parameters
=cut

sub getHTTPFarmVS    # ($farm_name,$service,$tag)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $service, $tag ) = @_;

	$service = "" unless $service;
	$tag     = "" unless $tag;
	my $proxy_mode = &getGlobalConfiguration( 'proxy_ng' );

	my $farm_filename = &getFarmFile( $farm_name );
	my $output        = "";
	if (    $tag eq 'replaceRequestHeader'
		 || $tag eq 'replaceResponseHeader'
		 || $tag eq 'rewriteUrl'
		 || $tag eq 'addRequestHeader'
		 || $tag eq 'addResponseHeader'
		 || $tag eq 'removeRequestHeader'
		 || $tag eq 'removeResponseHeader' )
	{
		$output = [];
	}
	else
	{
		$output = "";
	}

	my $directive_index = 0;

	open my $fileconf, '<', "$configdir/$farm_filename";

	my $sw         = 0;
	my $be_section = 0;
	my $be         = -1;
	my $sw_ti      = 0;
	my $output_ti  = "";
	my $sw_pr      = 0;
	my $output_pr  = "";
	my $sw_w       = 0;
	my $output_w   = "";
	my $sw_co      = 0;
	my $output_co  = "";
	my $sw_tag     = 0;
	my $output_tag = "";
	my $outputa;
	my $outputp;
	my @return;

	foreach my $line ( <$fileconf> )
	{
		if ( $line =~ /^\tService \"$service\"/ ) { $sw = 1; }
		if ( $line =~ /^\tEnd\s*$/ )              { $sw = 0; }

		# returns all services for this farm
		if ( $tag eq "" && $service eq "" )
		{
			if ( $line =~ /^\tService\ \"/ && $line !~ "#" )
			{
				@return = split ( "\ ", $line );
				$return[1] =~ s/\"//g;
				$return[1] =~ s/^\s+//;
				$return[1] =~ s/\s+$//;
				$output = "$output $return[1]";
			}
		}

		#vs tag
		if ( $tag eq "vs" )
		{
			if ( $line =~ "HeadRequire" && $sw == 1 && $line !~ /^\s*#/ )
			{
				@return = split ( "Host:", $line );
				$return[1] =~ s/\"//g;
				$return[1] =~ s/^\s+//;
				$return[1] =~ s/\s+$//;
				$output = $return[1];
				last;

			}
		}

		#url pattern
		if ( $tag eq "urlp" )
		{
			if ( $line =~ /^\s*Url \"/ && $sw == 1 )
			{
				@return = split ( "Url", $line );
				$return[1] =~ s/\"//g;
				$return[1] =~ s/^\s+//;
				$return[1] =~ s/\s+$//;
				$output = $return[1];
				last;
			}
		}

		#redirect
		if ( $tag eq "redirect" )
		{
			# Redirect types: 301, 302 or 307.
			if (    $line =~ /Redirect(?:Append)?\s/
				 && $sw == 1
				 && $line !~ /^\s*#/ )
			{
				@return = split ( " ", $line );

				my $url = $return[-1];
				$url =~ s/\"//g;
				$url =~ s/^\s+//;
				$url =~ s/\s+$//;
				$output = $url;
				last;
			}
		}

		if ( $tag eq "redirecttype" )
		{
			if (    $line =~ /Redirect(?:Append)?\s/
				 && $sw == 1
				 && $line !~ "#" )
			{
				if    ( $line =~ /Redirect / )       { $output = "default"; }
				elsif ( $line =~ /RedirectAppend / ) { $output = "append"; }
				last;
			}
		}

		#dynscale
		if ( $tag eq "dynscale" )
		{
			if ( $line =~ "DynScale\ " && $sw == 1 && $line !~ "#" )
			{
				$output = "true";
				last;
			}

		}

		#sesstion type
		if ( $tag eq "sesstype" )
		{
			if ( $line =~ "Type" && $sw == 1 && $line !~ "#" )
			{
				@return = split ( "\ ", $line );
				$return[1] =~ s/\"//g;
				$return[1] =~ s/^\s+//;
				$return[1] =~ s/\s+$//;
				$output = $return[1];
				last;
			}
		}

		#ttl
		if ( $tag eq "ttl" )
		{
			if ( $line =~ "TTL" && $sw == 1 )
			{
				@return = split ( "\ ", $line );
				$return[1] =~ s/\"//g;
				$return[1] =~ s/^\s+//;
				$return[1] =~ s/\s+$//;
				$output = $return[1];
				last;
			}
		}

		#session id
		if ( $tag eq "sessionid" )
		{
			if ( $line =~ "\t\t\tID" && $sw == 1 && $line !~ /^\s*#/ )
			{
				@return = split ( "\ ", $line );
				$return[1] =~ s/\"//g;
				$return[1] =~ s/^\s+//;
				$return[1] =~ s/\s+$//;
				$output = $return[1];
				last;
			}
		}

		#HTTPS tag
		if ( $tag eq "httpsbackend" )
		{
			if ( $line =~ "##True##HTTPS-backend##" && $sw == 1 )
			{
				$output = "true";
				last;
			}
		}

		#PinnedConnection tag
		if ( $tag eq "pinnedConnection" )
		{
			if ( $proxy_mode eq "true" )
			{
				if ( $line =~ /^\t\t(#?)PinnedConnection\s+(.*)/ && $sw == 1 )
				{
					if ( $1 eq "#" )
					{
						$output = 0;
						last;
					}
					else
					{
						$2 =~ s/^\s+//;
						$output = $2;
						last;
					}
				}
				elsif ( $sw == 1 && $line =~ /\t#BackEnd/ )
				{
					$output = 0;
					last;
				}
			}
			else
			{
				$output = undef;
				last;
			}
		}

		#RoutingPolicy tag
		if ( $tag eq "routingPolicy" )
		{
			if ( $proxy_mode eq "true" )
			{
				if ( $line =~ /^\t\t(#?)RoutingPolicy\s+(.*)/ && $sw == 1 )
				{
					if ( $1 eq "#" )
					{
						$output = "ROUND_ROBIN";
						last;
					}
					else
					{
						$2 =~ s/^\s+//;
						$output = $2;
						last;
					}
				}
				elsif ( $sw == 1 && $line =~ /\t#BackEnd/ )
				{
					$output = "ROUND_ROBIN";
					last;
				}
			}
			else
			{
				$output = undef;
				last;
			}
		}

		#ReplaceRequestHeader tag
		if ( $tag eq "replaceRequestHeader" )
		{
			if ( $proxy_mode eq "true" )
			{

				if (    $line =~ /^\t\t(#?)ReplaceHeader\s+(.+)\s+"(.+)"\s+"(.+)"\s+"(.*)"/
					 && $sw == 1 )
				{
					if ( $1 eq "#" )
					{
						next;
					}
					elsif ( $2 eq 'Response' )
					{
						next;
					}
					else
					{
						push @{ $output },
						  {
							"id"      => $directive_index++,
							"header"  => $3,
							"match"   => $4,
							"replace" => $5
						  };
						next;
					}
				}
				elsif ( $sw == 1 && $line =~ /\t#BackEnd/ )
				{
					last;
				}
			}
			else
			{
				$output = undef;
				last;
			}
		}

		#ReplaceResponseHeader tag
		if ( $tag eq "replaceResponseHeader" )
		{
			if ( $proxy_mode eq "true" )
			{

				if (    $line =~ /^\t\t(#?)ReplaceHeader\s+(.+)\s+"(.+)"\s+"(.+)"\s+"(.*)"/
					 && $sw == 1 )
				{
					if ( $1 eq "#" )
					{
						next;
					}
					elsif ( $2 eq 'Request' )
					{
						next;
					}
					else
					{
						push @{ $output },
						  {
							"id"      => $directive_index++,
							"header"  => $3,
							"match"   => $4,
							"replace" => $5
						  };
						next;
					}
				}
				elsif ( $sw == 1 && $line =~ /\t#BackEnd/ )
				{
					last;
				}
			}
			else
			{
				$output = undef;
				last;
			}
		}

		#RewriteUrl tag
		if ( $tag eq "rewriteUrl" )
		{
			if ( $proxy_mode eq "true" )
			{
				if (    $line =~ /^\t\t(#?)RewriteUrl\s+"(.+)"\s+"(.*)"(\s+last)?/
					 && $sw == 1 )
				{
					if ( $1 eq "#" )
					{
						next;
					}
					else
					{
						my $last = ( defined $4 ) ? "true" : "false";
						push @{ $output },
						  {
							"id"      => $directive_index++,
							"pattern" => $2,
							"replace" => $3,
							"last"    => $last
						  };
						next;
					}
				}
				elsif ( $sw == 1 && $line =~ /\t#BackEnd/ )
				{
					last;
				}
			}
			else
			{
				$output = undef;
				last;
			}
		}

		#RewriteLocation tag
		if ( $tag eq "rewriteLocation" )
		{
			if ( $proxy_mode eq "true" )
			{

				if (    $line =~ /^\t\t(#)?RewriteLocation\s+(\d)\s*(path)?/
					 && $sw == 1 )
				{
					if ( $1 eq "#" )
					{
						next;
					}
					else
					{
						if    ( $2 eq 0 ) { $output = "disabled"; last; }
						elsif ( $2 eq 1 ) { $output = "enabled"; }
						elsif ( $2 eq 2 ) { $output = "enabled-backends"; }

						if ( $3 eq 'path' ) { $output .= "-path"; }
						last;
					}
				}
				elsif ( $sw == 1 && $line =~ /\t#BackEnd/ )
				{
					$output = "disabled";
					last;
				}
			}
			else
			{
				$output = undef;
				last;
			}
		}

		#AddRequestHeader tag
		if ( $tag eq "addRequestHeader" )
		{
			if (    $line =~ /^\t\t(#?)AddHeader\s+"(.+)"/
				 && $sw == 1 )
			{
				if ( $1 eq "#" )
				{
					next;
				}
				else
				{
					push @{ $output },
					  {
						"id"     => $directive_index++,
						"header" => $2
					  };
					next;
				}
			}
			elsif ( $sw == 1 && $line =~ /\t#BackEnd/ )
			{
				last;
			}
		}

		#AddResponseHeader tag
		if ( $tag eq "addResponseHeader" )
		{
			if (    $line =~ /^\t\t(#?)AddResponseHeader\s+"(.+)"/
				 && $sw == 1 )
			{
				if ( $1 eq "#" )
				{
					next;
				}
				else
				{
					push @{ $output },
					  {
						"id"     => $directive_index++,
						"header" => $2
					  };
					next;
				}
			}
			elsif ( $sw == 1 && $line =~ /\t#BackEnd/ )
			{
				last;
			}
		}

		#RemoveRequestHeader tag
		if ( $tag eq "removeRequestHeader" )
		{
			if (    $line =~ /^\t\t(#?)HeadRemove\s+"(.+)"/
				 && $sw == 1 )
			{
				if ( $1 eq "#" )
				{
					next;
				}
				else
				{
					push @{ $output },
					  {
						"id"      => $directive_index++,
						"pattern" => $2
					  };
					next;
				}
			}
			elsif ( $sw == 1 && $line =~ /\t#BackEnd/ )
			{
				last;
			}
		}

		#RemoveResponseHeader tag
		if ( $tag eq "removeResponseHeader" )
		{
			if (    $line =~ /^\t\t(#?)RemoveResponseHeader\s+"(.+)"/
				 && $sw == 1 )
			{
				if ( $1 eq "#" )
				{
					next;
				}
				else
				{
					push @{ $output },
					  {
						"id"      => $directive_index++,
						"pattern" => $2
					  };
					next;
				}
			}
			elsif ( $sw == 1 && $line =~ /\t#BackEnd/ )
			{
				last;
			}
		}

		#backends
		if ( $tag eq "backends" )
		{
			if ( $line =~ /#BackEnd/ && $sw == 1 )
			{
				$be_section = 1;
			}
			if ( $be_section == 1 )
			{

				#if ($line =~ /Address/ && $be >=1){
				if (    $line =~ /End/
					 && $line !~ /#/
					 && $sw == 1
					 && $be_section == 1
					 && $line !~ /BackEnd/ )
				{
					if ( $sw_ti == 0 )
					{
						$output_ti = "TimeOut -";
					}
					if ( $sw_pr == 0 )
					{
						$output_pr = "Priority -";
					}
					if ( $sw_w == 0 )
					{
						$output_w = "Weight -";
					}
					if ( $sw_co == 0 )
					{
						$output_co = "ConnLimit -";
					}
					if ( $sw_tag == 0 )
					{
						$output_tag = "NfMark -";
					}

					$output =
					  "$output $outputa $outputp $output_ti $output_pr $output_w $output_co $output_tag\n";
					$output_ti = "";
					$output_pr = "";
					$sw_ti     = 0;
					$sw_pr     = 0;
					$sw_w      = 0;
					$sw_co     = 0;
					$sw_tag    = 0;
				}
				if ( $line =~ /Address/ )
				{
					$be++;
					chomp ( $line );
					$outputa = "Server $be $line";
				}
				if ( $line =~ /Port/ )
				{
					chomp ( $line );
					$outputp = "$line";
				}
				if ( $line =~ /TimeOut/ )
				{
					chomp ( $line );

					#$output = $output . "$line";
					$output_ti = $line;
					$sw_ti     = 1;
				}
				if ( $line =~ /Priority/ )
				{
					chomp ( $line );

					#$output = $output . "$line";
					$output_pr = $line;
					$sw_pr     = 1;
				}
				if ( $line =~ /Weight/ )
				{
					chomp ( $line );

					#$output = $output . "$line";
					$output_w = $line;
					$sw_w     = 1;
				}
				if ( $line =~ /ConnLimit/ )
				{
					chomp ( $line );

					#$output = $output . "$line";
					$output_co = $line;
					$sw_co     = 1;
				}
				if ( $line =~ /NfMark/ )
				{
					chomp ( $line );

					#$output = $output . "$line";
					$output_tag = $line;
					$sw_tag     = 1;
				}
			}
			if ( $sw == 1 && $be_section == 1 && $line =~ /#End/ )
			{
				last;
			}
		}
	}
	close $fileconf;

	return $output;
}

=begin nd
Function: setHTTPFarmVS

	Set values for service parameters. The parameters are: vs, urlp, redirect, redirectappend, dynscale, sesstype, ttl, sessionid, httpsbackend or backends

	A blank string comment the tag field in config file

Parameters:
	farmname - Farm name
	service - Service name
	tag - Indicate which parameter modify
	string - value for the field "tag"

Returns:
	Integer - Error code: 0 on success or -1 on failure

=cut

sub setHTTPFarmVS    # ($farm_name,$service,$tag,$string)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $service, $tag, $string ) = @_;

	my $farm_filename  = &getFarmFile( $farm_name );
	my $output         = 0;
	my $sw             = 0;
	my $j              = -1;
	my $clean_sessions = 0;

	$string =~ s/^\s+//;
	$string =~ s/\s+$//;

	require Skudonet::Lock;
	my $lock_file = &getLockFile( $farm_name );
	my $lock_fh   = &openlock( $lock_file, 'w' );

	if ( $tag eq 'rewriteLocation' )
	{
		if    ( $string eq "disabled" )              { $string = "0"; }
		elsif ( $string eq "enabled" )               { $string = "1"; }
		elsif ( $string eq "enabled-backends" )      { $string = "2"; }
		elsif ( $string eq "enabled-path" )          { $string = "1 path"; }
		elsif ( $string eq "enabled-backends-path" ) { $string = "2 path"; }
	}

	require Tie::File;
	tie my @fileconf, 'Tie::File', "$configdir/$farm_filename";

	foreach my $line ( @fileconf )
	{
		$j++;
		if ( $line =~ /\tService \"$service\"/ ) { $sw = 1; }
		if ( $line =~ /^\tEnd$/ && $sw == 1 )    { last; }
		next if $sw == 0;

		#vs tag
		if ( $tag eq "vs" )
		{
			if ( $line =~ /^\t\t#?HeadRequire/ && $sw == 1 && $string ne "" )
			{
				$line = "\t\tHeadRequire \"Host: $string\"";
				last;
			}
			if ( $line =~ /^\t\t#?HeadRequire/ && $sw == 1 && $string eq "" )
			{
				$line = "\t\t#HeadRequire \"Host:\"";
				last;
			}
		}

		#url pattern
		if ( $tag eq "urlp" )
		{
			if ( $line =~ /^\t\t#?Url/ && $sw == 1 && $string ne "" )
			{
				$line = "\t\tUrl \"$string\"";
				last;
			}
			if ( $line =~ /^\t\t#?Url/ && $sw == 1 && $string eq "" )
			{
				$line = "\t\t#Url \"\"";
				last;
			}
		}

		#dynscale
		if ( $tag eq "dynscale" )
		{
			if ( $line =~ /^\t\t#?DynScale/ && $sw == 1 && $string ne "" )
			{
				$line = "\t\tDynScale 1";
				last;
			}
			if ( $line =~ /^\t\t#?DynScale/ && $sw == 1 && $string eq "" )
			{
				$line = "\t\t#DynScale 1";
				last;
			}
		}

		#client redirect default
		if ( $tag eq "redirect" )
		{
			if ( $line =~ /^\t\t#?(Redirect(?:Append)?) (30[127] )?.*/ )
			{
				my $policy        = $1;
				my $redirect_code = $2;
				my $comment       = '';
				if ( $string eq "" )
				{
					$comment = '#';
					$policy  = "Redirect";
				}
				$line = "\t\t${comment}${policy} ${redirect_code}\"${string}\"";
				last;
			}
		}

		#client redirect default
		if ( $tag eq "redirecttype" )
		{
			if ( $line =~ /^\t\tRedirect(?:Append)? (.*)/ )
			{
				my $rest   = $1;
				my $policy = ( $string eq 'append' ) ? 'RedirectAppend' : 'Redirect';

				$line = "\t\t${policy} $rest";
				last;
			}
		}

		#TTL
		if ( $tag eq "ttl" )
		{
			if ( $line =~ /^\t\t\t#?TTL/ && $sw == 1 && $string ne "" )
			{
				$line = "\t\t\tTTL $string";
				last;
			}
			if ( $line =~ /^\t\t\t#?TTL/ && $sw == 1 && $string eq "" )
			{
				$line = "\t\t\t#TTL 120";
				last;
			}
		}

		#session id
		if ( $tag eq "sessionid" )
		{
			if ( $line =~ "\t\t\tID|\t\t\t#ID" && $sw == 1 && $string ne "" )
			{
				$line = "\t\t\tID \"$string\"";
				last;
			}
			if ( $line =~ "\t\t\tID|\t\t\t#ID" && $sw == 1 && $string eq "" )
			{
				$line = "\t\t\t#ID \"$string\"";
				last;
			}
		}

		#HTTPS Backends tag
		if ( $tag eq "httpsbackend" )
		{
			if ( $line =~ "##HTTPS-backend##" && $sw == 1 && $string ne "" )
			{
				#turn on
				$line = "\t\t##True##HTTPS-backend##";
			}

			if ( $line =~ "##HTTPS-backend##" && $sw == 1 && $string eq "" )
			{
				#turn off
				$line = "\t\t##False##HTTPS-backend##";
			}

			#Delete HTTPS tag in a BackEnd
			if ( $sw == 1 && $line =~ /HTTPS$/ && $string eq "" )
			{
				#Delete HTTPS tag
				splice @fileconf, $j, 1,;
			}

			#Add HTTPS tag
			if ( $sw == 1 && $line =~ /\t\tBackEnd$/ && $string ne "" )
			{
				$line .= "\n\t\t\tHTTPS";
			}

			#go out of curret Service
			if (    $line =~ /\tService \"/
				 && $sw == 1
				 && $line !~ /\tService \"$service\"/ )
			{
				$tag = "";
				$sw  = 0;
				last;
			}
		}

		#session type
		if ( $tag eq "session" )
		{
			require Skudonet::Farm::HTTP::Sessions;
			if ( $string ne "nothing" && $sw == 1 )
			{
				if ( $line =~ /^\t\t#Session/ )
				{
					$line = "\t\tSession";
				}
				if ( $line =~ /\t\t#End/ )
				{
					$line = "\t\tEnd";
				}
				if ( $line =~ /^\t\t\t#?Type\s+(.*)\s*/ )
				{
					$line           = "\t\t\tType $string";
					$clean_sessions = 1 if ( $1 ne $string );
				}
				if ( $line =~ /^\t\t\t#?TTL/ )
				{
					$line =~ s/#//g;
				}
				if ( $line =~ /\t\t\t#?ID / )
				{
					if (    $string eq "URL"
						 || $string eq "COOKIE"
						 || $string eq "HEADER" )
					{
						$line =~ s/#//g;
					}
					else
					{
						$line = "#$line";
					}
				}
			}

			if ( $string eq "nothing" && $sw == 1 )
			{
				if ( $line =~ /^\t\tSession/ )
				{
					$line = "\t\t#Session";
				}
				if ( $line =~ /^\t\tEnd/ )
				{
					$line = "\t\t#End";
				}
				if ( $line =~ /^\t\t\tTTL/ )
				{
					$line = "\t\t\t#TTL 120";
				}
				if ( $line =~ /^\t\t\tType/ )
				{
					$line           = "\t\t\t#Type nothing";
					$clean_sessions = 1;
				}
				if ( $line =~ "\t\t\tID |\t\t\t#ID " )
				{
					$line = "\t\t\t#ID \"sessionname\"";
				}
			}
			if ( $sw == 1 && $line =~ /End/ )
			{
				&deleteConfL7FarmAllSession( $farm_name, $service ) if ( $clean_sessions );
				last;
			}
		}

		#PinnedConnection
		if ( $tag eq "pinnedConnection" )
		{
			if ( $line =~ /^\t\t#?PinnedConnection/ && $sw == 1 && $string ne "" )
			{
				$line = "\t\tPinnedConnection $string";
				last;
			}

			if ( $sw == 1 && $line =~ /BackEnd/ )
			{
				$line = "\t\tPinnedConnection $string\n" . $line;
				last;
			}
		}

		#RoutingPolicy
		if ( $tag eq "routingPolicy" )
		{
			if ( $line =~ /^\t\t#?RoutingPolicy/ && $sw == 1 && $string ne "" )
			{
				$line = "\t\tRoutingPolicy $string";
				last;
			}

			if ( $sw == 1 && $line =~ /BackEnd/ )
			{
				$line = "\t\tRoutingPolicy $string\n" . $line;
				last;
			}
		}

		#RewriteLocation
		if ( $tag eq "rewriteLocation" )
		{
			if ( $line =~ /^\t\t#?RewriteLocation/ && $sw == 1 && $string ne "" )
			{
				$line = "\t\tRewriteLocation $string";
				last;
			}

			if ( $sw == 1 && $line =~ /BackEnd/ )
			{
				$line = "\t\tRewriteLocation $string\n" . $line;
				last;
			}
		}
	}

	untie @fileconf;
	close $lock_fh;

	return $output;
}

=begin nd
Function: getFarmVSI

	Get the index of a service in a http farm

Parameters:
	farmname - Farm name
	service - Service name

Returns:
	integer - Service index, it returns -1 if the service does not exist

FIXME:
	Rename with intuitive name, something like getHTTPFarmServiceIndex
=cut

sub getFarmVSI    # ($farm_name,$service)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farmname, $service ) = @_;

	# get service position
	my $srv_position = -1;
	my @services     = &getHTTPFarmServices( $farmname );
	my $index        = 0;
	foreach my $srv ( @services )
	{
		if ( $srv eq $service )
		{
			# found
			$srv_position = $index;
			last;
		}
		else
		{
			$index++;
		}
	}

	return $srv_position;
}

# esta funcion es solo para API32. borrar y usar getHTTPServiceStruct
sub get_http_service_struct
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farmname, $service_name ) = @_;

	require Skudonet::FarmGuardian;
	require Skudonet::Farm::HTTP::Backend;

	my $service_ref = &getHTTPServiceStruct( $farmname, $service_name );

	# Backends
	my $backends = &getHTTPFarmBackends( $farmname, $service_name );

	# Remove backend status 'undefined', it is for news api versions
	foreach my $be ( @{ $backends } )
	{
		$be->{ 'status' } = 'up' if $be->{ 'status' } eq 'undefined';
	}

	# Add FarmGuardian
	$service_ref->{ farmguardian } = &getFGFarm( $farmname, $service_name );


	return $service_ref;
}

# esta funcion es solo para API32.
sub get_http_all_services_struct
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farmname ) = @_;

	# Output
	my @services_list = ();

	foreach my $service ( &getHTTPFarmServices( $farmname ) )
	{
		my $service_ref = &get_http_service_struct( $farmname, $service );

		push @services_list, $service_ref;
	}


	return \@services_list;
}

sub get_http_all_services_summary_struct
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farmname ) = @_;

	# Output
	my @services_list = ();

	foreach my $service ( &getHTTPFarmServices( $farmname ) )
	{
		push @services_list, { 'id' => $service };
	}

	return \@services_list;
}

=begin nd
Function: getHTTPFarmPriorities

        Get the list of the backends priorities of the service in a http farm

Parameters:
        farmname - Farm name
        service - Service name

Returns:
        Array Ref - it returns an array ref of priority values

=cut

sub getHTTPFarmPriorities    # ( $farmname, $service_name )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farmname     = shift;
	my $service_name = shift;
	my @priorities;
	my $backends = &getHTTPFarmBackends( $farmname, $service_name );
	foreach my $backend ( @{ $backends } )
	{
		if ( defined $backend->{ priority } )
		{
			push @priorities, $backend->{ priority };
		}
		else
		{
			push @priorities, 1;
		}

	}
	return \@priorities;
}

1;

