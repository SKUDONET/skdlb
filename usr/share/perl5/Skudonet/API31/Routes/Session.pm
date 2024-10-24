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
use warnings;

require CGI::Session;


# POST CGISESSID to login
POST qr{^/session$} => \&session_login;

#  DELETE session to logout
DELETE qr{^/session$} => \&session_logout;


sub session_login
{
	&zenlog(__FILE__ . ":" . __LINE__ . ":" . (caller(0))[3] . "( @_ )", "debug", "PROFILING" );
	my $desc = "Login to new session";
	my $session = CGI::Session->new( &getCGI() );

	require Skudonet::SystemInfo;

	unless ( $session && !$session->param( 'is_logged_in' ) )
	{
		my $msg = "Already logged in a session";
		&httpErrorResponse( code => 401, desc => $desc, msg => $msg );
	}

	# not validated credentials
	my ( $username, $password ) = &getAuthorizationCredentials();

	unless ( &authenticateCredentials( $username, $password ) )
	{
		$session->delete();
		$session->flush();

		my $msg = "Login failed for username: $username";
		&httpErrorResponse( code => 401, desc => $desc, msg => $msg );
	}

	$session->param( 'is_logged_in', 1 );
	$session->param( 'username',     $username );
	$session->expire( 'is_logged_in', '+30m' );

	my ( $header ) = split ( "\r\n", $session->header() );
	my ( undef, $session_cookie ) = split ( ': ', $header );
	my $body;
	$body->{ host } = &getHostname();
	$body->{ key }  = &keycert() if defined( &keycert );

	&zenlog( "Login successful for user: $username", "info", "SYSTEM" );
	&httpResponse(
				   {
					 code => 200,
					 body => $body,
					 headers => { 'Set-cookie' => $session_cookie },
				   }
	);
}

sub session_logout
{
	&zenlog(__FILE__ . ":" . __LINE__ . ":" . (caller(0))[3] . "( @_ )", "debug", "PROFILING" );
	my $desc = "Logout of session";
	my $cgi = &getCGI();

	unless ( $cgi->http( 'Cookie' ) )
	{
		my $msg = "Session cookie not found";
		&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	my $session = new CGI::Session( $cgi );

	unless ( $session && $session->param( 'is_logged_in' ) )
	{
		my $msg = "Session expired or not found";
		&httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	my $username = $session->param( 'username' );
	my $ip_addr  = $session->param( '_SESSION_REMOTE_ADDR' );

	&zenlog( "Logged out user $username from $ip_addr", "info", "SYSTEM" );

	$session->delete();
	$session->flush();

	&httpResponse( { code => 200 } );
}

1;
