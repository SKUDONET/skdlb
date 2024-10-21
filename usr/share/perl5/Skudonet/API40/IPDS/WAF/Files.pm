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

require Skudonet::IPDS::WAF::File;

#GET /ipds/waf/files
sub list_waf_file
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $files = &listWAFFile();
	my $desc  = "List the WAF files";

	my @out = ();

	foreach my $f ( sort keys %{ $files } )
	{
		push @out, $files->{ $f };
	}

	return &httpResponse(
				   { code => 200, body => { description => $desc, params => \@out } } );
}

#  GET /ipds/waf/files/<file>
sub get_waf_file
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $file = shift;

	my $desc = "Get the WAF file $file";

	my $files = &listWAFFile();
	if ( !exists $files->{ $file } )
	{
		my $msg = "Requested file $file does not exist.";
		return &httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	my $content = &getWAFFileContent( $files->{ $file }->{ path } );
	my $out = {
				'content' => $content,
				'type'    => $files->{ $file }->{ 'type' },
	};

	my $body = { description => $desc, params => $out };

	return &httpResponse( { code => 200, body => $body } );
}

#  POST ipds/waf/files/<file>
sub upload_waf_file
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $content = shift;
	my $name    = shift;

	my $desc = "Upload WAF file '$name'";

	my $file_basename;
	my $file_ext;
	my $waf_file_format = &getValidFormat( 'waf_file' );
	if ( $name =~ /^($waf_file_format)\.(.+)$/ )
	{
		$file_basename = $1;
		$file_ext      = $2;
		my $waf_file_ext_format = &getValidFormat( 'waf_file_ext' );
		if ( not $file_ext =~ /^$waf_file_ext_format$/ )
		{
			my $msg = "Error, trying to upload file '$name' : WAF file extension not valid";
			return &httpErrorResponse( code => 400, desc => $desc, msg => $msg );
		}
	}
	else
	{
		my $msg = "Error, trying to upload file '$name' : WAF file name not valid";
		return &httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	if ( not defined $content or $content eq "" )
	{
		my $msg = "Error, trying to upload file '$name' : file is empty";
		return &httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}

	my $ext_types = {
					  "lua"  => "script",
					  "LUA"  => "script",
					  "conf" => "ruleset",
					  "CONF" => "ruleset",
					  "data" => "data",
					  "DATA" => "data"
	};

	my $file = {
				 name    => $file_basename,
				 content => $content,
				 type    => $ext_types->{ $file_ext }
	};
	my $output = &createWAFFile( $file );
	if ( $output->{ code } == 0 )
	{
		my $msg;
		my $code;
		if ( $output->{ desc } eq "Created" )
		{
			$msg  = "The file '$name' was created properly";
			$code = 201;
		}
		else
		{
			$msg  = "The file '$name' was modified properly";
			$code = 200;
		}
		my $body = {
					 description => $desc,
					 message     => $msg,
		};
		return &httpResponse( { code => $code, body => $body } );
	}
	else
	{
		my $msg = "Error, trying to upload WAF file '$name' : $output->{ desc }";
		return &httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}
}

#  PUT ipds/waf/files/<file>
sub create_waf_file
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $json_obj = shift;
	my $name     = shift;

	my $desc = "Create the WAF file '$name'";

	my $params = &getZAPIModel( "waf_file-create.json" );

	# Check allowed parameters
	my $error_msg = &checkZAPIParams( $json_obj, $params, $desc );
	return &httpErrorResponse( code => 400, desc => $desc, msg => $error_msg )
	  if ( $error_msg );

	$json_obj->{ name } = $name;
	my $output = &createWAFFile( $json_obj );

	if ( $output->{ code } == 0 )
	{
		my $msg;
		my $code;
		if ( $output->{ desc } eq "Created" )
		{
			$msg  = "The file '$name' was created properly";
			$code = 201;
		}
		else
		{
			$msg  = "The file '$name' was modified properly";
			$code = 200;
		}
		my $body = {
					 description => $desc,
					 message     => $msg,
		};
		return &httpResponse( { code => $code, body => $body } );
	}
	else
	{
		my $msg = "Error, trying to create the WAF file $name : $output->{ desc }";
		return &httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}
}

#  DELETE /ipds/waf/files/<set>
sub delete_waf_file
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $name = shift;

	my $desc = "Delete the WAF file '$name'";

	my $file = &listWAFFile()->{ $name };

	if ( not defined $file )
	{
		my $msg = "The WAF file '$name' does not exist";
		return &httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}
	elsif ( $file->{ module } ne 'waf' )
	{
		my $msg = "'$name' is not a WAF file";
		return &httpErrorResponse( code => 404, desc => $desc, msg => $msg );
	}

	if ( $file->{ type } eq "data" or $file->{ type } eq "script" )
	{
		my $sets = &checkWAFFileUsed( $name );
		if ( @{ $sets } )
		{
			my $string = join ( ', ', @{ $sets } );
			my $msg =
			  "The WAF file '$name' cannot be deleted. It is used by the Ruleset(s): $string";
			return &httpErrorResponse( code => 404, desc => $desc, msg => $msg );
		}
	}
	elsif ( $file->{ type } eq "ruleset" )
	{
		require Skudonet::IPDS::WAF::Core;
		my @farms = &listWAFBySet( $file->{ name } );

		if ( @farms )
		{
			my $str = join ( ', ', @farms );
			my $msg =
			  "The WAF file '$name' cannot be deleted. It is used by the farm(s): $str.";
			return &httpErrorResponse( code => 400, desc => $desc, msg => $msg );
		}
	}

	my $err = &deleteWAFFile( $file->{ path } );

	if ( !$err )
	{
		my $msg = "The WAF file '$name' has been deleted successfully.";
		my $body = {
					 description => $desc,
					 success     => "true",
					 message     => $msg,
		};
		return &httpResponse( { code => 200, body => $body } );
	}
	else
	{
		my $msg = "Deleting the WAF file '$name'.";
		return &httpErrorResponse( code => 400, desc => $desc, msg => $msg );
	}
}

1;

