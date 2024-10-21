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

use Skudonet::Core;
use Skudonet::IPDS::WAF::Core;
use Skudonet::IPDS::WAF::Config;
use Skudonet::IPDS::WAF::Parser;
require Skudonet::Lock;


my $wafFileDir = &getWAFSetDir();

=begin nd
Function: listWAFFile

	It returns an object with the WAF scripts and data files.

Parameters:
	none - .

Returns:
	Hash ref - The output of the hash is like:

	  "windows-powershell-commands" : {
         "module" : "waf",
         "name" : "windows-powershell-commands",
         "path" : "/usr/local/skudonet/config/ipds/waf/sets/windows-powershell-commands.data",
         "type" : "data"
      },
=cut

sub listWAFFile
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my %files = ();
	my @f_dir;

	require Skudonet::Validate;
	my $waf_file_format = &getValidFormat( 'waf_file' );

	if ( opendir ( my $fd, $wafFileDir ) )
	{
		@f_dir = readdir ( $fd );
		closedir $fd;

		foreach my $f ( @f_dir )
		{
			my $type;
			my $set_name;
			if ( $f =~ /($waf_file_format)\.(lua|data|conf)$/ )
			{
				$set_name = $1;
				$type     = $2;
				if ( $type eq "lua" )
				{
					$type = "script";
				}
				elsif ( $type eq "conf" )
				{
					$type = "ruleset";
				}
			}
			else
			{
				next;
			}

			$files{ $set_name } = {
									name   => $set_name,
									type   => $type,
									path   => "$wafFileDir/$f",
									module => "waf",
			};
		}
	}

	return \%files;
}

=begin nd
Function: existWAFFile

	It checks if a WAF File exists using the output of the listWafFile function

Parameters:
	name - File name. It is the file name without extension

Returns:
	Integer - It returns 1 if the file exists or 0 if it does not exist

=cut

sub existWAFFile
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $name = shift;

	my $exist = ( exists &listWAFFile()->{ $name } ) ? 1 : 0;

	return $exist;
}

=begin nd
Function: getWAFFileContent

	It gets the content of a file.

Parameters:
	Path - It is the absolute path to the file

Returns:
	String - Returns an string with the content of the file

=cut

sub getWAFFileContent
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $path    = shift;
	my $content = "";

	my $fh = &openlock( $path, 'r' );
	if ( $fh )
	{
		while ( <$fh> )
		{
			$content .= $_;
		}
	}
	close $fh;

	return $content;
}

=begin nd
Function: createWAFFile

	It creates a file with a lua script or data to be linked with the WAF rules.

Parameters:
	File struct. It is a hash reference with the following parameters:
		content - string with the content file
		name - name of the file
		type - the possible values for this field are 'script' or 'data'

Returns:
	error_ref - error object. code = 0, on success 

Variable: $error_ref.

	A hashref that maps error code and description

	$error_ref->{ code } - Integer. Error code
	$error_ref->{ desc } - String. Description of the error.

=cut

sub createWAFFile
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $file = shift;
	my $error_ref = { code => 0 };

	if (    !exists $file->{ content }
		 or !exists $file->{ name }
		 or ( $file->{ type } !~ /^(?:data|script|ruleset)$/ ) )
	{
		my $msg = "The parameters to create a WAF file are not correct";
		&zenlog( $msg, 'error', 'waf' );
		$error_ref->{ code } = 1;
		$error_ref->{ desc } = $msg;
		return $error_ref;
	}

	my $extension;
	if ( $file->{ type } eq 'script' )
	{
		$extension = "lua";
	}
	elsif ( $file->{ type } eq 'data' )
	{
		$extension = "data";
	}
	elsif ( $file->{ type } eq 'ruleset' )
	{
		$extension = "conf";
	}
	my $path = "$wafFileDir/$file->{name}.$extension";
	my $log_tag = ( -f $path ) ? "Overwritten" : "Created";

	if ( $file->{ type } ne "ruleset" )
	{
		my $fh = &openlock( $path, '>' ) or return 1;
		print $fh $file->{ content };
		close $fh;
	}
	else
	{
		my $dir       = &getWAFSetDir();
		my $tmp       = "$dir/waf_rulesets.build";
		my $lock_file = &getLockFile( $path );

		require Skudonet::IPDS::WAF::Parser;
		my $ruleset_conf;

		my $mark_conf_begin = "## begin conf";
		my $has_config      = 0;
		my @batch           = split ( '\n', $file->{ content } );

		foreach my $line ( @batch )
		{
			if ( $line eq $mark_conf_begin )
			{
				$has_config = 1;
				last;
			}
		}

		my @ruleset_conf_arr = ();
		if ( not $has_config )
		{
			if ( -f $path )
			{
				$ruleset_conf = &getWAFSetConf( $file->{ name } );
			}
			else
			{
				$ruleset_conf->{ configuration } = &getWAFSetStructConf();
			}
			@ruleset_conf_arr = &buildWAFSetConf( $ruleset_conf->{ configuration } );
		}

		my $flock = &openlock( $lock_file, 'w' );
		if ( not $flock )
		{
			my $msg = "Error locking file '$lock_file'";
			&zenlog( $msg, 'error', 'waf' );
			$error_ref->{ code } = 4;
			$error_ref->{ desc } = $msg;
			return $error_ref;

		}
		my $fh = &openlock( $tmp, 'w' );
		if ( not $fh )
		{
			close $flock;
			my $msg = "Error locking file '$tmp'";
			&zenlog( $msg, 'error', 'waf' );
			$error_ref->{ code } = 4;
			$error_ref->{ desc } = $msg;
			return $error_ref;
		}

		foreach my $line ( @ruleset_conf_arr )
		{
			print $fh $line . "\n";
		}

		print $fh $file->{ content };
		close $fh;

		# check seclang ruleset
		my $err_msg = &checkWAFFileSyntax( $tmp );

		# save file
		if ( $err_msg )
		{
			my $msg = "Error checking syntax '$file->{ name }': $err_msg";
			&zenlog( $msg, 'error', 'waf' );
			$error_ref->{ code } = 2;
			$error_ref->{ desc } = $msg;
			close $flock;
			return $error_ref;
		}
		else
		{
			if ( &copyLock( $tmp, $path ) )
			{
				my $msg = "Error saving changes in '$file->{ name }'";
				&zenlog( $msg, 'error', 'waf' );
				$error_ref->{ code } = 3;
				$error_ref->{ desc } = $msg;
			}
			else
			{
				#restart rule
			}
		}

		close $flock;
	}

	&zenlog( "$log_tag the WAF file '$path'", 'info', 'waf' );
	$error_ref->{ desc } = $log_tag;

	&logAndRun( "chmod +x $path " ) if ( $file->{ type } eq 'script' );

	return $error_ref;
}

=begin nd
Function: deleteWAFFile

	It deletes a file of the WAF module.

Parameters:
	Path - It is the absolute path to the file

Returns:
	Integer - It is the error code. 0 on success or another value on failure

=cut

sub deleteWAFFile
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $path = shift;

	my $del = unlink $path;
	if ( $del )
	{
		&zenlog( "The file '$path' was deleted", 'info', 'waf' );
	}
	else
	{
		&zenlog( "The file '$path' could not be deleted", 'error', 'waf' );
	}

	return ( $del ) ? 0 : 1;
}

=begin nd
Function: checkWAFFileUsed

	It checks if some WAF rule is using a required file

Parameters:
	File name - It is the file name without extension and without path

Returns:
	Array ref - It is a list with all WAF rulesets are using the file

=cut

sub checkWAFFileUsed
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	my $name = shift;
	my @sets = ();

	opendir ( my $fd, $wafFileDir );

	foreach my $file ( readdir ( $fd ) )
	{
		next if ( $file !~ /\.conf$/ );

		my $fh = &openlock( "$wafFileDir/$file", 'r' );
		push @sets, $file if ( grep ( /\b$name\b/, <$fh> ) );
		close $fh;
	}
	closedir ( $fd );

	grep ( s/\.conf$//, @sets );
	return \@sets;
}

1;

