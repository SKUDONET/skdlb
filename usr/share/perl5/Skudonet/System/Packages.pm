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
require Skudonet::Log;
use Skudonet::SystemInfo;
use File::Grep qw( fgrep );

my $eload;
if ( eval { require Skudonet::ELoad; } )
{
	$eload = 1;
}

=begin nd
Function: setSystemPackagesRepo

    It configures the system to connect with the APT.

Parameters:

Returns:
	Integer - Error code, 0 on success or another value on failure

=cut

sub setSystemPackagesRepo
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	if ( $eload )
	{
		return
		  &eload( module => 'Skudonet::Apt',
				  func   => 'setAPTRepo', );
	}

	# Variables
	my $host         = &getGlobalConfiguration( 'repo_url_skudonet' );
	my $file         = &getGlobalConfiguration( 'apt_source_skudonet' );
	my $aptget_bin   = &getGlobalConfiguration( 'aptget_bin' );
	my $distribution = "bookworm";
	my $error        = 0;

	&zenlog( "Configuring the APT repository", "info", "SYSTEM" );

	# get the kernel version
	my $kernelversion = &getKernelVersion();

	# configuring repository
	open ( my $FH, '>', $file ) or die "Could not open file '$file' $!";

	if ( $kernelversion =~ /^6.1/ )
	{
		print $FH "deb http://$host/ce/v7/ $distribution main\n";
		&zenlog( "$file configured", "info", "SYSTEM" );
	}
	else
	{
		&zenlog( "The kernel version is not valid, $kernelversion", "error", "apt" );
		$error = 1;
	}

	close $FH;

	if ( !$error )
	{
		my $aptfile = &getGlobalConfiguration( 'fileapt' );
		if ( fgrep { /^\s*deb\s+cdrom:.*Skudonet/ } "$aptfile" )
		{
			&zenlog( "Found Skudonet cdrom : APT list not updated", "info", "SYSTEM" );
		}
		else
		{
			# update repositories
			$error = &logAndRun(
				"$aptget_bin update -o Dir::Etc::sourceparts=\"-\" -o Dir::Etc::sourcelist=$file"
			);
			&zenlog( "APT list updated", "info", "SYSTEM" );
		}
	}

	return $error;
}

=begin nd
Function: getSystemPackagesUpdatesList

    It returns information about the status of the system regarding updates.
    This information is parsed from a file

Parameters:

Returns:
	Hash ref -
		{
			 'message'    := message with the instructions to update the system
			 'last_check' := date of the last time that checkupgrades (or apt-get) was executed
			 'status'     := information about if there is pending updates.
			 'number'     := number of packages pending of updating
			 'packages'   := list of packages pending of updating
		};

=cut

sub getSystemPackagesUpdatesList
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	require Skudonet::Lock;
	my $package_list = &getGlobalConfiguration( 'apt_outdated_list' );
	my $message_file = &getGlobalConfiguration( 'apt_msg' );

	my @pkg_list = ();
	my $msg;
	my $date   = "";
	my $status = "unknown";
	my $install_msg;
	if ( $eload )
	{
		my $install_msg =
		  "To upgrade the system, please, execute in a shell the following command:
			'checkupgrades -i'";
	}
	else
	{
		my $install_msg =
		  "To upgrade the system, please, execute in a shell the following command:
			'checkupdates -i'";
	}

	my $fh = &openlock( $package_list, '<' );
	if ( $fh )
	{
		@pkg_list = split ( ' ', <$fh> );
		close $fh;

		# remove the first item
		shift @pkg_list if ( $pkg_list[0] eq 'Listing...' );
	}

	$fh = &openlock( $message_file, '<' );
	if ( $fh )
	{
		$msg = <$fh>;
		close $fh;

		if ( $msg =~ /last check at (.+) -/ )
		{
			$date   = $1;
			$status = "Updates available";
		}
		elsif ( $msg =~ /Skudonet Packages are up-to-date/ )
		{
			$status = "Updated";
		}
	}

	return {
			 'message'    => $install_msg,
			 'last_check' => $date,
			 'status'     => $status,
			 'number'     => scalar @pkg_list,
			 'packages'   => \@pkg_list
	};
}

1;
