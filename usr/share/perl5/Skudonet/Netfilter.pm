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

#
sub loadNfModule    # ($modname,$params)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $modname, $params ) = @_;

	my $status  = 0;
	my $lsmod   = &getGlobalConfiguration( 'lsmod' );
	my @modules = @{ &logAndGet( $lsmod, "array" ) };

	if ( !grep { /^$modname /x } @modules )
	{
		my $modprobe         = &getGlobalConfiguration( 'modprobe' );
		my $modprobe_command = "$modprobe $modname $params";

		&zenlog( "L4 loadNfModule: $modprobe_command", "info", "SYSTEM" );
		$status = &logAndRun( "$modprobe_command" );
	}

	return $status;
}

#
sub removeNfModule    # ($modname)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $modname = shift;

	my $modprobe         = &getGlobalConfiguration( 'modprobe' );
	my $modprobe_command = "$modprobe -r $modname";

	&zenlog( "L4 removeNfModule: $modprobe_command", "info", "SYSTEM" );

	return &logAndRun( "$modprobe_command" );
}

#
sub getNewMark    # ($farm_name)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farm_name = shift;

	require Tie::File;
	require Skudonet::Lock;

	my $found       = 0;
	my $marknum     = 0x200;
	my $fwmarksconf = &getGlobalConfiguration( 'fwmarksconf' );
	my @contents;

	&ztielock( \@contents, "$fwmarksconf" );

	for my $i ( 512 .. 4095 )
	{
		my $num = sprintf ( "0x%x", $i );
		if ( !grep { /^$num/x } @contents )
		{
			$found   = 1;
			$marknum = $num;
			last;
		}
	}

	if ( $found )
	{
		push @contents, "$marknum // FARM\_$farm_name\_";
	}

	untie @contents;

	return $marknum;
}

#
sub delMarks    # ($farm_name,$mark)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $mark ) = @_;

	require Skudonet::Lock;

	my $status      = 0;
	my $fwmarksconf = &getGlobalConfiguration( 'fwmarksconf' );
	my @contents;

	if ( $farm_name ne "" )
	{
		&ztielock( \@contents, "$fwmarksconf" );
		@contents = grep { !/ \/\/ FARM\_$farm_name\_$/ } @contents;
		untie @contents;
	}

	if ( $mark ne "" )
	{
		&ztielock( \@contents, "$fwmarksconf" );
		@contents = grep { !/^$mark \/\/ FARM\_/ } @contents;
		untie @contents;
	}

	return $status;
}

#
sub renameMarks    # ( $farm_name, $newfname )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	my $farm_name = shift;
	my $newfname  = shift;

	require Tie::File;

	my $status = 0;

	if ( $farm_name ne "" )
	{
		my $fwmarksconf = &getGlobalConfiguration( 'fwmarksconf' );
		tie my @contents, 'Tie::File', "$fwmarksconf";
		foreach my $line ( @contents )
		{
			$line =~ s/ \/\/ FARM\_$farm_name\_/ \/\/ FARM\_$newfname\_/x;
		}
		$status = $?;    # FIXME
		untie @contents;
	}

	return $status;      # FIXME
}

1;

