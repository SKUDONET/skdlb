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

=begin nd
Function: getIPDSfarmsRules

	Gather all the IPDS rules applied to a given farm

Parameters:
	farmName - farm name to get its IPDS rules

Returns:
	scalar - array reference of array references ('dos', 'blacklists', 'rbl', 'waf') hashes in the form of ('name', 'rule', 'type')

=cut

sub getIPDSfarmsRules
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farmName = shift;

	require Config::Tiny;
	include 'Zevenet::IPDS::WAF::Core';

	my $rules;
	my $fileHandle;
	my @dosRules        = ();
	my @blacklistsRules = ();
	my @rblRules        = ();

	my $dosConf        = &getGlobalConfiguration( 'dosConf' );
	my $blacklistsConf = &getGlobalConfiguration( 'blacklistsConf' );
	my $rblPath        = &getGlobalConfiguration( 'configdir' ) . "/ipds/rbl";
	my $rblConf        = "$rblPath/rbl.conf";

	if ( -e $dosConf )
	{
		$fileHandle = Config::Tiny->read( $dosConf );
		foreach my $key ( sort keys %{ $fileHandle } )
		{
			if ( exists $fileHandle->{ $key }->{ 'farms' }
				 && $fileHandle->{ $key }->{ 'farms' } =~ /( |^)$farmName( |$)/ )
			{
				my $status = $fileHandle->{ $key }->{ 'status' } || "down";
				push @dosRules, { 'name' => $key, 'status' => $status };
			}
		}
	}

	if ( -e $blacklistsConf )
	{
		$fileHandle = Config::Tiny->read( $blacklistsConf );
		foreach my $key ( sort keys %{ $fileHandle } )
		{
			if ( $fileHandle->{ $key }->{ 'farms' } =~ /( |^)$farmName( |$)/ )
			{
				my $status = $fileHandle->{ $key }->{ 'status' } || "down";
				push @blacklistsRules, { 'name' => $key, 'status' => $status };
			}
		}
	}

	if ( -e $rblConf )
	{
		$fileHandle = Config::Tiny->read( $rblConf );
		foreach my $key ( sort keys %{ $fileHandle } )
		{
			if ( $fileHandle->{ $key }->{ 'farms' } =~ /( |^)$farmName( |$)/ )
			{
				my $status = $fileHandle->{ $key }->{ 'status' } || "down";
				push @rblRules, { 'name' => $key, 'status' => $status };
			}
		}
	}

	$rules = {
			   dos        => \@dosRules,
			   blacklists => \@blacklistsRules,
			   rbl        => \@rblRules,
			   waf        => []
	};

	# add waf if the rule is HTTP
	require Zevenet::Farm::Core;
	if ( &getFarmType( $farmName ) =~ /http/ )
	{
		foreach my $ru ( &listWAFByFarm( $farmName ) )
		{
			push @{ $rules->{ waf } }, { 'name' => $ru };
		}
	}

	return $rules;
}

=begin nd
Function: getIPDSRules

	Gather all the IPDS rules

Parameters:
	none

Returns:
	scalar - array reference of hashes in the form of ('name', 'rule', 'type')

=cut

sub getIPDSRules
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	require Config::Tiny;
	include 'Zevenet::IPDS::WAF::Core';

	my @rules = ();
	my $fileHandle;

	my $dosConf        = &getGlobalConfiguration( 'dosConf' );
	my $blacklistsConf = &getGlobalConfiguration( 'blacklistsConf' );
	my $rblPath        = &getGlobalConfiguration( 'configdir' ) . "/ipds/rbl";
	my $rblConf        = "$rblPath/rbl.conf";

	if ( -e $dosConf )
	{
		$fileHandle = Config::Tiny->read( $dosConf );
		foreach my $key ( keys %{ $fileHandle } )
		{
			push @rules,
			  {
				'name' => $key,
				'rule' => 'dos',
				'type' => $fileHandle->{ $key }->{ type }
			  };
		}
	}

	if ( -e $blacklistsConf )
	{
		$fileHandle = Config::Tiny->read( $blacklistsConf );
		foreach my $key ( keys %{ $fileHandle } )
		{
			push @rules, { 'name' => $key, 'rule' => 'blacklist' };
		}
	}

	if ( -e $rblConf )
	{
		$fileHandle = Config::Tiny->read( $rblConf );
		foreach my $key ( keys %{ $fileHandle } )
		{
			push @rules, { 'name' => $key, 'rule' => 'rbl' };
		}
	}

	foreach my $ru ( &listWAFSet() )
	{
		push @rules, { 'name' => $ru, 'rule' => 'waf' };
	}

	return \@rules;
}

=begin nd
Function: setIPDSFarmParam

	Apply an IPDS parameter to a farm independently of the profile

Parameters:
	param - ipds parameter to set to the farm
	value - value to set to the given parameter
	farm - name of the farm to be applied the new value

Returns:
	Integer - Code error: 0 on success or other value on failure

=cut

sub setIPDSFarmParam
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $param = shift;
	my $value = shift;
	my $farm  = shift;

	require Zevenet::Farm::Core;

	my $output = 0;
	my $type   = &getFarmType( $farm );
	my $attrib = "";
	my $delete = 0;

	if ( $type eq "l4xnat" )
	{
		require Zevenet::Farm::L4xNAT::Config;
		$output = &setL4FarmParam( $param, $value, $farm );
	}
	else
	{
		if ( $param eq 'sshbruteforce' )
		{
			return 0;
		}
		elsif ( $param eq 'dropicmp' )
		{
			return 0;
		}
		elsif ( $param eq 'limitconns' )
		{
			$attrib = qq(, "est-connlimit" : "$value" );
			$delete = 1 if ( $value eq "0" );
		}
		elsif ( $param eq 'limitsec' )
		{
			$attrib = qq(, "new-rtlimit" : "$value" );
		}
		elsif ( $param eq 'limitsecbrst' )
		{
			$attrib = qq(, "new-rtlimit-burst" : "$value" );
			$delete = 1 if ( $value eq "0" );
		}
		elsif ( $param eq 'limitrst' )
		{
			$attrib = qq(, "rst-rtlimit" : "$value" );
		}
		elsif ( $param eq 'limitrstbrst' )
		{
			$attrib = qq(, "rst-rtlimit-burst" : "$value" );
			$delete = 1 if ( $value eq "0" );
		}
		elsif ( $param eq 'bogustcpflags' )
		{
			$attrib = qq(, "tcp-strict" : "$value" );
			$delete = 1 if ( $value eq "off" );
		}
		elsif ( $param eq 'nfqueue' )
		{
			$attrib = qq(, "queue" : "$value" );
			$delete = 1 if ( $value eq "-1" );
		}
		elsif ( $param eq 'policy' )
		{
			$attrib = qq(, "policies" : [ { "name" : "$value" } ] );
		}
		else
		{
			return -1;
		}

		my $vip  = &getFarmVip( 'vip',  $farm );
		my $port = &getFarmVip( 'vipp', $farm );
		my $proto = "tcp";
		$proto = "udp" if ( &getFarmProto( $farm ) eq "UDP" );

		require Zevenet::Nft;

		$output = httpNlbRequest(
			{
			   farm   => $farm,
			   method => "PUT",
			   uri    => "/farms",
			   body =>
				 qq({"farms" : [ { "name" : "$farm", "virtual-addr" : "$vip", "virtual-ports" : "$port", "protocol" : "$proto", "mode" : "dnat"$attrib } ] })
			}
		);

		if ( $delete == 1 )
		{
			# if there is no rule remaining, delete the service
			my $rules = &getIPDSfarmsRules( $farm );
			if (    !@{ $rules->{ 'dos' } }
				 && !@{ $rules->{ 'blacklists' } }
				 && !@{ $rules->{ 'rbl' } }
				 && !@{ $rules->{ 'waf' } } )
			{
				$output = httpNlbRequest(
										  {
											farm   => $farm,
											method => "DELETE",
											uri    => "/farms/" . $farm,
										  }
				);
			}
		}
	}

	return $output;
}

=begin nd
Function: delIPDSFarmParam

	Delete an IPDS object of a farm independently of the profile

Parameters:
	param - ipds parameter to set to the farm
	value - value to set to the given parameter
	farm - name of the farm to be applied the new value

Returns:
	Integer - Code error: 0 on success or other value on failure

=cut

sub delIPDSFarmParam
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $param = shift;
	my $value = shift;
	my $farm  = shift;

	my $output = 0;
	my $attrib = "";
	my $type   = &getFarmType( $farm );

	if ( $param eq "policy" )
	{
		$attrib = "/policies";
		$attrib = $attrib . "/$value" if ( defined $value && $value ne "" );
	}
	else
	{
		return -1;
	}

	require Zevenet::Nft;

	$output = httpNlbRequest(
							  {
								method => "DELETE",
								uri    => "/farms/" . $farm . $attrib,
							  }
	);

	if ( $type eq "l4xnat" )
	{
		require Zevenet::Farm::Core;
		my $farm_filename = &getFarmFile( $farm );
		my $configdir     = &getGlobalConfiguration( 'configdir' );

		$output = httpNlbRequest(
								  {
									method => "GET",
									uri    => "/farms/" . $farm,
									file   => "$configdir/$farm_filename",
								  }
		);
	}
	else
	{
		# if there is no rule remaining, delete the service
		my $rules = &getIPDSfarmsRules( $farm );
		if (    !@{ $rules->{ 'dos' } }
			 && !@{ $rules->{ 'blacklists' } }
			 && !@{ $rules->{ 'rbl' } }
			 && !@{ $rules->{ 'waf' } } )
		{
			$output = httpNlbRequest(
									  {
										farm   => $farm,
										method => "DELETE",
										uri    => "/farms/" . $farm,
									  }
			);
		}
	}

	return $output;
}

=begin nd
Function: setIPDSPolicyParam

	Apply an IPDS parameter to a policy

Parameters:
	param - ipds parameter to set to the list. Values are: name, type, element, elements
	value - value to set to the given parameter
	list - name of the policy to be applied the new value

Returns:
	Integer - Code error: 0 on success or other value on failure

=cut

sub setIPDSPolicyParam
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $param = shift;
	my $value = shift;
	my $list  = shift;

	my $output = 0;
	my $attrib = "";

	if ( $param eq "name" )
	{
	}
	elsif ( $param eq "element" )
	{
		$attrib = qq(, "elements" : [{ "data" : "$value" }]);
	}
	elsif (    $param eq "elements"
			&& ref ( $value ) eq "ARRAY"
			&& scalar ( @{ $value } ) > 0 )
	{
		my $first = 1;
		$attrib = qq(, "elements" : [);

		foreach my $item ( @{ $value } )
		{
			if ( !$first )
			{
				$attrib = qq($attrib, { "data" : "$item" });
			}
			else
			{
				$attrib = qq($attrib { "data" : "$item" });
				$first--;
			}
		}
		$attrib = qq($attrib ]);
	}
	elsif ( $param eq "type" )
	{
		$attrib = qq(, "type" : "$value" );
	}
	else
	{
		return -1;
	}

	require Zevenet::Nft;

	my $file = "/tmp/ipds_$$";

	open ( my $fh, '>', "$file" );
	print $fh qq({"policies" : [ { "name" : "$list"$attrib } ] });
	close $fh;

	$output = httpNlbRequest(
							  {
								method => "PUT",
								uri    => "/policies",
								body   => "@" . "$file"
							  }
	);

	unlink ( $file );

	return $output;
}

=begin nd
Function: getIPDSPolicyParam

	Obtain an IPDS parameter to a policy

Parameters:
	param - ipds parameter to set to the farm. Valid values are: name, type, farms, elements
	value - value expected for the param
	list - name of the policy to be applied the new value

Returns:
	Scalar - array reference if a list

=cut

sub getIPDSPolicyParam
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $param = shift;
	my $list  = shift;

	my $output = -1;
	my $attrib = "";
	my $name   = "";
	my $file   = "/tmp/ipds_$$";

	if ( defined $list && $list ne "" )
	{
		$attrib = "/$list";
	}

	require Zevenet::Nft;

	$output = httpNlbRequest(
							  {
								method => "GET",
								file   => $file,
								uri    => "/policies$attrib",
							  }
	);

	if ( !-e "$file" )
	{
		return -2;
	}

	open my $fd, '<', "$file";
	chomp ( my @content = <$fd> );
	close $fd;

	unlink ( $file );

	my @policies = ();

	if ( !defined $list || $list eq "" )
	{
		foreach my $line ( @content )
		{
			if ( $line =~ /\"name\"/ )
			{
				my @l = split /"/, $line;
				my $val = $l[3];
				push @policies, { $val };
			}
		}
		return \@policies;
	}

	foreach my $line ( @content )
	{
		if ( $line =~ /\"name\"/ )
		{
			my @l = split /"/, $line;
			$name = $l[3];
		}

		if ( $param eq 'name' )
		{
			return 1 if ( $list eq $name );
			next;
		}

		if ( $list eq $name && $line =~ /\"farms-used\"/ && $param eq 'farms' )
		{
			my @l = split /"/, $line;
			my $val = $l[3];
			return $val;
		}
	}

	return $output;
}

=begin nd
Function: delIPDSPolicy

	Delete policy objects

Parameters:
	param - ipds parameter to set to the list. Values are: element, elements, policy
	value - list element to delete, only required when 'element' parameter is set
	list - name of the policy to be applied the new value

Returns:
	Integer - Code error: 0 on success or other value on failure

=cut

sub delIPDSPolicy
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $param = shift;
	my $value = shift;
	my $list  = shift;

	my $output = 0;
	my $attrib = "";

	if ( $param eq "policies" )
	{
		$attrib = "";
	}
	elsif ( $param eq "policy" )
	{
		$attrib = "/$list";
	}
	elsif ( $param eq "elements" )
	{
		$attrib = "/$list/elements";
	}
	elsif ( $param eq "element" && defined $value && $value ne "" )
	{
		$attrib = "/$list/element/$value";
	}
	else
	{
		return -1;
	}

	require Zevenet::Nft;

	$output = httpNlbRequest(
							  {
								method => "DELETE",
								uri    => "/policies$attrib",
							  }
	);

	return $output;
}

1;
