#!/usr/bin/perl
###############################################################################
#
#    SKUDONET Software License
#    This file is part of the SKUDONET Load Balancer software package.
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
use Regexp::IPv6 qw($IPv6_re);
require Skudonet::Net::Validate;

# Notes about regular expressions:
#
# \w matches the 63 characters [a-zA-Z0-9_] (most of the time)
#

my $UNSIGNED8BITS = qr/(?:25[0-5]|2[0-4]\d|(?!0)[1]?\d\d?|0)/;       # (0-255)
my $UNSIGNED7BITS = qr/(?:[0-9]{1,2}|10[0-9]|11[0-9]|12[0-8])/;      # (0-128)
my $cidr          = qr/(?:3[0-2]|[1-2][0-9]|[0-9])/;                 # (0-32)
my $HEXCHAR       = qr/(?:[A-Fa-f0-9])/;
my $ipv6_word     = qr/(?:$HEXCHAR+){1,4}/;
my $ipv4_addr     = qr/(?:$UNSIGNED8BITS\.){3}$UNSIGNED8BITS/;
my $ipv6_addr     = $IPv6_re;
my $mac_addr      = qr/(?:$HEXCHAR$HEXCHAR\:){5}$HEXCHAR$HEXCHAR/;
my $ipv4v6        = qr/(?:$ipv4_addr|$ipv6_addr)/;
my $boolean       = qr/(?:true|false)/;
my $enable        = qr/(?:enable|disable)/;
my $integer       = qr/\d+/;
my $natural = qr/[1-9]\d*/;    # natural number = {1, 2, 3, ...}
my $weekdays = qr/(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday)/;
my $minutes  = qr/(?:\d|[0-5]\d)/;
my $hours    = qr/(?:\d|[0-1]\d|2[0-3])/;
my $months   = qr/(?:[1-9]|1[0-2])/;
my $dayofmonth = qr/(?:[1-9]|[1-2]\d|3[01])/;            # day of month
my $rrdTime    = qr/\d\d-\d\d-(?:\d\d)?\d\d-\d\d:\d\d/
  ;    # MM-DD-[YY]YY-hh:mm ; example: "11-09-2020-14:05";

my $hostname = qr/[a-z][a-z0-9\-]{0,253}[a-z0-9]/;
my $service  = qr/[a-zA-Z0-9][a-zA-Z0-9_\-\.]*/;
my $zone     = qr/(?:$hostname\.)+[a-z]{2,}/;

my $cert_name = qr/(?:\*[_|\.])?\w[\w\.\(\)\@ \-]*/;

my $vlan_tag    = qr/\d{1,4}/;
my $virtual_tag = qr/[a-zA-Z0-9\-]{1,13}/;
my $nic_if      = qr/[a-zA-Z0-9\-]{1,15}/;
my $vlan_if   = qr/[a-zA-Z0-9\-]{1,13}\.$vlan_tag/;
my $interface = qr/$nic_if(?:\.$vlan_tag)?(?:\:$virtual_tag)?/;
my $port_range =
  qr/(?:[1-9]\d{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])/;
my $graphsFrequency = qr/(?:daily|weekly|monthly|yearly)/;


my $run_actions = qr/^(?:stop|start|restart)$/;

my $name  = qr/^(?:[a-zA-Z0-9][\w]{5,31})$/;
my $email = qr/(?:[a-zA-Z][\w\_\.]+)\@(?:[a-zA-Z0-9.-]+)\.(?:[a-zA-Z]{2,4})/;

my $waf_file     = qr/(?:[\s+\w-]+)/;
my $waf_file_ext = qr/(?:lua|LUA|conf|CONF|data|DATA)/;

my %format_re = (

	# generic types
	'integer'     => $integer,
	'natural_num' => $natural,
	'boolean'     => $boolean,
	'ipv4v6'      => $ipv4v6,
	'rrd_time'    => $rrdTime,

	# hostname
	'hostname' => $hostname,
	'fqdn'     => qr/$hostname(?:\.$hostname)*/,

	# license
	'license_format' => qr/(?:txt|html)/,

	# log
	'log' => qr/[\.\-\w]+/,

	#zapi
	'zapi_key'      => qr/[a-zA-Z0-9]+/,
	'zapi_status'   => $enable,
	'zapi_password' => qr/.+/,

	# common
	'port' => $port_range,
	'multiport' =>
	  qr/(?:\*|(?:$port_range|$port_range\:$port_range)(?:,$port_range|,$port_range\:$port_range)*)/,

	'user'     => qr/[\w]+/,
	'password' => qr/.+/,

	# system
	'dns_nameserver' => $ipv4v6,
	'dns'            => qr/(?:primary|secondary)/,
	'snmp_status'    => $boolean,
	'snmp_ip'        => qr/(?:$ipv4v6|\*)/,
	'snmp_community' => qr{.+},
	'snmp_port'      => $port_range,
	'snmp_scope'     => qr{(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}},    # ip/mask
	'ntp'            => qr{[\w\.\-]+},
	'http_proxy' => qr{\S*},    # use any character except the spaces


	# farms
	'farm_name'    => qr/[a-zA-Z0-9\-]+/,
	'farm_profile' => qr/HTTP|L4XNAT|DATALINK/,
	'backend'      => qr/\d+/,
	'service'      => $service,
	'http_service' => qr/[a-zA-Z0-9\-]+/,
	'farm_modules'          => qr/(?:dslb|lslb)/,
	'service_position'      => qr/\d+/,
	'l4_session'            => qr/[ \._\:\w]+/,
	'l7_session'            => qr/[ \._\:\w]+/,
	'farm_maintenance_mode' => qr/(?:drain|cut)/,    # not used from API 4

	# cipher
	'ciphers' =>
	  qr/(?:all|highsecurity|customsecurity|ssloffloading)/,   # not used from API 4

	# backup
	'backup'        => qr/[\w-]+/,
	'backup_action' => qr/apply/,

	# graphs
	'graphs_frequency' => $graphsFrequency,
	'graphs_system_id' => qr/(?:cpu|load|ram|swap)/,
	'mount_point'      => qr/root[\w\-\.\/]*/,


	# http
	'redirect_code'    => qr/(?:301|302|307)/,    # not used from API 4
	'http_sts_status'  => qr/(?:true|false)/,     # not used from API 4
	'http_sts_timeout' => qr/(?:\d+)/,


	# interfaces ( WARNING: length in characters < 16  )
	'mac_addr'      => $mac_addr,
	'interface'     => $interface,
	'nic_interface' => $nic_if,
	'vlan_interface'   => $vlan_if,
	'virt_interface'   => qr/(?:$nic_if)(?:\.$vlan_tag)?:$virtual_tag/,
	'routed_interface' => qr/(?:$nic_if|$vlan_if)/,
	'interface_type'   => qr/(?:nic|vlan|virtual)/,
	'vlan_tag'         => qr/$vlan_tag/,
	'virtual_tag'      => qr/$virtual_tag/,

	# WAF
	'waf_set_name'   => qr/[\.\w-]+/,
	'waf_file'       => $waf_file,
	'waf_file_ext'   => $waf_file_ext,
	'waf_audit_log'  => qr/(?:$boolean|)/,
	'waf_set_status' => qr/(?:$boolean|detection)/,

	# certificates filenames
	'certificate_name'    => $cert_name,
	'certificate'         => qr/$cert_name\.(?:pem|csr)/,
	'cert_pem'            => qr/$cert_name\.pem/,
	'cert_name'           => qr/[a-zA-Z0-9\-]+/,
	'cert_csr'            => qr/\w[\w\.\-]*\.csr/,
	'cert_csr_key'        => qr/\w[\w\.\-]*\.key/,
	'cert_dh2048'         => qr/\w[\w\.\-]*_dh2048\.pem/,
	'le_certificate_name' => $cert_name,
	'le_mail'             => $email,

	# IPS
	'IPv4_addr' => qr/$ipv4_addr/,
	'IPv4_mask' => qr/(?:$ipv4_addr|3[0-2]|[1-2][0-9]|[0-9])/,

	'IPv6_addr' => qr/$ipv6_addr/,
	'IPv6_mask' => $UNSIGNED7BITS,

	'ip_addr'       => $ipv4v6,
	'ip_mask'       => qr/(?:$ipv4_addr|$UNSIGNED7BITS)/,
	'ip_addr_range' => qr/$ipv4_addr-$ipv4_addr/,

	# farm guardian
	'fg_name'    => qr/[\w-]+/,
	'fg_type'    => qr/(?:http|https|l4xnat)/,    # not used from API 4
	'fg_enabled' => $boolean,
	'fg_log'     => $boolean,
	'fg_time'    => qr/$natural/,                 # this value can't be 0


);


sub getZAPIModel
{
	my $file = shift;
	require Skudonet::Zapi;
	my $api_version = &getZapiVersion();
	my $dir = &getGlobalConfiguration( "zapi_model_path" ) . "/v$api_version/json";

	require JSON;
	my $content;
	{
		open ( my $fh, '<', "$dir/$file" ) or die "The file '$dir/$file' was not found";
		local $/ = undef;
		$content = <$fh>;
		close $fh;
	}
	return JSON::decode_json( $content )->{ params } if ( $content ne "" );
}

=begin nd
Function: getValidFormat

	Validates a data format matching a value with a regular expression.
	If no value is passed as an argument the regular expression is returned.

	Usage:

	# validate exact data
	if ( ! &getValidFormat( "farm_name", $input_farmname ) ) {
		print "error";
	}

	# use the regular expression as a component for another regular expression
	my $file_regex = &getValidFormat( "certificate" );
	if ( $file_path =~ /$configdir\/$file_regex/ ) { ... }

Parameters:
	format_name	- type of format
	value		- value to be validated (optional)
	new_format_re	- structure with the formats to use. (optional)

Returns:
	false	- If value failed to be validated
	true	- If value was successfuly validated
	regex	- If no value was passed to be matched

See also:
	Mainly but not exclusively used in zapi v3.
=cut

# &getValidFormat ( $format_name, $value );
sub getValidFormat
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $format_name, $value, %new_format_re ) = @_;

	# Checks if it should use the formats passed by parameters.
	%format_re = %new_format_re if ( %new_format_re );

	#~ print "getValidFormat type:$format_name value:$value\n"; # DEBUG
	if ( exists $format_re{ $format_name } )
	{
		if ( defined $value )
		{
			#~ print "$format_re{ $format_name }\n"; # DEBUG
			if ( ref ( $value ) eq "ARRAY" )
			{
				return !grep ( !/^$format_re{ $format_name }$/, @{ $value } ) > 0;
			}
			else
			{
				return $value =~ /^$format_re{ $format_name }$/;
			}
		}
		else
		{
			#~ print "$format_re{ $format_name }\n"; # DEBUG
			return $format_re{ $format_name };
		}
	}
	else
	{
		my $message = "getValidFormat: format $format_name not found.";
		&zenlog( $message );
		die ( $message );
	}
}

=begin nd
Function: getValidPort

	Validate if the port is valid for a type of farm.

Parameters:
	port - Port number.
	profile - Farm profile (HTTP, L4XNAT, GSLB or DATALINK). Optional.

Returns:
	Boolean - TRUE for a valid port number, FALSE otherwise.

Bugs:

See Also:
	zapi/v3/post.cgi
=cut

sub getValidPort    # ( $ip, $port, $profile )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $port    = shift;
	my $profile = shift;    # farm profile, optional

	if ( $profile =~ /^(?:HTTP)$/i )
	{
		return &getValidFormat( 'port', $port );
	}
	elsif ( $profile =~ /^(?:L4XNAT)$/i )
	{
		return &getValidFormat( 'multiport', $port );
	}
	elsif ( $profile =~ /^(?:DATALINK)$/i )
	{
		return $port eq undef;
	}
	elsif ( !defined $profile )
	{
		return &getValidFormat( 'port', $port );
	}
	else    # profile not supported
	{
		return 0;
	}
}

=begin nd
Function: getValidOptParams

[DEPRECATED]: It is used untill the API 3.2. Now, use checkZAPIParams

	Check parameters when all params are optional

	Before called:	getValidPutParams

Parameters:
	\%json_obj - .
	\@allowParams - .

Returns:
	none - .

Bugs:

See Also:

=cut

sub getValidOptParams    # ( \%json_obj, \@allowParams )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $params         = shift;
	my $allowParamsRef = shift;
	my @allowParams    = @{ $allowParamsRef };
	my $output;
	my $pattern;

	if ( !keys %{ $params } )
	{
		return "Not found any param.";
	}

	# Check if any param isn't for this call
	$pattern .= "$_|" for ( @allowParams );
	chop ( $pattern );
	my @errorParams = grep { !/^(?:$pattern)$/ } keys %{ $params };
	if ( @errorParams )
	{
		$output .= "$_, " for ( @errorParams );
		chop ( $output );
		chop ( $output );
		$output = "Illegal params: $output";
	}

	return $output;
}

=begin nd
Function: getValidReqParams

[DEPRECATED]: It is used untill the API 3.2. Now, use checkZAPIParams

	Check parameters when there are required params

	Before called:	getValidPostParams

Parameters:
	\%json_obj - .
	\@requiredParams - .
	\@optionalParams - .

Returns:
	none - .

Bugs:

See Also:

=cut

sub getValidReqParams    # ( \%json_obj, \@requiredParams, \@optionalParams )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $params            = shift;
	my $requiredParamsRef = shift;
	my $allowParamsRef    = shift || [];
	my @requiredParams    = @{ $requiredParamsRef };
	my @allowParams;
	@allowParams = @{ $allowParamsRef } if ( $allowParamsRef );
	push @allowParams, @requiredParams;
	my $output;
	my $pattern;

	# Check all required params are in called
	$pattern .= "$_|" for ( @requiredParams );

	chop ( $pattern );
	my $aux = grep { /^(?:$pattern)$/ } keys %{ $params };
	if ( $aux != scalar @requiredParams )
	{
		$aux    = scalar @requiredParams - $aux;
		$output = "Missing required parameters. Parameters missed: $aux.";
	}

	# Check if any param isn't for this call
	if ( !$output )
	{
		$output  = "";
		$pattern = "";
		$pattern .= "$_|" for ( @allowParams );
		chop ( $pattern );
		my @errorParams = grep { !/^(?:$pattern)$/ } keys %{ $params };
		if ( @errorParams )
		{
			$output .= "$_, " for ( @errorParams );
			chop ( $output );
			chop ( $output );
			$output = "Illegal params: $output";
		}
	}

	return $output;
}

=begin nd
Function: checkZAPIParams

	Function to check parameters of a PUT or POST call.
	It check a list of parameters, and apply it some checks:
	- Almost 1 parameter
	- All required parameters must exist
	- All required parameters are correct

	Also, it checks: getValidFormat funcion, if black is allowed, intervals, aditionals regex, excepts regex and a list with the possbile values

	It is possible add a error message with the correct format. For example: $parameter . "must have letters and digits"


Parameters:
	Json_obj - Parameters sent in a POST or PUT call
	Parameters - Hash of parameter objects

	parameter object:
	{
		parameter :
		{		# parameter is the key or parameter name
			"required" 	: "true",		# or not defined
			"non_blank" : "true",		# or not defined
			"interval" 	: "1,65535",	# it is possible define strings matchs ( non implement). For example: "ports" = "1-65535", "log_level":"1-3", ...
										# ",10" indicates that the value has to be less than 10 but without low limit
										# "10," indicates that the value has to be more than 10 but without high limit
										# The values of the interval has to be integer numbers
			"exceptions"	: [ "zapi", "webgui", "root" ],	# The parameter can't have got any of the listed values
			"values" : ["priority", "weight"],		# list of possible values for a parameter
			"length" : 32,				# it is the maximum string size for the value
			"regex"	: "/\w+,\d+/",		# regex format
			"ref"	: "array|hash",		# the expected input must be an array or hash ref. To allow ref inputs and non ref for a parameter use the word 'none'. Example:  'ref' => 'array|none'
			"valid_format"	: "farmname",		# regex stored in Validate.pm file, it checks with the function getValidFormat
			"function" : \&func,		# function of validating, the input parameter is the value of the argument. The function has to return 0 or 'false' when a error exists
			"format_msg"	: "must have letters and digits",	# used message when a value is not correct
		}
		param2 :
		{
			...
		}
		....
	}


Returns:
	String - Return a error message with the first error found or undef on success

=cut

sub checkZAPIParams
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $json_obj    = shift;
	my $param_obj   = shift;
	my $description = shift;
	my $err_msg;

	## Remove parameters do not according to the edition
	foreach my $p ( keys %$param_obj )
	{
		if ( exists $param_obj->{ $p }->{ edition } )
		{
			if ( $param_obj->{ $p }->{ edition } eq 'ee' )
			{
					delete $param_obj->{ $p };
			}
		}
	}

	my @rec_keys = keys %{ $json_obj };

	# Returns a help with the expected input parameters
	if ( !@rec_keys )
	{
		&httpResponseHelp( $param_obj, $description );
	}

	# All required parameters must exist
	my @expect_params = keys %{ $param_obj };

	$err_msg = &checkParamsRequired( \@rec_keys, \@expect_params, $param_obj );
	return $err_msg if ( $err_msg );

	# All sent parameters are correct
	$err_msg = &checkParamsInvalid( \@rec_keys, \@expect_params );
	return $err_msg if ( $err_msg );

	# check for each parameter
	foreach my $param ( @rec_keys )
	{
		my $custom_msg =
		  ( exists $param_obj->{ $param }->{ format_msg } )
		  ? "$param $param_obj->{ $param }->{ format_msg }"
		  : "The parameter '$param' has not a valid value.";

		if (   $json_obj->{ $param } eq ''
			or not defined $json_obj->{ $param }
			or ( ref $json_obj->{ $param } eq 'ARRAY' and @{ $json_obj->{ $param } } == 0 )
		  )
		{
			# if blank value is allowed
			if ( $param_obj->{ $param }->{ 'non_blank' } eq 'true' )
			{
				return "The parameter '$param' can't be in blank.";
			}

			# parameter validated, pass to next one
			next;
		}

		# the input has to be a ref
		my $r = ref $json_obj->{ $param } // '';
		if ( exists $param_obj->{ $param }->{ 'ref' } )
		{
			if ( $r eq '' )
			{
				if ( 'none' !~ /$param_obj->{ $param }->{ 'ref' }/ )
				{
					return
					  "The parameter '$param' expects a '$param_obj->{ $param }->{ref}' reference as input";
				}
			}
			elsif ( $r !~ /^$param_obj->{ $param }->{ 'ref' }$/i )
			{
				return
				  "The parameter '$param' expects a '$param_obj->{ $param }->{ref}' reference as input";
			}
		}
		elsif ( $r eq 'ARRAY' or $r eq 'HASH' )
		{
			return "The parameter '$param' does not expect a $r as input";
		}

		if ( ( exists $param_obj->{ $param }->{ 'values' } ) )
		{
			if ( $r eq 'ARRAY' )
			{
				foreach my $value ( @{ $json_obj->{ $param } } )
				{
					if ( !grep ( /^$value$/, @{ $param_obj->{ $param }->{ 'values' } } ) )
					{
						return
						  "The parameter '$param' expects some of the following values: '"
						  . join ( "', '", @{ $param_obj->{ $param }->{ 'values' } } ) . "'";
					}
				}
			}
			else
			{
				if (
					!grep ( /^$json_obj->{ $param }$/, @{ $param_obj->{ $param }->{ 'values' } } ) )
				{
					return
					  "The parameter '$param' expects one of the following values: '"
					  . join ( "', '", @{ $param_obj->{ $param }->{ 'values' } } ) . "'";
				}
			}
		}

		# getValidFormat funcion:
		if (
			 ( exists $param_obj->{ $param }->{ 'valid_format' } )
			 and (
				   !&getValidFormat(
									 $param_obj->{ $param }->{ 'valid_format' },
									 $json_obj->{ $param }
				   )
			 )
		  )
		{
			return $custom_msg;
		}

		# length
		if ( exists $param_obj->{ $param }->{ 'length' } )
		{
			my $data_length = length ( $json_obj->{ $param } );
			if ( $data_length > $param_obj->{ $param }->{ 'length' } )
			{
				return
				  "The maximum length for '$param' is '$param_obj->{ $param }->{ 'length' }'";
			}
		}

		# intervals
		if ( exists $param_obj->{ $param }->{ 'interval' } )
		{
			$err_msg = &checkParamsInterval( $param_obj->{ $param }->{ 'interval' },
											 $param, $json_obj->{ $param } );
			return $err_msg if $err_msg;
		}

		# exceptions
		if (
			 ( exists $param_obj->{ $param }->{ 'exceptions' } )
			 and (
				   grep ( /^$json_obj->{ $param }$/,
						  @{ $param_obj->{ $param }->{ 'exceptions' } } ) )
		  )
		{
			return
			  "The value '$json_obj->{ $param }' is a reserved word of the parameter '$param'.";
		}

		# regex
		if ( ( exists $param_obj->{ $param }->{ 'regex' } ) )
		{
			if ( defined $json_obj->{ $param } )
			{
				# If ARRAY, evaluate all in values.
				if ( ref ( $json_obj->{ $param } ) eq "ARRAY" )
				{
					foreach my $value ( @{ $json_obj->{ $param } } )
					{
						return "The value '$value' is not valid for the parameter '$param'."
						  if ( grep ( !/^$param_obj->{ $param }->{ 'regex' }$/, $value ) );
					}
				}
				else
				{
					return
					  "The value '$json_obj->{ $param }' is not valid for the parameter '$param'."
					  if ( $json_obj->{ $param } !~ /^$param_obj->{ $param }->{ 'regex' }$/ );
				}
			}
		}

		# negated_regex
		if ( ( exists $param_obj->{ $param }->{ 'negated_regex' } ) )
		{
			if ( defined $json_obj->{ $param } )
			{
				# If ARRAY, evaluate all in values.
				if ( ref ( $json_obj->{ $param } ) eq "ARRAY" )
				{
					foreach my $value ( @{ $json_obj->{ $param } } )
					{
						return "The value '$value' is not valid for the parameter '$param'."
						  if ( grep ( /^$param_obj->{ $param }->{ 'regex' }$/, $value ) );
					}
				}
				else
				{
					return
					  "The value '$json_obj->{ $param }' is not valid for the parameter '$param'."
					  if ( $json_obj->{ $param } =~ /$param_obj->{ $param }->{ 'negated_regex' }/ );
				}
			}
		}

		# is_regex
		if ( $param_obj->{ $param }->{ 'is_regex' } eq 'true' )
		{
			if ( defined $json_obj->{ $param } )
			{
				eval { qr/$json_obj->{ $param }/ };
				return "The value of field $param is an invalid regex" if $@;
			}
		}

		if ( exists $param_obj->{ $param }->{ 'function' } )
		{
			my $result =
			  &{ $param_obj->{ $param }->{ 'function' } }( $json_obj->{ $param } );

			return $custom_msg if ( !$result or $result eq 'false' );
		}
	}

	return;
}

=begin nd
Function: checkParamsInterval

	Check parameters when there are required params. The value has to be a integer number

Parameters:
	Interval - String with the expected interval. The low and high limits must be splitted with a comma character ','
	Parameter - Parameter name
	Value - Parameter value

Returns:
	String - It returns a string with the error message or undef on success

=cut

sub checkParamsInterval
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $interval, $param, $value ) = @_;
	my $err_msg;

	if ( $interval =~ /,/ )
	{
		my ( $low_limit, $high_limit ) = split ( ',', $interval );

		my $msg = "";
		if ( defined $low_limit and defined $high_limit and length $high_limit )
		{
			$msg =
			  "'$param' has to be an integer number between '$low_limit' and '$high_limit'";
		}
		elsif ( defined $low_limit )
		{
			$msg =
			  "'$param' has to be an integer number greater than or equal to '$low_limit'";
		}
		elsif ( defined $high_limit )
		{
			$msg =
			  "'$param' has to be an integer number lower than or equal to '$high_limit'";
		}

		$err_msg = $msg
		  if (    ( $value !~ /^\d*$/ )
			   || ( $value > $high_limit and length $high_limit )
			   || ( $value < $low_limit  and length $low_limit ) );
	}
	else
	{
		die "Expected a interval string, got: $interval";
	}

	return $err_msg;
}

=begin nd
Function: checkParamsInvalid

	Check if some of the sent parameters is invalid for the current API call

Parameters:
	Receive Parameters - It is the list of sent parameters in the API call
	Expected parameters - It is the list of expected parameters for a API call

Returns:
	String - It returns a string with the error message or undef on success

=cut

sub checkParamsInvalid
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $rec_keys, $expect_params ) = @_;
	my $err_msg;
	my @non_valid;

	foreach my $param ( @{ $rec_keys } )
	{
		push @non_valid, "'$param'" if ( !grep ( /^$param$/, @{ $expect_params } ) );
	}

	if ( @non_valid )
	{
		$err_msg = &putArrayAsText( \@non_valid,
			"The parameter<sp>s</sp> <pl> <bs>is<|>are</bp> not correct for this call. Please, try with: '"
			  . join ( "', '", @{ $expect_params } )
			  . "'" );
	}

	return $err_msg;
}

=begin nd
Function: checkParamsRequired

	Check if all the mandatory parameters has been sent in the current API call

Parameters:
	Receive Parameters - It is the list of sent parameters in the API call
	Expected parameters - It is the list of expected parameters for a API call
	Model - It is the struct with all allowed parameters and its possible values and options

Returns:
	String - It returns a string with the error message or undef on success

=cut

sub checkParamsRequired
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $rec_keys, $expect_params, $param_obj ) = @_;
	my @miss_params;
	my $err_msg;

	foreach my $param ( @{ $expect_params } )
	{
		next if ( !exists $param_obj->{ $param }->{ 'required' } );

		if ( $param_obj->{ $param }->{ 'required' } eq 'true' )
		{
			push @miss_params, "'$param'"
			  if ( !grep ( /^$param$/, @{ $rec_keys } ) );
		}
	}

	if ( @miss_params )
	{
		$err_msg = &putArrayAsText( \@miss_params,
					   "The required parameter<sp>s</sp> <pl> <bs>is<|>are</bp> missing." );
	}
	return $err_msg;
}

=begin nd
Function: httpResponseHelp

	This function sends a response to client with the expected input parameters model.

	This function returns a 400 HTTP error code

Parameters:
	Model - It is the struct with all allowed parameters and its possible values and options
	Description - Descriptive message about the zapi call

Returns:
	None - .

=cut

sub httpResponseHelp
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $param_obj  = shift;
	my $desc       = shift;
	my $resp_param = [];

	# build the output
	foreach my $p ( keys %{ $param_obj } )
	{
		my $param->{ name } = $p;
		if ( exists $param_obj->{ $p }->{ valid_format } )
		{
			$param->{ format } = $param_obj->{ $p }->{ valid_format };
		}
		if ( exists $param_obj->{ $p }->{ values } )
		{
			$param->{ possible_values } = $param_obj->{ $p }->{ values };
		}
		if ( exists $param_obj->{ $p }->{ interval } )
		{
			my ( $ll, $hl ) = split ( ',', $param_obj->{ $p }->{ interval } );
			$ll = '-' if ( !defined $ll );
			$hl = '-' if ( !defined $hl );
			$param->{ interval } = "Expects a value between '$ll' and '$hl'.";
		}
		if ( exists $param_obj->{ $p }->{ non_blank }
			 and $param_obj->{ $p }->{ non_blank } eq 'true' )
		{
			push @{ $param->{ options } }, "non_blank";
		}
		if ( exists $param_obj->{ $p }->{ required }
			 and $param_obj->{ $p }->{ required } eq 'true' )
		{
			push @{ $param->{ options } }, "required";
		}
		if ( exists $param_obj->{ $p }->{ format_msg } )
		{
			$param->{ description } = $param_obj->{ $p }->{ format_msg };
		}
		if ( exists $param_obj->{ $p }->{ ref } )
		{
			$param->{ ref } = $param_obj->{ $p }->{ ref };
		}

		push @{ $resp_param }, $param;
	}

	my $msg  = "No parameter has been sent. Please, try with:";
	my $body = {

		message => $msg,
		params  => $resp_param,
	};
	$body->{ description } = $desc if ( defined $desc );

	return &httpResponse( { code => 400, body => $body } );
}

=begin nd
Function: putArrayAsText

	This funcion receives a text string and a list of values and it generates a
	text with the values.

	It uses a delimited to modify the text string passed as argument:
	put list - <pl>
	select plural - <sp>text</sp>
	select single - <ss>text</ss>
	select between single or plural - <bs>text_single<|>text_plural</bp>

	Examples:
		putArrayAsText ( ["password", "user", "key"], "The possible value<sp>s</sp> <sp>are</sp>: <pl>")
			return: ""
		putArrayAsText ( ["", "", ""], "The values are")
			return: ""


Parameters:
	Parameters - List of parameters to add to the string message
	Text string - Text

Returns:
	String - Return a message adjust to the number of parameters passed

=cut

sub putArrayAsText
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $array_ref = shift;
	my $msg       = shift;
	my @array     = @{ $array_ref };

	# one element
	if ( scalar @array eq 1 )
	{
		# save single tags
		$msg =~ s/<\/?ss>//g;

		# remove plural text
		#~ $msg =~ s/<sp>.+<\/?sp>// while ( $msg =~ /<sp>/ );
		$msg =~ s/<sp>.+<\/?sp>//g;

		# select between plural and single text
		#~ $msg =~ s/<bs>(.+)<|>.+<\/bp>/$1/ while ( $msg =~ /<|>/ );
		$msg =~ s/<bs>(.+)<\|>.+<\/bp>/$1/g;

		# put list
		$msg =~ s/<pl>/$array[0]/;
	}

	# more than one element
	else
	{
		# save plual tags
		$msg =~ s/<\/?sp>//g;

		# remove single text
		#~ $msg =~ s/<ss>.+<\/?ss>// while ( $msg =~ /<ss>/ );
		$msg =~ s/<ss>.+<\/?ss>//g;

		# select between plural and single text
		#~ $msg =~ s/<bs>.+<|>(.+)<\/bp>/$1/ while ( $msg =~ /<|>/ );
		$msg =~ s/<bs>.+<\|>(.+)<\/bp>/$1/g;

		my $lastItem = pop @array;
		my $list = join ( ", ", @array );
		$list .= " and $lastItem";

		# put list
		$msg =~ s/<pl>/$list/;
	}

	return $msg;
}

1;
