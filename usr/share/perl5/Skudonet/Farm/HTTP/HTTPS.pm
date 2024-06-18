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
Function: getFarmCertificate

	Return the certificate applied to the farm

Parameters:
	farmname - Farm name

Returns:
	scalar - Return the certificate file, or -1 on failure.

FIXME:
	If are there more than one certificate, only return the last one

=cut

sub getFarmCertificate    # ($farm_name)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name ) = @_;

	my $output = -1;

	my $farm_filename = &getFarmFile( $farm_name );
	open my $fd, '<', "$configdir/$farm_filename";
	my @content = <$fd>;
	close $fd;

	foreach my $line ( @content )
	{
		if ( $line =~ /Cert/ && $line !~ /\#.*Cert/ )
		{
			my @partline = split ( '\"', $line );
			@partline = split ( "\/", $partline[1] );
			my $lfile = @partline;
			$output = $partline[$lfile - 1];
		}
	}

	return $output;
}

=begin nd
Function: setFarmCertificate

	Configure a certificate for a HTTP farm

Parameters:
	certificate - certificate file name
	farmname - Farm name

Returns:
	Integer - Error code: 0 on success, or -1 on failure.

FIXME:
	There is other function for this action: setFarmCertificateSNI

=cut

sub setFarmCertificate    # ($cfile,$farm_name)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $cfile, $farm_name ) = @_;

	require Tie::File;
	require Skudonet::Lock;
	require Skudonet::Farm::HTTP::Config;

	my $farm_filename = &getFarmFile( $farm_name );
	my $lock_file     = &getLockFile( $farm_name );
	my $lock_fh       = &openlock( $lock_file, 'w' );
	my $output        = -1;

	my $certdir = &getGlobalConfiguration( 'certdir' );

	&zenlog( "Setting 'Certificate $cfile' for $farm_name farm https",
			 "info", "LSLB" );

	require Skudonet::Certificate;
	my $error = &checkCertPEMValid( "$certdir/$cfile" );
	if ( $error->{ code } )
	{
		&zenlog( "'Certificate $cfile' for $farm_name farm https is not valid",
				 "error", "LSLB" );
		return $output;
	}
	tie my @array, 'Tie::File', "$configdir/$farm_filename";
	for ( @array )
	{
		if ( $_ =~ /Cert "/ )
		{
			s/.*Cert\ .*/\tCert\ \"$certdir\/$cfile\"/g;
			$output = $?;
		}
	}
	untie @array;
	close $lock_fh;

	return $output;
}

=begin nd
Function: setFarmCipherList

	Set Farm Ciphers value

Parameters:
	farmname - Farm name
	ciphers - The options are: cipherglobal, cipherpci, cipherssloffloading or ciphercustom
	cipherc - Cipher custom, this field is used when ciphers is ciphercustom

Returns:
	Integer - return 0 on success or -1 on failure
=cut

sub setFarmCipherList    # ($farm_name,$ciphers,$cipherc)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	# assign first/second/third argument or take global value
	my $farm_name = shift;
	my $ciphers   = shift;
	my $cipherc   = shift;

	require Tie::File;
	require Skudonet::Lock;
	require Skudonet::Farm::HTTP::Config;

	my $farm_filename = &getFarmFile( $farm_name );
	my $lock_file     = &getLockFile( $farm_name );
	my $lock_fh       = &openlock( $lock_file, 'w' );
	my $output        = -1;

	tie my @array, 'Tie::File', "$configdir/$farm_filename";

	for my $line ( @array )
	{
		# takes the first Ciphers line only
		next if ( $line !~ /Ciphers/ );

		if ( $ciphers eq "cipherglobal" )
		{
			$line =~ s/#//g;
			$line   = "\tCiphers \"ALL\"";
			$output = 0;
		}
		elsif ( $ciphers eq "cipherpci" )
		{
			my $cipher_pci = &getGlobalConfiguration( 'cipher_pci' );
			$line =~ s/#//g;
			$line   = "\tCiphers \"$cipher_pci\"";
			$output = 0;
		}
		elsif ( $ciphers eq "ciphercustom" )
		{
			$cipherc = 'DEFAULT' if not defined $cipherc;
			$line =~ s/#//g;
			$line   = "\tCiphers \"$cipherc\"";
			$output = 0;
		}
		elsif ( $ciphers eq "cipherssloffloading" )
		{
			my $cipher = &getGlobalConfiguration( 'cipher_ssloffloading' );
			$line   = "\tCiphers \"$cipher\"";
			$output = 0;
		}

		# default cipher
		else
		{
			$line =~ s/#//g;
			$line   = "\tCiphers \"ALL\"";
			$output = 0;
		}

		last;
	}

	untie @array;
	close $lock_fh;

	return $output;
}

=begin nd
Function: getFarmCipherList

	Get Cipher value defined in l7 proxy configuration file

Parameters:
	farmname - Farm name

Returns:
	scalar - return a string with cipher value or -1 on failure
=cut

sub getFarmCipherList    # ($farm_name)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farm_name = shift;
	my $output    = -1;

	my $farm_filename = &getFarmFile( $farm_name );

	open my $fd, '<', "$configdir/$farm_filename";
	my @content = <$fd>;
	close $fd;

	foreach my $line ( @content )
	{
		next if ( $line !~ /Ciphers/ );

		$output = ( split ( '\"', $line ) )[1];

		last;
	}

	return $output;
}

=begin nd
Function: getFarmCipherSet

	Get Ciphers value defined in l7 proxy configuration file. Possible values are:
		cipherglobal, cipherpci, cipherssloffloading or ciphercustom.

Parameters:
	farmname - Farm name

Returns:
	scalar - return a string with cipher set (ciphers) or -1 on failure

=cut

sub getFarmCipherSet    # ($farm_name)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $farm_name = shift;

	my $output = -1;

	my $cipher_list = &getFarmCipherList( $farm_name );

	if ( $cipher_list eq 'ALL' )
	{
		$output = "cipherglobal";
	}
	elsif ( $cipher_list eq &getGlobalConfiguration( 'cipher_pci' ) )
	{
		$output = "cipherpci";
	}
	else
	{
		$output = "ciphercustom";
	}

	return $output;
}

=begin nd
Function: getHTTPFarmDisableSSL

	Get if a security protocol version is enabled or disabled in a HTTPS farm

Parameters:
	farmname - Farm name
	protocol - SSL or TLS protocol get status (disabled or enabled)

Returns:
	Integer - 1 on disabled, 0 on enabled or -1 on failure
=cut

sub getHTTPFarmDisableSSL    # ($farm_name, $protocol)
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $protocol ) = @_;

	my $farm_filename = &getFarmFile( $farm_name );
	my $output        = -1;

	open my $fd, '<', "$configdir\/$farm_filename" or return $output;
	$output = 0;    # if the directive is not in config file, it is disabled
	my @file = <$fd>;
	close $fd;

	foreach my $line ( @file )
	{
		if ( $line =~ /^\tDisable $protocol$/ )
		{
			$output = 1;
			last;
		}
	}

	return $output;
}

=begin nd
Function: setHTTPFarmDisableSSL

	Enable or disable security protocols for a HTTPS farm

Parameters:
	farmname - Farm name
	protocol - Scalar or hash ref containing SSL or TLS protocols to disable/enable: SSLv2|SSLv3|TLSv1|TLSv1_1|TLSv1_2|TLSv1_3
	action - The available actions are: 1 to disable or 0 to enable. Not used when parameter protocol is a hash ref containing the action.

Returns:
	Integer - Error code: 0 on success or -1 on failure
=cut

sub setHTTPFarmDisableSSL    # ($farm_name, $protocol, $action )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farm_name, $protocol, $action ) = @_;

	require Tie::File;
	require Skudonet::Lock;
	require Skudonet::Farm::HTTP::Config;

	my $farm_filename = &getFarmFile( $farm_name );
	my $lock_file     = &getLockFile( $farm_name );
	my $lock_fh       = &openlock( $lock_file, 'w' );
	my $output        = -1;

	tie my @file, 'Tie::File', "$configdir/$farm_filename";

	my @lines_removed;
	if ( ref ( $protocol ) eq 'HASH' )
	{
		my $it = -1;
		foreach my $line ( @file )
		{
			$it = $it + 1;
			if ( $line =~ /Ciphers\ .*/ )
			{
				foreach my $param ( keys %$protocol )
				{
					if ( $protocol->{ $param } == 1 )
					{
						$line = "$line\n\tDisable $param";
						delete $protocol->{ $param };
					}
				}
			}
			elsif ( $line =~ /^\tDisable (TLSv1(_[1-3])*)$/ )
			{
				if ( exists $protocol->{ $1 } and $protocol->{ $1 } == 0 )
				{
					push ( @lines_removed, $it );
				}
			}
			elsif ( $line =~ /^\tService "*"$/ )
			{
				last;
			}
		}

		my $index = 0;
		foreach my $offset ( @lines_removed )
		{
			$offset = $offset - $index;
			splice ( @file, $offset, 1 );
			$index++;
		}

		$output = 0;
	}
	else
	{
		if ( $action == 1 )
		{
			foreach my $line ( @file )
			{
				if ( $line =~ /Ciphers\ .*/ )
				{
					$line = "$line\n\tDisable $protocol";
					last;
				}
			}
			$output = 0;
		}
		else
		{
			my $it = -1;
			foreach my $line ( @file )
			{
				$it = $it + 1;
				last if ( $line =~ /Disable $protocol$/ );
			}

			# Remove line only if it is found (we haven't arrive at last line).
			splice ( @file, $it, 1 ) if ( ( $it + 1 ) != scalar @file );
			$output = 0;
		}
	}

	untie @file;
	close $lock_fh;

	return $output;
}

=begin nd
Function: setHTTPFarmDisableTLS

	Decides what TLS protocols need to be disabled or enabled for an HTTPS farm

Parameters:
	farmname - Farm name
	disable_tls - hash containing TLS versions to enable (0) or disable (1):
		    - $disable->{ TLSv1_3 } : 0/1
		    - $disable->{ TLSv1_2 } : 0/1
		    - $disable->{ TLSv1_1 } : 0/1
		    - $disable->{ TLSv1 } : 0/1

Returns:
	Hash - error-ref->{ code }: 0 on success, 1 on failure when writing config file, 2 on failure due to wrong TLS protocols config
	     - error_ref->{ msg }: error message
=cut

sub setHTTPFarmDisableTLS    # ($farm_name, $disable_tls )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $farmname, $disable_tls ) = @_;

	my $tls_status->{ TLSv1_3 } = &getHTTPFarmDisableSSL( $farmname, "TLSv1_3" );
	$tls_status->{ TLSv1_2 } = &getHTTPFarmDisableSSL( $farmname, "TLSv1_2" );
	$tls_status->{ TLSv1_1 } = &getHTTPFarmDisableSSL( $farmname, "TLSv1_1" );
	$tls_status->{ TLSv1 }   = &getHTTPFarmDisableSSL( $farmname, "TLSv1" );

	my $error_ref->{ code } = 0;
	if ( exists $disable_tls->{ TLSv1_3 } )
	{
		if ( $tls_status->{ TLSv1_3 } != $disable_tls->{ TLSv1_3 } )
		{
			if ( $disable_tls->{ TLSv1_3 } == 1 and $tls_status->{ TLSv1_2 } == 1 )
			{
				if ( not exists $disable_tls->{ TLSv1_2 } or $disable_tls->{ TLSv1_2 } == 1 )
				{
					my $msg = "Cannot disable TLSv1_3 while TLSv1_2 is disabled.";
					$error_ref->{ code } = 2;
					$error_ref->{ msg }  = $msg;
					return $error_ref;
				}
			}
			$tls_status->{ TLSv1_3 } = $disable_tls->{ TLSv1_3 };
		}
		else
		{
			delete $disable_tls->{ TLSv1_3 };
		}
	}

	if ( exists $disable_tls->{ TLSv1_2 } )
	{
		if ( $tls_status->{ TLSv1_2 } != $disable_tls->{ TLSv1_2 } )
		{
			if ( $disable_tls->{ TLSv1_2 } == 1 )
			{
				if ( $tls_status->{ TLSv1_3 } == 1 )
				{
					my $msg = "Cannot disable TLSv1_2 while TLSv1_3 is disabled.";
					$error_ref->{ code } = 2;
					$error_ref->{ msg }  = $msg;
					return $error_ref;
				}
				else
				{
					$disable_tls->{ TLSv1_1 } = 1 if $tls_status->{ TLSv1_1 } == 0;
					$disable_tls->{ TLSv1 }   = 1 if $tls_status->{ TLSv1 } == 0;

				}
			}
			$tls_status->{ TLSv1_2 } = $disable_tls->{ TLSv1_2 };
		}
		else
		{
			delete $disable_tls->{ TLSv1_2 };
		}
	}

	if ( exists $disable_tls->{ TLSv1_1 } )
	{
		if ( $tls_status->{ TLSv1_1 } != $disable_tls->{ TLSv1_1 } )
		{
			if ( $disable_tls->{ TLSv1_1 } == 1 )
			{
				$disable_tls->{ TLSv1 } = 1 if $tls_status->{ TLSv1 } == 0;
			}
			else
			{
				if ( $tls_status->{ TLSv1_2 } == 1 )
				{
					my $msg = "Cannot enable TLSv1_1 while TLSv1_2 is disabled.";
					$error_ref->{ code } = 2;
					$error_ref->{ msg }  = $msg;
					return $error_ref;
				}
			}
			$tls_status->{ TLSv1_1 } = $disable_tls->{ TLSv1_1 };
		}
		else
		{
			delete $disable_tls->{ TLSv1_1 };
		}
	}

	if ( exists $disable_tls->{ TLSv1 } )
	{
		if ( $tls_status->{ TLSv1 } != $disable_tls->{ TLSv1 } )
		{
			if ( $disable_tls->{ TLSv1 } == 0 )
			{
				if ( $tls_status->{ TLSv1_1 } == 1 )
				{
					my $msg = "Cannot enable TLSv1 while TLSv1_1 is disabled.";
					$error_ref->{ code } = 2;
					$error_ref->{ msg }  = $msg;
					return $error_ref;
				}
			}
		}
		else
		{
			delete $disable_tls->{ TLSv1 };
		}
	}

	if ( %$disable_tls )
	{
		if ( &setHTTPFarmDisableSSL( $farmname, $disable_tls ) == -1 )
		{
			my $msg = "Some errors happened trying to modify TLS.";
			$error_ref->{ code } = 1;
			$error_ref->{ msg }  = $msg;
			return $error_ref;
		}
	}
	return $error_ref;
}

1;

