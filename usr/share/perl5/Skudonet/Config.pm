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

use v5.14;
use strict;

use Skudonet::Log;

=begin nd
Function: getGlobalConfiguration

	Get the value of a configuration variable. The global.conf is parsed only the first time

Parameters:
	parameter - Name of the global configuration variable. Optional.
	Force_relad - This parameter is a flag that force a reload of the global.conf structure, useful to reload the struct when it has been modified. Optional

Returns:
	scalar - Value of the configuration variable when a variable name is passed as an argument.
	scalar - Hash reference to all global configuration variables when no argument is passed.

See Also:
	Widely used.
=cut

sub getGlobalConfiguration
{
	my $parameter = shift;
	my $force_reload = shift // 0;

	state $global_conf = &parseGlobalConfiguration();
	$global_conf = &parseGlobalConfiguration() if ( $force_reload );

	if ( $parameter )
	{
		if ( defined $global_conf->{ $parameter } )
		{
			return $global_conf->{ $parameter };
		}

# bugfix: it is not returned any message when the 'debug' parameter is not defined in global.conf.
		elsif ( $parameter eq 'debug' )
		{
			return undef;
		}
		else
		{
			&zenlog( "The global configuration parameter '$parameter' has not been found",
					 'warning', 'Configuration' )
			  if ( $parameter ne "debug" );
			return undef;
		}
	}

	return $global_conf;
}

=begin nd
Function: parseGlobalConfiguration

	Parse the global.conf file. It expands the variables too.

Parameters:
	none - .

Returns:
	scalar - Hash reference to all global configuration variables when no argument is passed.

See Also:
	Widely used.
=cut

sub parseGlobalConfiguration
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	my $global_conf_filepath = "/usr/local/skudonet/config/global.conf";
	my $global_conf;

	open ( my $global_conf_file, '<', $global_conf_filepath ) or do
	{
		my $msg = "Could not open $global_conf_filepath: $!";
		&zenlog( $msg, "error", "SYSTEM" );
		die $msg;
	};

	# build globalconf struct
	while ( my $conf_line = <$global_conf_file> )
	{
		# extract variable name and value
		if ( $conf_line =~ /^\s*\$(\w+)\s*=\s*(?:"(.*)"|\'(.*)\');(?:\s*#update)?\s*$/ )
		{
			$global_conf->{ $1 } = $2;
		}
	}
	close $global_conf_file;

	# expand the variables
	my $var;
	my $value;
	foreach my $param ( keys %{ $global_conf } )
	{
		# replace every variable used in the $var_value by its content
		while ( $global_conf->{ $param } =~ /\$(\w+)/ )
		{
			$var = $1;
			$value = $global_conf->{ $var } // '';
			$global_conf->{ $param } =~ s/\$$var/$value/;
		}
	}

	return $global_conf;
}

=begin nd
Function: setGlobalConfiguration

	Set a value to a configuration variable

Parameters:
	param - Configuration variable name.
	value - New value to be set on the configuration variable.

Returns:
	scalar - 0 on success, or -1 if the variable was not found.

Bugs:
	Control file handling errors.

See Also:
	Zapi v3: <set_ntp>
=cut

sub setGlobalConfiguration    # ( parameter, value )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $param, $value ) = @_;

	my $global_conf_file = &getGlobalConfiguration( 'globalcfg' );
	my $output           = -1;

	require Tie::File;
	tie my @global_hf, 'Tie::File', $global_conf_file;

	foreach my $line ( @global_hf )
	{
		if ( $line =~ /^\$$param\s*=/ )
		{
			$line   = "\$$param = \"$value\";";
			$output = 0;
		}
	}
	untie @global_hf;

	# reload global.conf struct
	&getGlobalConfiguration( undef, 1 );

	return $output;
}

=begin nd
Function: setConfigStr2Arr

	Put a list of string parameters as array references

Parameters:
	object - reference to a hash
	parameters - list of parameters to change from string to array
	not_sorted - 0 sorted, 1 not sorted.

Returns:
	hash ref - Object updated

=cut

sub setConfigStr2Arr
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $obj        = shift;
	my $param_list = shift;
	my $not_sorted = shift;

	foreach my $param_name ( @{ $param_list } )
	{
		my @list = ();

		# split parameter if it is not a blank string
		if ( $obj->{ $param_name } )
		{
			if ( $not_sorted )
			{
				@list = split ( ' ', $obj->{ $param_name } );
			}
			else
			{
				@list = sort split ( ' ', $obj->{ $param_name } );
			}
		}
		$obj->{ $param_name } = \@list;
	}

	return $obj;
}

=begin nd
Function: getTiny

	Get a Config::Tiny object from a file name.

Parameters:
	file_path - Path to file.

Returns:
	scalar - reference to Config::Tiny object, or undef on failure.

See Also:

=cut

sub getTiny
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $file_path = shift;

	if ( !-f $file_path )
	{
		open my $fi, '>', $file_path;
		if ( $fi )
		{
			&zenlog( "The file was created $file_path", "info" );
		}
		else
		{
			&zenlog( "Cannot create file $file_path: $!", "error" );
			return;
		}
		close $fi;
	}

	require Config::Tiny;

	# returns object on success or undef on error.
	my $tiny_object = Config::Tiny->read( $file_path );
	if ( not defined $tiny_object )
	{
		&zenlog( "Error reading $file_path", "warning" );
	}
	return $tiny_object;
}

=begin nd
Function: getTinyObj

	Get a Config::Tiny object from a file name.
	This function has 3 behaviors:
	it can returns all parameters from all groups
	or it can returns all parameters from a group
	or it can returns only selected parameters.
	selected parameters can be ignored,undef or error if they do not exists

Parameters:
	file_path - Path to file.
	object - Group to get. Empty means all groups.
	key_ref - Array of parameters to get. Empty means all parameters
	key_action - string define the action. Possible values are "ignored|undef|error".Empty means error.

Returns:
	hash ref - a reference to Config::Tiny object when success, undef on failure.

See Also:

=cut

sub getTinyObj    #( $filepath, $object, $key_ref )
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	my ( $filepath, $object, $key_ref, $key_action ) = @_;
	my $tiny_ref_tmp = &getTiny( $filepath );
	return if ( !defined $tiny_ref_tmp );

	my $tiny_ref;

	if ( !defined $object )
	{
		$tiny_ref = $tiny_ref_tmp;
	}
	else
	{
		if ( !exists $tiny_ref_tmp->{ $object } )
		{
			return;
		}
		else
		{
			if ( !defined $key_ref )
			{
				$tiny_ref = $tiny_ref_tmp->{ $object };
			}
			else
			{
				if ( ref $key_ref eq 'ARRAY' )
				{
					foreach my $param ( @{ $key_ref } )
					{
						if ( defined $tiny_ref_tmp->{ $object }->{ $param } )
						{
							$tiny_ref->{ $param } = $tiny_ref_tmp->{ $object }->{ $param };
						}
						else
						{
							return if ( !defined $key_action or $key_action eq "error" );
							$tiny_ref->{ $param } = undef if ( $key_action eq "undef" );
						}
					}
				}
			}
		}
	}

	return $tiny_ref;

}

=begin nd
Function: setTiny
	Save an struct in a config file. The file is locked before than applying the changes

Parameters:
	path - Tiny conguration file where to apply the change
	tiny_ref - Hash ref to apply the change

Returns:
	Integer -  Error code: 0 on success or other value on failure
=cut

sub setTiny
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $path, $tiny_ref ) = @_;
	unless ( $tiny_ref )
	{
		&zenlog( "Object not defined trying to save it in file $path" );
		return;
	}
	require Skudonet::Lock;
	require Config::Tiny;

	my $lock_file = &getLockFile( $path );
	my $lock_fd = &openlock( $lock_file, 'w' );

	my $fileHandle = &getTiny( $path );

	unless ( $fileHandle )
	{
		&zenlog( "Could not open file $path: $Config::Tiny::errstr" );
		return -1;
	}
	foreach my $object ( %{ $tiny_ref } )
	{
		foreach my $param ( keys %{ $tiny_ref->{ $object } } )
		{
			if ( ref $tiny_ref->{ $object }->{ $param } eq "ARRAY" )
			{
				$fileHandle->{ $object }->{ $param } =
				  join ( ' ', @{ $tiny_ref->{ $object }->{ $param } } );
			}
			else
			{
				$fileHandle->{ $object }->{ $param } = $tiny_ref->{ $object }->{ $param };
			}
		}
	}

	my $success = $fileHandle->write( $path );
	close $lock_fd;
	unlink $lock_file;

	return ( $success ) ? 0 : 1;
}

=begin nd
Function: setTinyObj

	Save a change in a config file. The file is locker before than applying the changes
	This function has 2 behaviors:
	it can receives a hash ref to save a struct
	or it can receive a key and parameter to replace a value

Parameters:
	path - Tiny conguration file where to apply the change
	object - Group to apply the change
	key - parameter to change or struct ref to overwrite.
	value - new value for the parameter or action for struct ref. The possible action values are: "update" to update only existing params , "new" to delete old params and set news ones or empty to add all new params. 
	action - This is a optional parameter. The possible values are: "add" to add
	a item to a list, or "del" to delete a item from a list, or "remove" to delete the key

Returns:
	Integer -  Error code: 0 on success or other value on failure

=cut

sub setTinyObj
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my ( $path, $object, $key, $value, $action ) = @_;

	unless ( $object )
	{
		&zenlog( "Object not defined trying to save it in file $path" );
		return;
	}

	&zenlog( "Modify $object from $path", "debug2" );

	require Skudonet::Lock;
	require Config::Tiny;

	my $lock_file = &getLockFile( $path );
	my $lock_fd = &openlock( $lock_file, 'w' );

	my $fileHandle = &getTiny( $path );

	unless ( $fileHandle )
	{
		&zenlog( "Could not open file $path: $Config::Tiny::errstr" );
		return -1;
	}

	# save all struct
	if ( ref $key )
	{
		if ( $value eq "new" )
		{
			$fileHandle->{ $object } = {};
		}
		foreach my $param ( keys %{ $key } )
		{
			if ( ref $key->{ $param } eq 'ARRAY' )
			{
				$key->{ $param } = join ( ' ', @{ $key->{ $param } } );
			}
			next
			  if (     ( !exists $fileHandle->{ $object }->{ $param } )
				   and ( $value eq "update" ) );

			$fileHandle->{ $object }->{ $param } = $key->{ $param };
		}
	}

	# save a parameter
	else
	{
		if ( 'add' eq $action )
		{
			$fileHandle->{ $object }->{ $key } .= " $value";
		}
		elsif ( 'del' eq $action )
		{
			$fileHandle->{ $object }->{ $key } =~ s/(^| )$value( |$)/ /;
		}
		elsif ( 'remove' eq $action )
		{
			delete $fileHandle->{ $object }->{ $key };
		}
		else
		{
			$fileHandle->{ $object }->{ $key } = $value;
		}
	}

	my $success = $fileHandle->write( $path );
	close $lock_fd;
	unlink $lock_file;

	return ( $success ) ? 0 : 1;
}

=begin nd
Function: delTinyObj

	It deletes a object of a tiny file. The tiny file is locked before than set the configuration

Parameters:
	object - Group name
	path - Tiny file where the object will be deleted

Returns:
	Integer -  Error code: 0 on success or other value on failure

=cut

sub delTinyObj
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $path   = shift;
	my $object = shift;

	&zenlog( "Delete $object from $path", "debug2" );

	require Skudonet::Lock;

	my $lock_file = &getLockFile( $path );
	my $lock_fd = &openlock( $lock_file, 'w' );

	my $fileHandle = Config::Tiny->read( $path );
	delete $fileHandle->{ $object };
	my $error = $fileHandle->write( $path );

	close $lock_fd;
	unlink $lock_file;

	return $error;
}

=begin nd
Function: migrateConfigFiles

	Apply all migrating scripts to skudonet

Parameters:
	none - .

Returns:
	none - .

=cut

sub migrateConfigFiles
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );

	my $MIG_DIR = &getGlobalConfiguration( 'mig_dir' );

	my @listing = `ls $MIG_DIR`;
	foreach my $file ( @listing )
	{
		my @run = `${MIG_DIR}/${file}`;
	}

}

1;

