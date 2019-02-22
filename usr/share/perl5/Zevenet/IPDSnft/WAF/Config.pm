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
use Zevenet::Core;
use Zevenet::Lock;

include 'Zevenet::IPDS::WAF::Core';
include 'Zevenet::IPDS::WAF::Parser';

=begin nd
Function: addWAFDelRegister

	Add a new entry in the delete register.
	The delete register is a register to note the rule has been modified, moved or deleted by the user.
	If a rule is moved or modified it is deleted from the set in the migration process, and it is added a
	new rule with the new configuration.

Parameters:
	Set - Name of the rule
	Raw rule - Array ref. Each item is a line of the rule

Returns:
	Integer - Return 0 on success or another value on failure

=cut

sub addWAFDelRegister
{
	my $set   = shift;
	my $raw   = shift;
	my $err   = 0;
	my $file  = &getWAFDelRegisterFile( $set );
	my $chain = &convertWAFLine( $raw );
	my $fh;

	if ( !-f $file )
	{
		$fh = &openlock( $file, 'w' ) or $err = 1;
	}
	else
	{
		$fh = &openlock( $file, 'a' ) or $err = 1;
	}
	print $fh $chain;
	close $fh;

	&zenlog( "Error registering deleting rule of set $set and rule \"$chain\"",
			 "error", 'waf' )
	  if $err;

	return $err;
}

=begin nd
Function: checkWAFDelRegister

	Serializate the rule and check if a rule is added in the delete register

Parameters:
	Set - Name of the rule
	Raw rule - Array ref. Each item is a line of the rule

Returns:
	Integer - Return 0 if the rule is not in the register or another value if the rule has been found

=cut

sub checkWAFDelRegister
{
	my $set   = shift;
	my $raw   = shift;
	my $flag  = 0;
	my $chain = &convertWAFLine( $raw );
	my $file  = &getWAFDelRegisterFile( $set );
	my $fh    = &openlock( $file, 'r' );
	if ( defined $fh )
	{

		foreach my $line ( <$fh> )
		{
			chomp $line;
			if ( $chain eq $line )
			{
				$flag = 1;
				last;
			}
		}
	}

	return $flag;
}

=begin nd
Function: genWAFRuleId

	Returns a rule ID available

Parameters:
	None - .

Returns:
	Integer - The rule id

=cut

sub genWAFRuleId
{
	my $interval_limit_up   = 99999;
	my $interval_limit_down = 1;
	my $id                  = $interval_limit_down;
	my $fin                 = 0;

	do
	{
		if ( !&existWAFRuleId( $id ) )
		{
			$fin = 1;
		}
		else
		{
			$id++;
		}
	} while ( $id <= $interval_limit_up and !$fin );

	if ( $id > $interval_limit_up )
	{
		$id = 0;
		&zenlog( "The limit of WAF rule id has been alreached", "error", "waf" );
	}

	return $id;
}

=begin nd
Function: setWAFRule

	It replaces a rule inside of a set, using the rule index, by anther one.

Parameters:
	Set - It is the WAF set name.
	Index - It is the rule index to replace.
	Set - It is the rule object to set.

Returns:
	String - It returns a blank string on success or it returns a string with a message for the error.

=cut

sub setWAFRule
{
	my $set      = shift;
	my $id       = shift;
	my $rule_ref = shift;
	my $rule;

	if ( ref $rule_ref ne 'HASH' )
	{
		$rule_ref = &parseWAFRule( $rule_ref );
	}

	# not to check syntax if the rule has chains
	my $set_st = &getWAFSet( $set );

	if ( $rule_ref->{ modified } eq 'no' )
	{
		&addWAFDelRegister( $set, $rule_ref->{ raw } );
	}
	$rule_ref->{ modified } = 'refresh';

	$set_st->{ rules }->[$id] = $rule_ref;
	my $err_msg = &buildWAFSet( $set, $set_st );

	return $err_msg;
}

=begin nd
Function: createWAFRule

	It appends a rule in a set.

Parameters:
	Set - It is the WAF set name.
	Set - It is the rule object to add.

Returns:
	String - It returns a blank string on success or it returns a string with a message for the error.

=cut

sub createWAFRule
{
	my $set      = shift;
	my $rule_ref = shift;
	my $err_msg  = 0;
	my $rule;

	if ( ref $rule_ref ne 'HASH' )
	{
		return "Rule format does not expected";
	}

	$rule_ref->{ rule_id } = &genWAFRuleId()
	  if not $rule_ref->{ rule_id };

	$rule_ref->{ modified } = 'refresh';

	my $set_st = &getWAFSet( $set );
	push @{ $set_st->{ rules } }, $rule_ref;
	my $err_msg = &buildWAFSet( $set, $set_st );

	return $err_msg;
}

=begin nd
Function: setWAFSetRaw

	It adds a batch of rules in a position of a WAF set.

Parameters:
	Set - It is the WAF set name.
	Rules batch - It is an array reference with a list of lines.
	index - It is the index to set the batch of rules. If the index is not defined, the batch will set in the last position.

Returns:
	String - It returns a blank string on success or it returns a string with a message for the error.

=cut

sub setWAFSetRaw
{
	my $set      = shift;
	my $set_raw  = shift;
	my $position = shift
	  ; # optional. if it is not defined, the set is appended else it the rule in the position is replaced
	my $err;

	# parse and get only the rules, not the global conf
	my $set_new_st = &parseWAFBatch( $set_raw );
	return "It has not been found any valid rule" if ( !@{ $set_new_st } );

	# add mark to specify that the rule was modified by the user
	foreach my $ru ( @{ $set_new_st } )
	{
		$ru->{ modified } = 'yes';
	}

	# get set
	my $set_st = &getWAFSet( $set );
	if ( defined $position )
	{
		if ( $set_st->{ rules }->[$position]->{ modified } eq 'no' )
		{
			&addWAFDelRegister( $set, $set_st->{ rules }->[$position]->{ raw } );
		}

		my @tmp_rules = @{ $set_st->{ rules } };
		splice @tmp_rules, $position, 1, @{ $set_new_st };
		$set_st->{ rules } = \@tmp_rules;
	}
	else
	{
		push @{ $set_st->{ rules } }, @{ $set_new_st };
	}
	$err = &buildWAFSet( $set, $set_st );

	return $err;
}

=begin nd
Function: createWAFMark

	It appends a mark in a WAF set.

Parameters:
	Set - It is the WAF set name.
	Mark - It is a string with the the mark.

Returns:
	String - It returns a blank string on success or it returns a string with a message for the error.

=cut

sub createWAFMark
{
	my $set  = shift;
	my $mark = shift;

	my $sentence = "SecMarker $mark";

	return &setWAFSetRaw( $set, [$sentence] );
}

=begin nd
Function: setWAFMark

	It adds a mark in a WAF set.

Parameters:
	Set - It is the WAF set name.
	Mark - It is a string with the the mark.
	index - It is the index to set the mark. If the index is not defined, the mark will set in the last position.

Returns:
	String - It returns a blank string on success or it returns a string with a message for the error.

=cut

sub setWAFMark
{
	my $set  = shift;
	my $id   = shift;
	my $mark = shift;

	my $sentence = "SecMarker $mark";

	return &setWAFSetRaw( $set, [$sentence], $id );
}

=begin nd
Function: copyWAFRule

	It copies a WAF rule by its rule id and it adds it to a set.

Parameters:
	Set - It is the WAF set name.
	rule id - It is the rule id to copy.

Returns:
	String - It returns a blank string on success or it returns a string with a message for the error.

=cut

sub copyWAFRule
{
	my $set = shift;
	my $id  = shift;

	# get rule
	my $rule = &getWAFRuleById( $id );

	# create rule
	$rule->{ rule_id } = &genWAFRuleId();
	my $err = &createWAFRule( $set, $rule );

	return $err;
}

# add a new rule in the end of the set file
sub createWAFSet
{
	my $setName = shift;
	my $err     = 0;

	my $fh = &openlock( &getWAFSetFile( $setName ), 'w' ) or $err = 1;
	close $fh;

	return $err;
}

=begin nd
Function: copyWAFSet

	It gets a set file and it copies in another file, changing the ID of each rule.

Parameters:
	Destine Set - It is the new set name where the set will be copied.
	Origin Set - It is the set name to copy.

Returns:
	Integer - It returns 0 on success or another value on failure.

=cut

sub copyWAFSet
{
	my $dstSet    = shift;
	my $originSet = shift;

	my $err = &copyLock( &getWAFSetFile( $originSet ), &getWAFSetFile( $dstSet ) );

	my $set_st = &getWAFSet( $dstSet );
	foreach my $rule ( @{ $set_st->{ rules } } )
	{
		## ?????? cambiar el id mediante expresion regular
		$rule->{ id } = &genWAFRuleId();
	}
	&buildWAFSet( $dstSet, $set_st );

	return $err;
}

=begin nd
Function: getWAFRuleById

	It looks for a rule in all the sets and it retuns it.
	This function is useful to copy rules.

Parameters:
	Id rule - It is the rule id.

Returns:
	Hash ref - It is the rule object.

=cut

sub getWAFRuleById
{
	my $id = shift;
	my $rule;

	# get set,
	my $setRule = &getWAFSetByRuleId( $id );

	# parse the set
	my $setParsed = &getWAFSet( $setRule );

	# get rule
	foreach my $ru ( @{ $setParsed->{ rules } } )
	{
		if ( $ru->{ rule_id } eq $id )
		{
			$rule = $ru;
			last;
		}
	}

	return $rule;
}

=begin nd
Function: deleteWAFRule

	It deletes a SecLang directive from a set file. It can delete a chained rule if the chain index is sent.

Parameters:
	Set - It is the name of the set.
	Rule index - It is the rule index in the set file.
	Chain index - It is the index of a chained rule in a rule.

Returns:
	Integer - It returns 0 on success or another value on failure.

=cut

sub deleteWAFRule
{
	my $set         = shift;
	my $rule_index  = shift;
	my $chain_index = shift;    # if exists, the chain index will be deleted
	my $err         = 0;

	my $set_st = &getWAFSet( $set );

	# delete a rule
	if ( !defined $chain_index )
	{
		return 1
		  if &addWAFDelRegister( $set, $set_st->{ rules }->[$rule_index]->{ raw } );
		return 1
		  if ( !splice ( @{ $set_st->{ rules } }, $rule_index, 1 ) )
		  ;                     # error if any item is deleted
	}

	# delete a chain from a rule
	else
	{
		my $rule_ref = $set_st->{ rules }->[$rule_index];
		if ( $rule_ref->{ modified } eq 'no' )
		{
			&addWAFDelRegister( $set, $set_st->{ rules }->{ raw } );
		}
		$rule_ref->{ modified } = 'refresh';

		return 1
		  if ( !splice ( @{ $rule_ref->{ chain } }, $chain_index, 1 ) )
		  ;    # error if any item is deleted
	}

	# save
	$err = &buildWAFSet( $set, $set_st );

	return $err;
}

=begin nd
Function: deleteWAFSet

	It deletes a WAF set from the system.

Parameters:
	Set - It is the name of the set.

Returns:
	Integer - It returns 0 on success or another value on failure.

=cut

sub deleteWAFSet
{
	my $set = shift;
	my $err = 0;

	# delete from all farms where is applied and restart them
	foreach my $farm ( &listWAFBySet( $set ) )
	{
		$err = &removeWAFSetFromFarm( $set, $farm );
		return $err if $err;
	}

	$err = unlink &getWAFSetFile( $set );
	unlink &getWAFDelRegisterFile( $set );

	return $err;
}

=begin nd
Function: getWAFRuleLast

	It returns the last rule from a set. It is useful to get the last created rule.

Parameters:
	Set - It is the name of the set.

Returns:
	Hash ref - It is a WAF rule object.

=cut

sub getWAFRuleLast
{
	my $set    = shift;
	my $set_st = &getWAFSet( $set );
	return ( scalar @{ $set_st->{ rules } } ) ? $set_st->{ rules }->[-1] : undef;
}

=begin nd
Function: moveWAFRule

	It moves a rule to another position. It is used the rule index and the desired position.
	If the rule is without modify, add a new entry in the delete register.

Parameters:
	Set - It is the name of the set.
	Rule index - It is index of the rule in the set.
	Position - It is the required position for the rule.

Returns:
	String - Returns a message with a description about the file is bad-formed. It will return a blank string if the file is well-formed.

=cut

sub moveWAFRule
{
	my $set = shift;
	my $id  = shift;
	my $pos = shift;

	require Zevenet::Arrays;

	my $err    = 0;
	my $set_st = &getWAFSet( $set );

	if ( $set_st->{ rules }->[$id]->{ modified } eq 'no' )
	{
		&addWAFDelRegister( $set, $set_st->{ rules }->[$id]->{ raw } );
		$set_st->{ rules }->[$id]->{ modified } = 'yes';
	}

	&moveByIndex( $set_st->{ rules }, $id => $pos );

	# save the change
	$err = &buildWAFSet( $set, $set_st );

	return $err;
}

=begin nd
Function: setWAFSet

	It modifies the configuration of a WAF set.

Parameters:
	Set - It is the name of the set.
	Params - It is a hash ref with the parameters to modify. The possible parameters and theirs values are:
		audit: on, off or RelevantOnly;
		process_request_body: true or false;
		process_response_body: true or false;
		request_body_limit: a interger;
		status: on, off, DetectionOnly;
		disable_rules: it is an array of integers, each integer is a rule id;
		default_action: pass, allow, deny or redirect:url;
		default_log: true, false or blank;
		default_phase: 1-5;

Returns:
	String - Returns a message with a description about the file is bad-formed. It will return a blank string if the file is well-formed.

=cut

sub setWAFSet
{
	my $setname = shift;
	my $params  = shift;

	my $struct = &getWAFSet( $setname );

	foreach my $key ( keys %{ $params } )
	{
		$struct->{ configuration }->{ $key } = $params->{ $key };
	}
	return &buildWAFSet( $setname, $struct );
}

=begin nd
Function: moveWAFSet

	It moves a WAF set in the list of set linked to a farm. The set order is the same
	in which they will be executed.

Parameters:
	Farm - It is farm name.
	Set - It is the name of the set.
	Position - It is the desired position for the set

Returns:
	Integer - It returns 0 on success or another value on failure.

=cut

sub moveWAFSet
{
	my $farm     = shift;
	my $set      = shift;
	my $position = shift;
	my $err      = 0;

	require Zevenet::Farm::Core;

	my $set_file  = &getWAFSetFile( $set );
	my $farm_file = &getFarmFile( $farm );
	my $configdir = &getGlobalConfiguration( 'configdir' );

	# write conf
	my $lock_file = &getLockFile( $farm );
	my $lock_fh   = &openlock( $lock_file, 'w' );
	my $flag_sets = 0;

	require Tie::File;
	tie my @filefarmhttp, 'Tie::File', "$configdir/$farm_file";

	# get line where waf rules begins
	my $waf_ind = -1;
	foreach my $line ( @filefarmhttp )
	{
		$waf_ind++;
		last if ( $line =~ /^WafRules/ );
	}

	# get set id
	my $set_ind   = -1;
	my @sets_list = &listWAFByFarm( $farm );
	foreach my $line ( @sets_list )
	{
		$set_ind++;
		last if ( $line =~ /^$set$/ );
	}

	require Zevenet::Arrays;
	&moveByIndex( \@filefarmhttp, $waf_ind + $set_ind, $waf_ind + $position );

	untie @filefarmhttp;
	close $lock_fh;

	# reload farm
	require Zevenet::Farm::Base;
	if ( &getFarmStatus( $farm ) eq 'up' and !$err )
	{
		include 'Zevenet::IPDS::WAF::Runtime';
		$err = &reloadWAFByFarm( $farm );
	}

	return $err;
}

1;
