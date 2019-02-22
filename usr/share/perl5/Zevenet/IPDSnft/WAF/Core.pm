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

my $configdir   = &getGlobalConfiguration( 'configdir' );
my $wafDir      = $configdir . "/ipds/waf";
my $wafSetDir   = $configdir . "/ipds/waf/sets";
my $deleted_reg = $configdir . "/ipds/waf/delreg";

sub getWAFDir
{
	return $wafDir;
}

=begin nd
Function: getWAFDelRegisterFile

	Returns the directory for the delete registers

Parameters:
	none - .

Returns:
	String - The path of the delete register directory

=cut

sub getWAFDelRegisterDir
{
	return $deleted_reg;
}

=begin nd
Function: getWAFDelRegisterFile

	Returns the path of the delete register for a set.

Parameters:
	Set - Set name

Returns:
	String - The path of the file or undef on failure.

=cut

sub getWAFDelRegisterFile
{
	my $set = shift;
	return "$deleted_reg/${set}.conf";
}

=begin nd
Function: getWAFSetDir

	It returns the WAF configruation directory.

Parameters:
	None - .

Returns:
	String - It is the path.

=cut

sub getWAFSetDir
{
	return $wafSetDir;
}

=begin nd
Function: getWAFSetFile

	It returns the configuration file for a set.

Parameters:
	Set - It is the set name.

Returns:
	String - It is the path.

=cut

sub getWAFSetFile
{
	my $set = shift;
	return "$wafSetDir/${set}.conf";
}

=begin nd
Function: getWAFRulesStruct

	It returns a struct with all parameters a WAF rule. It returns a different struct for rules of type "action"
	and rules of type "match_action".

Parameters:
	Type - It is the struct requiered. The possible values are "action" or "match_action".

Returns:
	Hash ref - It is a WAF rule object. The values are:
				'type'             => '',		# type of rule
				'id'               => '',       # position in set file
				'rule_id'          => '',       # id of the rule
				'description'      => '',		# desciption message
				'tag'              => [],		# tags to classify an attack
				'version'          => '',		# version of modsecurity necessary for the rule
				'maturity'         => '',		# madurity of the rule
				'severity'         => '',		# severtiy of the rule
				'accuracy'         => '',		# accuracy level
				'revision'         => '',		# revision of the rule
				'phase'            => '',		# phase, when the rule will be executed
				'transformations'  => [],		# transformations for the variables before than apply the
				'multi_match'      => 'false',	# apply a match for each transformation
				'capture'          => 'false',	# capture data from a regular expresion
				'action'           => '',		# action to apply if a rule matches
				'http_code'        => '',		# http response ccode for denies or redirect actions
				'modify_directive' => [],       # parameter 'ctl' in secrule
				'execute'          => '',		# execute LUA script if the rule matches
				'no_log'           => 'false',	# force no logging
				'log'              => 'false',	# force logging
				'audit_log'        => 'false',	# force audit logging
				'no_audit_log'     => 'false',	# force no audit logging
				'log_data'         => '',		# log a variable or a chunk of message
				'init_colection'   => [],		# initializate a colection
				'set_uid'          => '',		# set a uid
				'set_sid'          => '',		# set a sid
				'set_variable'     => [],		# set or initializate variables
				'expire_var'       => [],		# expire set valiables
				'chain'            => [],		# list of additional rules to match
				'skip'             => '',		# skip a number of rules if the current rule match
				'skip_after'       => '',		# skip until find a rule id or mark if the current rule match
				'modified'         => 'no|yes|refresh',		# it is used to detect if a rule has been modified by a user in the migration process. It is used to not to lost any parameter when a rule it is built by the helper

	The rules of type "match_action" add the parameters:
				'operating',				# valor to apply with the operator
				'operator',					# operation used to look for in a variable
				'variables'					# side where search a match

=cut

sub getWAFRulesStruct
{
	my $type = shift;
	my $out = {
		'type'             => $type,
		'id'               => '',        # position in set file
		'rule_id'          => '',        # id of the rule
		'description'      => '',
		'tag'              => [],
		'version'          => '',
		'maturity'         => '',
		'severity'         => '',
		'accuracy'         => '',
		'revision'         => '',
		'phase'            => '',
		'transformations'  => [],
		'multi_match'      => 'false',
		'capture'          => 'false',
		'action'           => '',
		'http_code'        => '',
		'modify_directive' => [],        # parameter 'ctl' in secrule
		'execute'          => '',
		'no_log'           => 'false',
		'log'              => 'false',
		'audit_log'        => 'false',
		'no_audit_log'     => 'false',
		'log_data'         => '',
		'init_colection'   => [],
		'set_uid'          => '',
		'set_sid'          => '',
		'set_variable'     => [],
		'expire_var'       => [],
		'chain'            => [],
		'skip'             => '',
		'skip_after'       => '',
		'modifed'          => 'no'
		, # shows if the rule has been modified by the user. it is used to not overwrite modified rules
	};

	if ( $type eq 'match_action' )
	{
		$out->{ 'operating' } = '';
		$out->{ 'operator' }  = '';
		$out->{ 'variables' } = [];
	}

	return $out;
}

=begin nd
Function: getWAFSetStructConf

	It returns a object with the common configuration for a WAF set.

Parameters:
	none - .

Returns:
	Hash ref - It is a object with the configuration.

	The possible keys and values are:
		audit: on, off or RelevantOnly;
		process_request_body: true or false;
		process_response_body: true or false;
		request_body_limit: a interger;
		status: on, off, DetectionOnly;
		disable_rules: it is an array of integers, each integer is a rule id;
		default_action: pass, allow, deny or redirect:url;
		default_log: true, false or blank;
		default_phase: 1-5;

=cut

sub getWAFSetStructConf
{
	return {
			 audit                 => 'false',    #SecAuditEngine: on|off|RelevantOnly
			 process_request_body  => 'false',    # SecRequestBodyAccess on|off
			 process_response_body => 'false',    # SecResponseBodyAccess on|off
			 request_body_limit    => '',         # SecRequestBodyNoFilesLimit SIZE
			 status                => 'false',    # SecRuleEngine on|off|DetectionOnly
			 disable_rules         => [],         # SecRuleRemoveById
			 default_action        => 'allow',
			 default_log           => '',
			 default_phase         => '1',
	};
}

=begin nd
Function: listWAFSet

	It returns all existing WAF sets in the system.

Parameters:
	none - .

Returns:
	Array - It is a list of set names.

=cut

sub listWAFSet
{
	my @listSet = ();

	opendir ( my $fd, $wafSetDir ) or return @listSet;
	@listSet = readdir ( $fd );
	@listSet = grep ( !/^\./, @listSet );
	closedir $fd;
	@listSet = grep ( s/\.conf$//, @listSet );

	return @listSet;
}

=begin nd
Function: existWAFSet

	It checks if a WAF set already exists in the system.

Parameters:
	Set - It is the set name.

Returns:
	Integer - It returns 1 if the set already exists or 0 if it is not exist

=cut

sub existWAFSet
{
	my $set = shift;
	return ( grep ( /^$set$/, &listWAFSet() ) ) ? 1 : 0;
}

=begin nd
Function: getWAFSetByRuleId

	It returns the set name where a WAF rule is.

Parameters:
	Rule id - It is the rule id.

Returns:
	String - It is the set name

=cut

sub getWAFSetByRuleId
{
	my $id  = shift;
	my $set = "";
	my $dir = &getWAFSetDir();

	opendir ( my $fd, $dir );

	foreach my $file ( readdir ( $fd ) )
	{
		next if ( $file =~ /^\./ );

		my $fh = &openlock( "$dir/$file", 'r' );
		my $find = grep ( /id:$id\b/, <$fh> );
		close $fh;

		if ( $find ) { $set = $file; last; }
	}

	closedir ( $fd );
	$set =~ s/\..*$//g;
	return $set;
}

=begin nd
Function: existWAFRuleId

	It checks if a WAF rule already exists in the system.

Parameters:
	Rule id - It is the rule id.

Returns:
	Integer - It returns 1 if the rule already exists or 0 if it is not exist

=cut

sub existWAFRuleId
{
	my $id = shift;
	return &getWAFSetByRuleId( $id ) ? 1 : 0;
}

=begin nd
Function: listWAFByFarm

	List all WAF sets that are applied to a farm.

Parameters:
	Farm - It is the farm id.

Returns:
	Array - It is a list with the set names.

=cut

sub listWAFByFarm
{
	my $farm  = shift;
	my @rules = ();

	require Zevenet::Farm::Core;
	require Zevenet::Lock;

	my $configdir = &getGlobalConfiguration( 'configdir' );
	my $farm_file = &getFarmFile( $farm );

	my $fh = &openlock( "$configdir/$farm_file", 'r' );
	my @rules = grep ( s/^WafRules\s+\".+\/([^\/]+).conf\".*$/$1/, <$fh> );
	chomp @rules;
	close $fh;

	return @rules;
}

=begin nd
Function: listWAFBySet

	It list all farms where a WAF set is applied.

Parameters:
	Set - It is the set name.

Returns:
	String - It is a list with farm names.

=cut

sub listWAFBySet
{
	my $set   = shift;
	my @farms = ();
	my $farm_file;
	my $fh;
	my $find;

	require Zevenet::Farm::Core;
	require Zevenet::Lock;

	my $confdir   = &getGlobalConfiguration( 'configdir' );
	my $set_file  = &getWAFSetFile( $set );
	my @httpfarms = &getFarmsByType( 'http' );
	push @httpfarms, &getFarmsByType( 'https' );

	foreach my $farm ( @httpfarms )
	{
		$farm_file = &getFarmFile( $farm );
		$fh = &openlock( "$confdir/$farm_file", 'r' );

		$find = grep ( /WafRules\s+"$set_file"/, <$fh> );
		close $fh;

		push @farms, $farm if $find;
	}

	return @farms;
}

1;
