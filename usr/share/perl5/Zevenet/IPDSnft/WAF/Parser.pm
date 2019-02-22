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

my $mark_conf_begin = "## begin conf";
my $mark_conf_end   = "## end conf";

my $audit_file = "/var/log/waf_audit.log";

=begin nd
Function: convertWAFLine

	This function concatenates a set of lines in a one line.

Parameters:

	lines - It is an array reference with the parameters of a SecLang directive.

Returns:
	String - String with the SecLang directive.

Output example:
	$VAR = "SecRule REQUEST_METHOD "@streq POST" "id:'9001184',phase:1,t:none,pass,nolog,noauditlog,chain";

=cut

sub convertWAFLine
{
	my $ref_arr = shift;

	my @txt = @{ $ref_arr };

	my $line;
	grep ( s/\\$//g,  @txt );
	grep ( s/^\s*//g, @txt );
	chomp $_ for ( @txt );
	$line = join ( '', @txt );
	return $line;
}

=begin nd
Function: parseWAFRule

	It parses a SecLang directive and it returns an object with all parameters of the directive.

	This function parses the next type of rules:
	* match_action, the SecRule directive
	* action, the SecAction directive
	* mark, the SecMark directive
	* custom, another directive

Parameters:

	Lines - It is an array reference with the parameters of a SecLang directive.

Returns:
	Hash ref - It is a rule parsed. The possible values are shown in the output example.

Output example:
	$VAR1 = {
		'init_colection' => [],
		'set_variable' => [
							'tx.php_injection_score=+%{tx.critical_anomaly_score}',
							'tx.anomaly_score=+%{tx.critical_anomaly_score}',
							'tx.%{rule.id}-OWASP_CRS/WEB_ATTACK/PHP_INJECTION-%{matched_var_name}=%{tx.0}'
							],
		'tag' => [
					'testing',
					'Api tests'
				],
		'raw' => 'SecRule REQUEST_URI|REQUEST_BODY "@contains index" "id:100,msg:\'Testing rule\',tag:testing,tag:Api tests,severity:2,phase:2,t:base64Decode,t:escapeSeqDecode,t:urlDecode,multimatch,pass,status:200,log,noauditlog,logdata:match in rule 41,setvar:tx.php_injection_score=+%{tx.critical_anomaly_score},setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-OWASP_CRS/WEB_ATTACK/PHP_INJECTION-%{matched_var_name}=%{tx.0},skip:2,skipAfter:100,exec:/opt/example_script.lua"',
		'no_audit_log' => 'true',
		'skip' => '2',
		'type' => 'match_action',
		'capture' => 'false',
		'set_sid' => '',
		'skip_after' => '100',
		'accuracy' => '',
		'operator' => 'contains',
		'id' => '',
		'action' => 'pass',
		'variables' => [
						'REQUEST_URI',
						'REQUEST_BODY'
						],
		'chain' => [],
		'expire_var' => [],
		'multi_match' => 'true',
		'operating' => 'index',
		'audit_log' => 'false',
		'log' => 'true',
		'no_log' => 'false',
		'http_code' => '200',
		'rule_id' => '100',
		'version' => '',
		'transformations' => [
								'base64Decode',
								'escapeSeqDecode',
								'urlDecode'
							],
		'phase' => '2',
		'log_data' => 'match in rule 41',
		'revision' => '',
		'description' => 'Testing rule',
		'severity' => '2',
		'set_uid' => '',
		'maturity' => '',
		'execute' => '/opt/example_script.lua',
		'modify_directive' => []
	};


=cut

sub parseWAFRule
{
	my $txt          = shift;
	my @nested_rules = @_;      # rest of nested rules
	my $line;
	my $rule;
	my $directive;
	my $act;
	my $raw = "";

	# convert text in a line
	if ( ref $txt eq 'ARRAY' )
	{
		$raw  = $txt;
		$line = &convertWAFLine( $txt );
	}
	else
	{
		$line = $txt;
		$raw  = [$txt];
	}
	$raw->[-1] =~ s/\s*#\s*$//s;    # remove modify tag

	if ( $line =~ /^\s*(Sec\w+)\s+/s )
	{
		$directive = $1;
	}

	my $modified = 'no';
	if ( $line =~ s/\s*#\s*$// )
	{
		$modified = 'yes';
	}

	if ( $directive =~ /(?:SecRule|SecAction)$/ )
	{
		my $type = ( $directive eq 'SecRule' ) ? 'match_action' : 'action';
		$rule = &getWAFRulesStruct( $type );

# example:
#	SecRule REQUEST_METHOD "@streq POST" "id:'9001184',phase:1,t:none,pass,nolog,noauditlog,chain"
#	SecRule REQUEST_FILENAME "@rx /file/ajax/field_asset_[a-z0-9_]+/[ua]nd/0/form-[a-z0-9A-Z_-]+$" chain
# there are 4 mandatory fields: 1:directive 2:variables 3:operating 4:actions

		if ( $directive eq 'SecRule' )
		{
			if ( $line !~ /^\s*SecRule\s+"?([^"]+)"?\s+"?([^"]+)"?\s+"?([^"]+)?"?/s )
			{
				return undef;
			}

			my $var = $1;
			my $val = $2;
			$act = $3;

			if ( $val =~ /^(?<operator>!?\@\w+)?\s+?(?<operating>[^"]+)?$/ )
			{
				$rule->{ operator } = $+{ operator } // "";
				$rule->{ operating } = $+{ operating };
			}

			my @var_sp = split ( '\|', $var );
			$rule->{ variables } = \@var_sp;

			# set not_operator
			if ( $rule->{ operator } )
			{
				$rule->{ operator } =~ s/^(!)?\@//;
				my $not_op = $1 // '';
				$rule->{ operator } = "${not_op}$rule->{ operator }";
				&zenlog( "Not variable found parsing rule: $line ", "debug1", "waf" )
				  if ( !$rule->{ operator } );
			}
		}

		# parsing SecAction
		else
		{
			$act = $line;
			$act =~ s/^\s*SecAction\s+//;
			$act =~ s/^"//;
			$act =~ s/"\s*$//;

			$rule->{ type } = 'action';

			# delete the exclusive parameters of SecRules
			delete $rule->{ operator };
			delete $rule->{ operating };
			delete $rule->{ variables };
		}

		my @options = split ( ',', $act );

		foreach my $param ( @options )
		{
			$param =~ s/^\s*//;
			$param =~ s/\s*$//;

			if ( $param =~ /msg:'?([^']+)'?/ )
			{
				$rule->{ description } = $1;
			}
			elsif ( $param =~ /id:'?([^']+)'?/ )
			{
				$rule->{ rule_id } = $1;
			}
			elsif ( $param =~ /tag:'?([^']+)'?/ )
			{
				push @{ $rule->{ tag } }, $1;
			}
			elsif ( $param =~ /ver:'?([^']+)'?/ )
			{
				$rule->{ version } = $1;
			}
			elsif ( $param =~ /maturity:'?([^']+)'?/ )
			{
				$rule->{ maturity } = $1;
			}
			elsif ( $param =~ /severity:'?([^']+)'?/ )
			{
				$rule->{ severity } = $1;
			}
			elsif ( $param =~ /accuracy:'?([^']+)'?/ )
			{
				$rule->{ accuracy } = $1;
			}
			elsif ( $param =~ /rev:'?([^']+)'?/ )
			{
				$rule->{ revision } = $1;
			}
			elsif ( $param =~ /status:'?([^']+)'?/ )
			{
				$rule->{ http_code } = $1;
			}
			elsif ( $param =~ /phase:'?([^']+)'?/ ) { $rule->{ phase } = $1; }

			# put same format phase
			elsif ( $param =~ /t:'?([^']+)'?/ )
			{
				push @{ $rule->{ transformations } }, $1;
			}
			elsif ( $param =~ /^multimatch$/ )
			{
				$rule->{ multi_match } = "true";
			}
			elsif ( $param =~ /^capture$/ ) { $rule->{ capture } = "true"; }
			elsif ( $param =~ /^(redirect|allow|pass|block|deny)$/ )
			{
				$rule->{ action } = $1;
			}
			elsif ( $param =~ /^nolog$/ )    { $rule->{ no_log }    = "true"; }
			elsif ( $param =~ /^log$/ )      { $rule->{ log }       = "true"; }
			elsif ( $param =~ /^auditlog$/ ) { $rule->{ audit_log } = "true"; }
			elsif ( $param =~ /^noauditlog$/ )
			{
				$rule->{ no_audit_log } = "true";
			}
			elsif ( $param =~ /^logdata:'?([^']+)'?/ )
			{
				$rule->{ log_data } = $1;
			}
			elsif ( $param =~ /initcol:'?([^']+)'?/ )
			{
				push @{ $rule->{ init_colection } }, $1;
			}
			elsif ( $param =~ /setuid:'?([^']+)'?/ )
			{
				$rule->{ set_uid } = $1;
			}
			elsif ( $param =~ /setsid:'?([^']+)'?/ )
			{
				$rule->{ set_sid } = $1;
			}
			elsif ( $param =~ /setvar:'?([^']+)'?/ )
			{
				push @{ $rule->{ set_variable } }, $1;
			}
			elsif ( $param =~ /^chain$/ )
			{
				foreach my $ru ( @nested_rules )
				{
					push @{ $rule->{ chain } }, &parseWAFRule( $ru );
					$rule->{ chain }->[-1]->{ type } = 'match_action';

					push @{ $raw },
					  @{ $rule->{ chain }->[-1]->{ raw } };    # TODO: tab the nested rule
				}
			}
			elsif ( $param =~ /skip:'?([^']+)'?/ ) { $rule->{ skip } = $1; }
			elsif ( $param =~ /skipAfter:'?([^']+)'?/ )
			{
				$rule->{ skip_after } = $1;
			}
			elsif ( $param =~ /exec:'?([^']+)'?/ ) { $rule->{ execute } = $1; }
			elsif ( $param =~ /ctl:'?([^']+)'?/ )
			{
				push @{ $rule->{ modify_directive } }, $1;
			}
		}
	}
	elsif ( $line =~ /^\s*SecMarker\s+(.+)/s )
	{
		$rule->{ 'type' } = 'marker';
		$rule->{ 'mark' } = $1;
	}
	else
	{
		$rule->{ 'type' } = 'custom';
	}

	# save rule
	$rule->{ modified } = $modified;
	chomp @{ $raw };
	$rule->{ raw } = $raw;

	return $rule;
}

=begin nd
Function: buildWAFRule

	Create a SecLang directive through a Zevenet WAF rule.

	The parameter modified of the rule struct is important. It is used to choose if
	build a rule or write the rule saved in the field raw. The raw rule must be written
	if it has been modfied in raw format or if it has not been modified yet.
	If the field modified has the value 'refreh', the rule will be buit.

Parameters:
	WAF rule - It is a hash reference with the WAF rule configuration.

Returns:
	String - text with the SecLang directive

=cut

sub buildWAFRule
{
	my $st         = shift;
	my $chain_flag = shift;
	my $secrule    = "";

	# respect the original chain if it is not been modified
	if ( $st->{ modified } ne 'refresh' )
	{
		my $ruleString = "";

		my $raw = $st->{ raw };
		my $it  = 0;
		foreach my $line ( @{ $raw } )
		{
			$ruleString .= $line;
			$ruleString .= "\n";
			$it++;
		}

		if ( $st->{ modified } eq 'yes' )
		{
			chomp $ruleString;
			$ruleString .= " #\n";
		}

		return $ruleString;
	}

	# else, modified eq 'refresh'
	if ( $st->{ type } =~ /(?:match_action|action)/ )
	{
		if ( $st->{ type } eq 'match_action' )
		{
			my $vars = join ( '|', @{ $st->{ variables } } );
			my $operator = $st->{ operator };
			$operator =~ s/^(!)?//;
			my $not_op = $1 // '';
			$secrule =
			    'SecRule '
			  . $vars . ' "'
			  . $not_op . '@'
			  . $operator . ' '
			  . $st->{ operating } . '" ';
			$secrule .= "\"\\\n";
		}
		else
		{
			$secrule = "SecAction \"\\\n";
		}

		$secrule .= "\tid:" . $st->{ rule_id } . ",\\\n"
		  if ( $st->{ rule_id } );
		$secrule .= "\tmsg:'" . $st->{ description } . "',\\\n"
		  if ( $st->{ description } );

		foreach my $tag ( @{ $st->{ tag } } )
		{
			$secrule .= "\ttag:$tag,\\\n";
		}
		$secrule .= "\tver:" . $st->{ version } . ",\\\n"
		  if ( $st->{ version } );
		$secrule .= "\tmaturity:" . $st->{ maturity } . ",\\\n"
		  if ( $st->{ maturity } =~ /\d/ );
		$secrule .= "\tseverity:" . $st->{ severity } . ",\\\n"
		  if ( $st->{ severity } =~ /\d/ );
		$secrule .= "\taccuracy:" . $st->{ accuracy } . ",\\\n"
		  if ( $st->{ accuracy } =~ /\d/ );
		$secrule .= "\trev:" . $st->{ revision } . ",\\\n"
		  if ( $st->{ revision } =~ /\d/ );
		$secrule .= "\tphase:" . $st->{ phase } . ",\\\n"
		  if ( $st->{ phase } );
		foreach my $t ( @{ $st->{ transformations } } )
		{
			$secrule .= "\tt:$t,\\\n";
		}
		$secrule .= "\tmultimatch,\\\n"    if ( $st->{ multi_match } eq 'true' );
		$secrule .= "\tcapture,\\\n"       if ( $st->{ capture } eq 'true' );
		$secrule .= "\t$st->{action},\\\n" if ( $st->{ action } );
		$secrule .= "\tstatus:" . $st->{ http_code } . ",\\\n"
		  if ( $st->{ http_code } );
		$secrule .= "\tnolog,\\\n"      if ( $st->{ no_log } eq 'true' );
		$secrule .= "\tlog,\\\n"        if ( $st->{ log } eq 'true' );
		$secrule .= "\tauditlog,\\\n"   if ( $st->{ audit_log } eq 'true' );
		$secrule .= "\tnoauditlog,\\\n" if ( $st->{ no_audit_log } eq 'true' );
		$secrule .= "\tlogdata:" . $st->{ log_data } . ",\\\n"
		  if ( $st->{ log_data } );

		foreach my $t ( @{ $st->{ init_colection } } )
		{
			$secrule .= "\tinitcol:$t,\\\n";
		}
		$secrule .= "\tsetuid:" . $st->{ setUid } . ",\\\n"
		  if ( $st->{ set_uid } );
		$secrule .= "\tsetsid:" . $st->{ set_sid } . ",\\\n"
		  if ( $st->{ set_sid } );

		foreach my $it ( @{ $st->{ set_variable } } )
		{
			$secrule .= "\tsetvar:$it,\\\n";
		}
		$secrule .= "\tskip:" . $st->{ skip } . ",\\\n"
		  if ( $st->{ skip } =~ /\d/ );
		$secrule .= "\tskipAfter:" . $st->{ skip_after } . ",\\\n"
		  if ( $st->{ skip_after } );
		$secrule .= "\texec:" . $st->{ execute } . ",\\\n"
		  if ( $st->{ execute } );
		foreach my $it ( @{ $st->{ modify_directive } } )
		{
			$secrule .= "\tctl:$it,\\\n";
		}

		$secrule .= "\tchain,\\\n" if ( @{ $st->{ chain } } or $chain_flag );

		# remove last terminator
		$secrule =~ s/,\\\n$//;
		$secrule .= '"';
		$secrule .= ' #';

		# print all chained rules
		my $num_chain = scalar @{ $st->{ chain } };
		if ( $num_chain )
		{
			foreach my $chained ( @{ $st->{ chain } } )
			{
				$chained->{ modified } = 'refresh';
				$chained->{ type }     = 'match_action';
				$secrule .= "\n\n" . &buildWAFRule( $chained, --$num_chain );
			}
		}
	}

	elsif ( $st->{ type } eq 'marker' )
	{
		$secrule = "SecMarker " . $st->{ mark };
		$secrule .= ' #';
	}

	# custom
	else
	{
		$secrule = $st->{ raw };
		$secrule .= ' #';
	}

	return $secrule;
}

=begin nd
Function: parseWAFSetConf

	It parses the set configuration. This set appears between two marks in the top of the configuration file.

Parameters:
	Conf block - It is an array reference with the configuration directives.

Returns:
	hash ref - text with the SecLang directive

Output example:
$VAR1 = {
          'status' => 'detection',
          'process_response_body' => 'true',
          'request_body_limit' => '6456456',
          'process_request_body' => 'true',
          'default_log' => 'true',
          'default_action' => 'pass',
          'disable_rules' => [
                               '100'
                             ],
          'default_phase' => 'pass',
          'audit' => 'true'
        };

=cut

sub parseWAFSetConf
{
	my $txt  = shift;
	my $conf = &getWAFSetStructConf();

	foreach my $line ( @{ $txt } )
	{
		if ( $line =~ /^\s*SecAuditEngine\s+(on|off)/ )
		{
			my $value = $1;
			$conf->{ audit } = 'true'  if ( $value eq 'on' );
			$conf->{ audit } = 'false' if ( $value eq 'off' );
		}
		if ( $line =~ /^\s*SecRequestBodyAccess\s+(on|off)/ )
		{
			my $value = $1;
			$conf->{ process_request_body } = 'true'  if ( $value eq 'on' );
			$conf->{ process_request_body } = 'false' if ( $value eq 'off' );
		}
		if ( $line =~ /^\s*SecResponseBodyAccess\s+(on|off)/ )
		{
			my $value = $1;
			$conf->{ process_response_body } = 'true'  if ( $value eq 'on' );
			$conf->{ process_response_body } = 'false' if ( $value eq 'off' );
		}
		if ( $line =~ /^\s*SecRequestBodyNoFilesLimit\s+(\d+)/ )
		{
			$conf->{ request_body_limit } = $1;
		}
		if ( $line =~ /^\s*SecRuleEngine\s+(on|off|DetectionOnly)/ )
		{
			my $value = $1;
			$conf->{ status } = 'true'      if ( $value eq 'on' );
			$conf->{ status } = 'false'     if ( $value eq 'off' );
			$conf->{ status } = 'detection' if ( $value eq 'DetectionOnly' );
		}
		if ( $line =~ /^\s*SecDefaultAction\s/ )
		{
			my $value = $line;
			$value =~ s/SecDefaultAction/SecAction/;
			my $def = &parseWAFRule( $value );
			$conf->{ default_action } = $def->{ action };
			$conf->{ default_log }    = $def->{ log };
			$conf->{ default_phase }  = $def->{ phase };
		}
		if ( $line =~ /^\s*SecRuleRemoveById\s+(.*)/ )
		{
			my @ids = split ( ' ', $1 );
			$conf->{ disable_rules } = \@ids;
		}
	}

	return $conf;
}

=begin nd
Function: buildWAFSetConf

	It gets the set configuration object and returns the directives to configuration file

Parameters:
	Conf block - It is an array reference with the configuration directives.

Returns:
	hash ref - text with the SecLang directive.

Output example:
$VAR1 = [
          '## begin conf',
          'SecAuditEngine on',
          'SecAuditLog /var/log/waf_audit.log',
          'SecRequestBodyAccess on',
          'SecResponseBodyAccess on',
          'SecRequestBodyNoFilesLimit 6456456',
          'SecRuleEngine DetectionOnly',
          'SecRuleRemoveById 100',
          'SecDefaultAction "pass,phase:2,log"',
          '## end conf'
        ];

=cut

sub buildWAFSetConf
{
	my $conf = shift;
	my @txt  = ();

	push @txt, $mark_conf_begin;

	if ( $conf->{ audit } eq 'true' )
	{
		push @txt, "SecAuditEngine on";
		push @txt, "SecAuditLog $audit_file";
	}
	if ( $conf->{ process_request_body } eq 'true' )
	{
		push @txt, "SecRequestBodyAccess on";
	}
	if ( $conf->{ process_response_body } eq 'true' )
	{
		push @txt, "SecResponseBodyAccess on";
	}
	if ( $conf->{ request_body_limit } )
	{
		push @txt, "SecRequestBodyNoFilesLimit $conf->{ request_body_limit }";
	}

	if ( $conf->{ status } eq 'true' ) { push @txt, "SecRuleEngine on"; }
	if ( $conf->{ status } eq 'detection' )
	{
		push @txt, "SecRuleEngine DetectionOnly";
	}

	if ( exists $conf->{ disable_rules } )
	{
		if ( @{ $conf->{ disable_rules } } )
		{
			my $ids = join ( ' ', @{ $conf->{ disable_rules } } );
			push @txt, "SecRuleRemoveById $ids";
		}
	}

	$conf->{ default_action } // 'pass';
	$conf->{ default_phase }  // '1';
	my $defaults =
	  "SecDefaultAction \"$conf->{ default_action },phase:$conf->{ default_phase }";
	$defaults .= ",nolog" if ( $conf->{ default_log } eq 'false' );
	$defaults .= ",log"   if ( $conf->{ default_log } eq 'true' );
	push @txt, $defaults . '"';

	push @txt, $mark_conf_end . "\n";

	return @txt;
}

=begin nd
Function: buildWAFSet

	It gets an object with the configuration and the directives and creates a set of directive lines for the configuration file

Parameters:
	Set name - It is the name of the set of rules.
	Set struct - It is a set with two keys: rules, they are a list of rules objects; and configuration, it is a object with the configuration of the set.

Returns:
	String - Returns a message with a description about the file is bad-formed. It will return a blank string if the file is well-formed.

=cut

sub buildWAFSet
{
	my $set      = shift;
	my $struct   = shift;
	my $set_file = &getWAFSetFile( $set );
	my $tmp      = '/tmp/waf_rules.build';
	my $err;

	# create tmp file
	my $fh = &openlock( $tmp, 'w' ) or return 1;

	#write set conf
	if ( exists $struct->{ configuration } )
	{
		my @conf = &buildWAFSetConf( $struct->{ configuration } );
		foreach my $line ( @conf )
		{
			print $fh $line . "\n";
		}
	}

	my $index = -1;
	foreach my $rule_st ( @{ $struct->{ rules } } )
	{
		my $index++;
		my $rule = &buildWAFRule( $rule_st );
		if ( $rule )
		{
			print $fh $rule . "\n\n";
		}
		else
		{
			$err = "Error in rule $index";
			last;
		}
	}
	close $fh;

	return $err if $err;

	# check syntax
	$err = &checkWAFFileSyntax( $tmp );

	# copy to definitive
	if ( not $err )
	{
		$err = &copyLock( $tmp, $set_file );
		include 'Zevenet::IPDS::WAF::Runtime';

		# restart rule
		$err = &reloadWAFByRule( $set );
	}
	else
	{
		&zenlog( "Error checking set syntax $set: $err", "error", "waf" );
	}

	# remove tmp file
	#~ unlink $tmp;

	return $err;
}

=begin nd
Function: checkWAFFileSyntax

	It checks if a file has a correct SecLang syntax

Parameters:
	Set file - It is a path with WAF rules.

Returns:
	String - Returns a message with a description about the file is bad-formed. It will return a blank string if the file is well-formed.

=cut

sub checkWAFFileSyntax
{
	my $file = shift;

	my $pound = &getGlobalConfiguration( 'pound' );
	my $out   = `$pound -W $file 2>&1`;
	my $err   = $?;
	&zenlog( "cmd: $pound -W $file", "debug1", "waf" );

	if ( $err )
	{
		&zenlog( $out, "Error", "waf" ) if $out;
		chomp $out;

		#parse response and return field that failed
		my @aux = split ( '\n', $out );
		$out = $aux[1];
		$out =~ s/^.+Column: \d+. //;
	}
	else
	{
		$out = "";
	}
	return $out;
}

=begin nd
Function: checkWAFRuleSyntax

	It checks if a WAF directive is well-formed.

Parameters:
	Rule string - It is a string with a SecLang directive.

Returns:
	String - Returns a message with a description about the rule is bad-formed. It will return a blank string if the rule is well-formed.

=cut

sub checkWAFRuleSyntax
{
	my $rule  = shift;
	my $pound = &getGlobalConfiguration( 'pound' );

	# is it necessary change rule format
	$rule =~ s/"/\\"/g;

	my $out = `$pound -w "$rule" 2>&1`;
	my $err = $?;
	&zenlog( "cmd: $pound -w \"$rule\"", "debug1", "waf" );

	if ( $err )
	{
		&zenlog( $out, "Error", "waf" ) if $out;
		chomp $out;

		#parse response and return fields that failed
		my @aux = split ( '\n', $out );
		$out = $aux[1];
		$out =~ s/^.+Column: \d+. //;
	}
	else
	{
		$out = "";
	}

	return $out;
}

=begin nd
Function: getWAFRule

	It returns a waf rule of a set using its index.

Parameters:
	Set path - It is the path of a WAF set
	Rule index - It is a index of the WAF rule

Returns:
	Hash ref - Returns a object with the parmeters of the rule.

=cut

sub getWAFRule
{
	my $set   = shift;
	my $index = shift;

	my $set_st = &getWAFSet( $set );
	return undef if ( $index >= scalar @{ $set_st->{ rules } } );

	return $set_st->{ rules }->[$index];
}

=begin nd
Function: parseWAFBatch

	It parses a batch of WAF rules and it returns list with the rules object.

Parameters:
	Rules - It is an array reference with a set of directives lines

Returns:
	Array ref - It is a list of rules object.

=cut

sub parseWAFBatch
{
	my $batch = shift;
	my @rules = ();

	my @rules_nested;
	my $rule  = [];
	my $id    = 0;
	my $chain = 0;    # if chain is found, sent the next rule too

	foreach my $line ( @{ $batch } )
	{
		$chain = 1 if ( $line =~ /[\"\s,]chain[\"\s,]/ );
		push @{ $rule }, $line;

		# if the line is not splitted '\', it is the final
		if ( $line !~ /\\\s*$/ )
		{
			push @rules_nested, $rule;
			if ( $chain )
			{
				$rule  = [];
				$chain = 0;
			}
			else
			{
				my $hash_rule = &parseWAFRule( @rules_nested );
				$hash_rule->{ id } = $id;
				$id++;

				push @rules, $hash_rule
				  if @rules_nested;    # add the last rule
				$rule         = [];
				@rules_nested = ();
			}
		}
	}

	return \@rules;
}

=begin nd
Function: getWAFSet

	It parses a set file and returns a object with two keys: configuration, is a object with the configuration of the set;
	rules, is a list with WAF rules objects.

Parameters:
	Set name - It is the name of a WAF set rule

Returns:
	Array ref - It is a list of rules object.

=cut

sub getWAFSet
{
	my $set = shift;

	my $fh = &openlock( &getWAFSetFile( $set ), 'r' ) or return undef;
	my @conf_arr;
	my @batch;
	my $conf_flag = 0;

	while ( my $line = <$fh> )
	{
		# get global configuration of the set
		if ( $line =~ /^$mark_conf_begin/ )
		{
			$conf_flag = 1;
			next;
		}
		if ( $conf_flag )
		{
			push @conf_arr, $line;

			# end conf
			if ( $line =~ /^$mark_conf_end/ )
			{
				$conf_flag = 0;
			}
			next;
		}

		next if ( $line =~ /^\s*$/ );    # skip blank lines
		next if ( $line =~ /^\s*#/ );    # skip commentaries

		push @batch, $line;
	}

	close $fh;

	my $conf  = &parseWAFSetConf( \@conf_arr );
	my $rules = &parseWAFBatch( \@batch );

	return { rules => $rules, configuration => $conf };
}

1;
