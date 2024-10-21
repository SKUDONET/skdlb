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
use Skudonet::Lock;
use Skudonet::IPDS::WAF::Core;

my $mark_conf_begin = "## begin conf";
my $mark_conf_end   = "## end conf";

=begin nd
Function: parseWAFRuleAction

	It parses a SecLang Action directive and it returns an object with all parameters of the directive.

	This function parses the next type of rules:
	* action, the SecAction directive

Parameters:

	Lines - It is an array reference with the parameters of a SecLang directive.

Returns:
	Hash ref - It is a rule parsed. The possible values are shown in the output example.

Output example:
	$VAR1 = {
		'action' => 'pass',
		'log' => 'true',
		'no_log' => 'false',
		'phase' => '2',
		'redirect_url' => '',
	};


=cut

sub parseWAFRuleAction
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $txt = shift;
	my $line;
	my $rule;
	my $directive = '';
	my $act;

	$line = $txt;

	if ( $line =~ /^\s*(Sec\w+)\s+/s )
	{
		$directive = $1;
	}

	if ( $directive =~ /SecAction$/ )
	{
		# parsing SecAction

		$act = $line;
		$act =~ s/^\s*SecAction\s+//;
		$act =~ s/^"//;
		$act =~ s/"\s*$//;

		$rule->{ type } = 'action';

		my @options = ();
		if ( defined $act )
		{
			# Does not split ',' when it is between quotes. Getting the quoted items:
			while ( $act =~ s/(\w+:'[^\']*'\s*)(?:,|$)// )
			{
				push @options, $1;
			}

			my @options2 = split ( ',', $act );
			push @options, @options2;
		}

		foreach my $param ( @options )
		{
			$param =~ s/^\s*//;
			$param =~ s/\s*$//;

			if ( $param =~ /phase:'?([^']+)'?/ )
			{
				$rule->{ phase } = $1;
				$rule->{ phase } = 2 if ( $rule->{ phase } eq 'request' );
				$rule->{ phase } = 4 if ( $rule->{ phase } eq 'response' );
				$rule->{ phase } = 5 if ( $rule->{ phase } eq 'logging' );
				$rule->{ phase } += 0;
			}

			elsif ( $param =~ /^(redirect(:.+)|allow|pass|drop|block|deny)$/ )
			{
				$rule->{ action }       = $1;
				$rule->{ redirect_url } = $2;
				if ( $rule->{ redirect_url } )
				{
					$rule->{ redirect_url } =~ s/^://;
					$rule->{ action } = 'redirect';
				}
			}
			elsif ( $param =~ /^nolog$/ )
			{
				$rule->{ no_log } = "true";
			}
			elsif ( $param =~ /^log$/ )
			{
				$rule->{ log } = "true";
			}
		}
	}
	else
	{
		$rule->{ 'type' } = 'custom';
	}

	return $rule;
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
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $txt  = shift;
	my $conf = &getWAFSetStructConf();
	my $def_action_flag =
	  0;    # avoid parsing more than one SecDefaultAction directive

	foreach my $line ( @{ $txt } )
	{
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

		# The 'SecRequestBodyNoFilesLimit' directive is read for a bugfix
		if ( $line =~ /^\s*(?:SecRequestBodyNoFilesLimit|SecRequestBodyLimit)\s+(\d+)/ )
		{
			$conf->{ request_body_limit } = $1;
		}
		if ( $line =~ /^\s*SecRuleEngine\s+(on|off|DetectionOnly)/ )
		{
			my $value = $1;
			$conf->{ status }       = ( $value eq 'off' )           ? 'false' : 'true';
			$conf->{ only_logging } = ( $value eq 'DetectionOnly' ) ? 'true'  : 'false';
		}
		if ( $line =~ /^\s*SecDefaultAction\s/ and !$def_action_flag )
		{
			my $value = $line;
			$def_action_flag = 1;
			$value =~ s/SecDefaultAction/SecAction/;
			my $def = &parseWAFRuleAction( $value );
			$conf->{ default_action } =
			  ( $def->{ action } ne '' ) ? $def->{ action } : 'pass';
			if ( $def->{ log } eq 'true' )
			{
				$conf->{ default_log } = 'true';
			}
			elsif ( $def->{ no_log } eq 'true' )
			{
				$conf->{ default_log } = 'false';
			}
			$conf->{ default_phase } = $def->{ phase };
			$conf->{ redirect_url }  = $def->{ redirect_url };
		}
	}

	return $conf;
}

=begin nd
Function: buildWAFSetConf

	It gets the set configuration object and returns the directives to configuration file

Parameters:
	Conf block - It is an array reference with the configuration directives.
	skip def action - This is a flag to not create de SecDefaultAction directive if this directive already exists for the requested phase. This directive only can exist one time for a phase.

Returns:
	hash ref - text with the SecLang directive.

Output example:
$VAR1 = [
          '## begin conf',
          'SecAuditEngine on',
          'SecAuditLog /var/log/waf_audit.log',
          'SecRequestBodyAccess on',
          'SecResponseBodyAccess on',
          'SecRequestBodyLimit 6456456',
          'SecRuleEngine DetectionOnly',
          'SecRuleRemoveById 100',
          'SecDefaultAction "pass,phase:2,log"',
          '## end conf'
        ];

=cut

sub buildWAFSetConf
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $conf       = shift;
	my $def_phases = shift;
	my @txt        = ();
	my $audit_file = "/var/log/waf_audit.log";

	push @txt, $mark_conf_begin;

	if ( $conf->{ process_request_body } eq 'true' )
	{
		push @txt, "SecRequestBodyAccess on";
		if ( $conf->{ request_body_limit } )
		{
			push @txt, "SecRequestBodyLimit $conf->{ request_body_limit }";
		}
	}
	else
	{
		push @txt, "SecRequestBodyAccess off";
	}
	if ( $conf->{ process_response_body } eq 'true' )
	{
		push @txt, "SecResponseBodyAccess on";
	}
	else
	{
		push @txt, "SecResponseBodyAccess off";
	}

	if ( $conf->{ status } eq 'true' )
	{
		if ( $conf->{ only_logging } eq 'true' )
		{
			push @txt, "SecRuleEngine DetectionOnly";
		}
		else
		{
			push @txt, "SecRuleEngine on";
		}
	}
	else
	{
		push @txt, "SecRuleEngine off";
	}


	$conf->{ default_action } //= 'pass';
	my $def_action =
	  ( defined $conf->{ redirect_url } and $conf->{ redirect_url } ne '' )
	  ? "redirect:$conf->{redirect_url}"
	  : $conf->{ default_action };
	my $defaults = "SecDefaultAction \"$def_action";
	$defaults .= ",nolog" if ( $conf->{ default_log } eq 'false' );
	$defaults .= ",log"   if ( $conf->{ default_log } eq 'true' );
	$defaults .= ',logdata:\'client:%{REMOTE_ADDR}\'';    # Add client IP to logs

	foreach my $phase ( @{ $def_phases } )
	{
		push @txt, $defaults . ",phase:$phase\"";
	}

	push @txt, $mark_conf_end;

	return @txt;
}

=begin nd
Function: buildWAFSetByConf

	It gets an object with the configuration and updates a set of directive lines for the configuration file

Parameters:
	Set name - It is the name of the set of rules.
	Set struct - It is a set with a configuration, it is a object with the configuration of the set.

Returns:
	String - Returns a message with a description about the file is bad-formed. It will return a blank string if the file is well-formed.

=cut

sub buildWAFSetByConf
{
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $set      = shift;
	my $struct   = shift;
	my $set_file = &getWAFSetFile( $set );
	my $dir      = &getWAFSetDir();
	my $tmp      = "$dir/waf_rulesets.build";
	my $err_msg;

	# create tmp file and lock resource
	my $lock_file = &getLockFile( $tmp );
	my $flock     = &openlock( $lock_file, 'w' ) or return "Error reading data";
	my $fh        = &openlock( $tmp, 'w' )
	  or do { close $flock; return "Error reading data" };

	#write set conf
	if ( exists $struct->{ configuration } )
	{
		# check that do not exist another SecDefaultAction in the same phase
		my $def_phases = [1, 2, 3, 4];
		my @conf = &buildWAFSetConf( $struct->{ configuration }, $def_phases );
		foreach my $line ( @conf )
		{
			print $fh $line . "\n";
		}

		my $fh_set = &openlock( $set_file, 'r' );
		if ( $fh_set )
		{
			my $in_config = 0;
			while ( <$fh_set> )
			{
				$in_config = 1 if $_ =~ /^$mark_conf_begin/;
				if ( $_ =~ /^$mark_conf_end/ )
				{
					$in_config = 0;
					next;
				}
				next if $in_config;
				print $fh $_;
			}
			close $fh_set;
		}
	}
	else
	{
		$err_msg = "No configuration in param!";
	}

	close $fh;

	if ( $err_msg )
	{
		close $flock;
		&zenlog( "Error building the set '$set'", "error", "waf" );
		return $err_msg;
	}

	# check syntax
	$err_msg = &checkWAFFileSyntax( $tmp );

	# copy to definitive
	if ( $err_msg )
	{
		&zenlog( "Error checking set syntax '$set': $err_msg", "error", "waf" );
		$err_msg = "Error checking syntax: " . $err_msg;
	}
	else
	{
		if ( &copyLock( $tmp, $set_file ) )
		{
			$err_msg = "Error saving changes in '$set'";
		}
		else
		{
			# restart rule
			require Skudonet::IPDS::WAF::Runtime;
			if ( &reloadWAFByRule( $set ) )
			{
				$err_msg = "Error reloading the set '$set'";
			}
		}
	}

	# free resource
	close $flock;

	return $err_msg;
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
	&zenlog( __FILE__ . ":" . __LINE__ . ":" . ( caller ( 0 ) )[3] . "( @_ )",
			 "debug", "PROFILING" );
	my $file = shift;

	my $waf_check = &getGlobalConfiguration( 'waf_rule_check_bin' );
	my $out       = &logAndGet( "$waf_check $file", "string", 1 );
	my $err       = $?;
	&zenlog( "cmd: $waf_check $file", "debug1", "waf" );

	if ( $err )
	{
		&zenlog( $out, "Error", "waf" ) if $out;
		chomp $out;

		# remove line:	"starting..."
		my @aux = split ( '\n', $out );
		$out = $aux[1];

		# clean line and column info
		$out =~ s/^.+Column: \d+. //;

		$out = &parseWAFError( $out );
	}
	else
	{
		$out = "";
	}
	return $out;
}

sub parseWAFError
{
	my $err_msg = shift;

# A parameter is a file and it has not been found
# Error loading waf rules, Rules error. File: /usr/local/skudonet/config/ipds/waf/sets/waf_rules.build. Line: 8. Column: 30. Failed to open file: php-error.data. Looking at: 'php-error.data', 'php-error.data', '/usr/local/skudonet/config/ipds/waf/sets/php-error.data', '/usr/local/skudonet/config/ipds/waf/sets/php-error.data'.
	if ( $err_msg =~ /Failed to open file / )
	{
		my $wafconfdir = &getWAFSetDir();
		if ( $err_msg =~ /'(${wafconfdir}[^']+)'/ )
		{
			$err_msg = "The file '$1' has not been found";
		}
		else
		{
			&zenlog( "Error parsing output: Failed to open file", "error", "waf" );
		}
	}

# Action parameter is not recognized
# Error loading waf rules, Rules error. File: /usr/local/skudonet/config/ipds/waf/sets/waf_rules.build. Line: 11. Column: 7. Expecting an action, got:  bloc,\
	elsif ( $err_msg =~ /Expecting an action, got:\s+(.+),\\/ )
	{
		$err_msg = "The parameter '$1' is not recognized";
	}

# Variable is not recognized
#Error loading waf rules, Rules error. File: /usr/local/skudonet/config/ipds/waf/sets/waf_rules.build. Line: 8. Column: 56. Expecting a variable, got:  :  _eNAMES|ARGS|XML:/* "@rexphp-errors.data" \
	elsif ( $err_msg =~ /Expecting a variable, got:\s+:\s+(.+) / )
	{
		#~ $err_msg = "The variable '$1' is not recognized";
		$err_msg = "Error in variables";
	}

	return $err_msg;
}

1;
