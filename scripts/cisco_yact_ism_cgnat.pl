#!/usr/bin/perl

###################################################################################### 
#                                                                                    #
# check_ism_cgnat                                                                    #
#                                                                                    #
# Check ISM CGv6 health and perfromance                                              #
#                                                                                    #
# Create by kresimir.petrovic@gmail.com for monitoring ISM CGNAT modules             #
# Originally developed to generate cacti statistics.                                 #
# Caching was introduced to reduce number of ssh connection on the ASR9k             #
#                                                                                    #
# Nagios::Plugin and Net::SSH2 perl modules are required                             #
#                                                                                    #
###################################################################################### 

package main;

our $VERSION = '1.1.1';

use strict;
use POSIX;

use Nagios::Plugin;
use Nagios::Plugin::Getopt;
use Nagios::Plugin::Threshold;
use Net::SSH2;
use Data::Dumper;
use	Storable;

if ( !caller ) {
    main();
}

my ($debug, $cache_file, $cache_timeout, %checks);
sub main {

	%checks = (		'NoAT' => 'Number of active translations',
					'NoS' => 'Number of sessions',
					'TCR' => 'Translations create rate',
					'TDR' => 'Translations delete rate',
					'ItOFR' => 'Inside to outside forward rate',
					'OtIFR' => 'Outside to inside forward rate',
					'ItODPLE' => 'Inside to outside drops port limit exceeded',
					'ItODSLR' => 'Inside to outside drops system limit reached',
					'ItODRD' => 'Inside to outside drops resource depletion',
					'NTED' => 'No translation entry drops',
					'PPTP_AT' => 'PPTP active tunnels',
					'PPTP_AC' => 'PPTP active channels',
					'PPTP_CMD' => 'PPTP ctrl message drops',
					'NoSUB' => 'Number of subscribers',
					'DSDLE' => 'Drops due to session db limit exceeded'
				);

	
	my ($result_text, $check_result, $check_text, $error_level);
	my ($plugin, $arg_opts);
	my ($ssh2, $ssh_host, $ssh_user, $ssh_pwd);
	my (@cmd_out, %statistics, $time, $command, $target, $warning, $critical);

	$plugin = Nagios::Plugin->new( shortname => 'ISM CGv6'); 
	$arg_opts = parse_nagios_plugin_options();	

	# Parse input parameters
	$ssh_host = $arg_opts->host();
	$ssh_user = $arg_opts->username();
	$ssh_pwd = $arg_opts->password();
	$debug = $arg_opts->debug();
	$cache_file = $arg_opts->file."-".$ssh_host;
	$cache_timeout = $arg_opts->cachetimeout;
	$warning =  $arg_opts->warning();
	$critical =  $arg_opts->critical();
	$command = 'show cgn '.$arg_opts->nat.' '.$arg_opts->instance.' statistics';
	$time = time();

	# If exists, load cache file first to avoid excessive connections on ASR9k
	if ($arg_opts->cache and -f $cache_file)
	{
		%statistics = load_stats_from_file($cache_file);	

		# Cache expired, connect to ASR9k and get statistics
		if (($time - $statistics{'exec_time'}) > $cache_timeout)
		{
			print "[DEBUG] Cache expired, start from begining\n" if $debug;
			@cmd_out = ssh2_execute_command($ssh_host, $ssh_user, $ssh_pwd, $command);
			%statistics = ();
			cgnat_parse_statistics(\%statistics, \@cmd_out);
			# Update cache time
			$statistics{'exec_time'}=$time;
			# Save new stats to file cache
			save_stats_to_file($cache_file, \%statistics);
		}
		# Cache is valid, use it
		else
		{
			print "[DEBUG] Using cached data\n" if $debug;
			cgnat_parse_statistics(\%statistics, \@cmd_out);
		}
	}
	# Don't use cache, we want relevant data every time
	else
	{
		print "[DEBUG] Cache disabled!!!\n" if $debug;
		@cmd_out = ssh2_execute_command($ssh_host, $ssh_user, $ssh_pwd, $command);
		%statistics = ();
		cgnat_parse_statistics(\%statistics, \@cmd_out);
		# Update cache time
		$statistics{'exec_time'}=$time;
		# Save new stats to file cache
		save_stats_to_file($cache_file, \%statistics);
	}

	# Geenrate only cacti statistics
	if ($arg_opts->cacti)
	{
		my ($cacti_perf_data);
		$cacti_perf_data = cgnat_gen_cacti_stats(\%statistics);
		print $cacti_perf_data;
		exit;
	}
	# Monitor specific value in CGNAT statistics. Possible targets are defined with %checks
	elsif ($target = $arg_opts->target())
	{
		# If target exists, check values
		if (exists $checks{$target})
		{
			print "[DEBUG] Monitoring target $target: $checks{$target}\n" if $debug;
			$error_level = $plugin->check_threshold( check => $statistics{$checks{$target}}, warning => $warning, critical => $critical );
			$result_text = $checks{$target}.": $statistics{$checks{$target}}";
		}
		# Misspelled target name
		else
		{
			$error_level = 'UNKNOWN';
		}
	}

	# Exit with proper error level and error text
	$plugin->nagios_exit( $error_level, $result_text );

#	print Dumper \%statistics if $debug;

}


# Parse plugin arguments
sub parse_nagios_plugin_options()
{
	my ($options);

	$options = Nagios::Plugin::Getopt->new( 
		usage => "Usage: %s [ -v|--verbose ]  [ -H|--host <ISM_ip> ] [ -U|--username <usernmae>] [ -P|--password <password>] [ -C|--cache ] [ -F|--file <file>] [ -T|--cachetimeout <time>] [ -I|--instance <instance_name> ] [ -N|--nat <NAT_type> ] [ -t|--target <value_target> ] [ -w|--warning <warning> ] [ -c|critical <critical> ]",
		version => $VERSION,
		blurb   => 'Monitors ISM CGv6 statistics, outputs perf data for cacti',
		extra   => 'Created by: Kresimir Petrovic kresimir.petrovic@gmail.com',
		url     => 'http://code.google.com/p/nagios-cpnr-monitoring/',
		timeout => 15
	);

    $options->arg(
		spec     => 'host|H=s',
		help     => 'ISAM IP address',
		required => 1 
    );

    $options->arg(
		spec     => 'username|U=s',
		help     => 'SSH Username',
		required => 1 
    );

    $options->arg(
		spec     => 'password|P=s',
		help     => 'SSH password',
		required => 1 
    );

    $options->arg(
		spec     => 'cache|C',
		help     => 'Enable cache',
		required => 0
    );

    $options->arg(
		spec     => 'file|F=s',
		help     => 'Cache file',
		required => 0,
		default  => '/tmp/ism_cgnat_stats.txt'
    );

    $options->arg(
		spec     => 'cachetimeout|T=i',
		help     => 'Cache timeout',
		required => 0,
		default  => 240
    );

    $options->arg(
		spec     => 'target|t=s',
		help     => 'Target to monitor',
		required => 0
    );

    $options->arg(
		spec     => 'warning|w=i',
		help     => 'warning',
		required => 0,
		default  => 100
    );

    $options->arg(
		spec     => 'critical|c=i',
		help     => 'critical',
		required => 0,
		default  => 200
    );

    $options->arg(
		spec     => 'debug',
		help     => 'debugging output',
		required => 0
    );
     
    $options->arg(
		spec     => 'instance|I=s',
		help     => 'Instance name',
		required => 1
    );

    $options->arg(
		spec     => 'nat|N=s',
		help     => 'NAT type',
		required => 0,
		default  => 'nat44'
    );
     
    $options->arg(
		spec     => 'cacti|n',
		help     => 'cacti perfdata format',
		required => 0
    );

    $options->arg(
		spec     => 'noperfdata|n',
		help     => 'no perfdata to output',
		required => 0
    );

    $options->getopts();
	return $options;
}

# Execute ssh command. No enable suuport, user must have required privilege
sub ssh2_execute_command()
{
	my ($ssh_host, $ssh_user, $ssh_pwd);
	my ($ssh_command, $ssh2, $chan);
	my (@result);

	($ssh_host, $ssh_user, $ssh_pwd, $ssh_command) = @_;


	print "[DEBUG] Connecting using SSH2 to $ssh_host with user:$ssh_user and pass:$ssh_pwd\n" if $debug;
	$ssh2 = Net::SSH2->new();
	$ssh2->connect($ssh_host) or die $!;

	if ($ssh2->auth_password($ssh_user,$ssh_pwd)) 
	{
		my $chan = $ssh2->channel();
		$chan->blocking(0);

		print "	[DEBUG] Executing command \"$ssh_command\"!\n" if $debug;
		$chan->exec($ssh_command);
		while (<$chan>){ push @result,$_; }

		$chan->close;
		return @result;
	} else 
	{
			warn "Authentication failed !!!\n";
	}
	$ssh2->disconnect();

}

# Parse CGNAT statistics
sub cgnat_parse_statistics()
{
	my ($result, $data );

	($result, $data) = @_;

	print "[DEBUG] Parsing CGv6 statistics.\n" if $debug;
	foreach (@{$data})
	{
		chomp();
		print "	[DEBUG] Line: $_\n" if $debug;
		#Parse cgn stats output to hash using simple regexp to avoid multiple if statements
		if (m/(.*):\s+(.*)\r/)
		{
			print "		[DEBUG] #$1#=#$2#\n" if $debug;
			$result->{$1} = $2; 
		}
		elsif (m/\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9]+).*/)
		{
			print "		[DEBUG] #$1#=#$2#\n" if $debug;
			$result->{$1} = $2; 
		}
	}
}

sub save_stats_to_file()
{
	my ($file, $stats_ref);

	($file, $stats_ref) = @_;

	print "[DEBUG] saving stats to \"$file\", saved time \"".localtime($stats_ref->{'exec_time'})."\"\n" if $debug;
	store $stats_ref, $file or die "Can't open file '$file':$!";
	return 1;
}

sub load_stats_from_file()
{
	my ($file, %stats);

	($file) = @_;

	%stats = %{retrieve($file)} or die "Can't open file '$file':$!";
	print "[DEBUG] loading stats from: \"$file\", saved time \"".localtime($stats{'exec_time'})."\"\n" if $debug;

	return %stats;
}

# Geenrate cacti statistics
sub cgnat_gen_cacti_stats()
{
	my (%stats, $result);
	%stats = %{$_[0]};

	$result='';
	$result.=" NoAT:".$stats{'Number of active translations'} if (exists $stats{'Number of active translations'});
	$result.=" NoS:".$stats{'Number of sessions'} if (exists $stats{'Number of sessions'});
	$result.=" TCR:".$stats{'Translations create rate'} if (exists $stats{'Translations create rate'});
	$result.=" TDR:".$stats{'Translations delete rate'} if (exists $stats{'Translations delete rate'});
	$result.=" ItOFR:".$stats{'Inside to outside forward rate'} if (exists $stats{'Inside to outside forward rate'});
	$result.=" OtIFR:".$stats{'Outside to inside forward rate'} if (exists $stats{'Outside to inside forward rate'});
	$result.=" ItODPLE:".$stats{'Inside to outside drops port limit exceeded'} if (exists $stats{'Inside to outside drops port limit exceeded'});
	$result.=" ItODSLR:".$stats{'Inside to outside drops system limit reached'} if (exists $stats{'Inside to outside drops system limit reached'});
	$result.=" ItODRD:".$stats{'Inside to outside drops resource depletion'} if (exists $stats{'Inside to outside drops resource depletion'});
	$result.=" NTED:".$stats{'No translation entry drops'} if (exists $stats{'No translation entry drops'});
	$result.=" PPTP_AT:".$stats{'PPTP active tunnels'} if (exists $stats{'PPTP active tunnels'});
	$result.=" PPTP_AC:".$stats{'PPTP active channels'} if (exists $stats{'PPTP active channels'});
	$result.=" PPTP_CMD:".$stats{'PPTP ctrl message drops'} if (exists $stats{'PPTP ctrl message drops'});
	$result.=" NoSUB:".$stats{'Number of subscribers'} if (exists $stats{'Number of subscribers'});
	$result.=" DSDLE:".$stats{'Drops due to session db limit exceeded'} if (exists $stats{'Drops due to session db limit exceeded'});
	return $result;
}
