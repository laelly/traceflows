package MyFork;
use strict;
use warnings;
use Exporter;
use Sereal qw(decode_sereal encode_sereal);
use Exporter qw(import);

our @EXPORT = qw( forkme );

our $TIMEOUT = 300;

sub forkme {
	my ( $func, @params ) = @_;
	return undef unless ref($func) eq 'CODE';

	pipe my $perr, my $cerr;
	pipe my $pout, my $cout;
	$cout->autoflush(1);
	$cerr->autoflush(1);

	my $pid = fork;
	my $s = time;
	die "Fork failed.", return unless defined $pid;
	if ( $pid == 0 ) {	## CHILD
		local $SIG{ __DIE__ };		## prevent parent from dying
		local $SIG{ __WARN__ };		## prevent parent from dying
		select($cerr);		## redirect STDOUT to $cerr
		open STDERR, ">&STDOUT" or die "Can't write STDERR to STDOUT: $!";
		
		## Die if timeout
		alarm $TIMEOUT;		## Timeout before the child is killed
		local $SIG{ALRM} = sub { die "No answer from child $$ process within the time limit of ${TIMEOUT}s. Killing it...\n"; };
		
		## close parent handles
		close($perr);
		close($pout);
		
		## Execute function with params
		my $result = {};
		eval{ $result = $func->(@params) };
		print $cerr $@ if $@;
		close($cerr);
		print $cout encode_sereal( $result );
		close($cout);
		
		## use thread exit if the fork is in a thread (otherwise the parent will be killed instead of the fork)
		threads->exit() if ( grep { /^threads/ } keys %INC );
		exit;
	}
	## close child handles
	close($cerr);
	close($cout);
	
	## Get errors and result
	my ($err, $result);
	eval {		
		$err = do { local $/; <$perr> };
		$result = do { local $/; <$pout> };
		$result = decode_sereal( $result );
	};
	if ( (time - $s) >= $TIMEOUT ) {
		$err = "Timed Out ! Task took more than defined timeout of ${TIMEOUT}s and has been killed";
		$result = undef;
	} elsif ( $@ ) {
		$err = 'Error when retreiving data from fork: '.$err."\n".$@;
		$result = undef;
	} elsif ( !$result ) {
		$err = "No result received from child!\n".$err;
	}
	
	## Return result & errors
	return ( $result, $err );
}



1;

