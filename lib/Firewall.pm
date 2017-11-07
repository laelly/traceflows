package Firewall;

use strict;
use warnings;
use Firewall::Utils qw( intersect_arrays intersect_multiple_arrays );
# use Sort::Key qw(nkeysort_inplace nkeysort);
use JSON::XS qw(decode_json);


##################################################################
## INITIALIZATION
##################################################################
##*********************************
## NEW
##*********************************
sub new {
    my ($class, %args) = @_;
	die('A firewall type must be provided when calling $h->new( name=>FIREWALL_NAME, type=>FIREWALL_TYPE )') unless $args{'type'};
	die('A firewall name must be provided when calling $h->new( name=>FIREWALL_NAME, type=>FIREWALL_TYPE )') unless $args{'name'};
	
	my $module = $args{'type'};
	eval "use Firewall::Vendor::${module}; 1;" or die("Unable to load module Firewall::Vendor::${module}. $@");
	my $self = "Firewall::Vendor::$module"->new( %args );
	
    return $self;
}


##################################################################
## FIREWALL INITIALISATION METHODS
##################################################################
#*************************
## Set Data Source
#*************************
sub set_source {
	# $fw->set_source ( type, %args )
	#	type => ssh or file
	#	args => {...}
    my ($self, $type, %args) = @_;
	die "Missing 'type' in method ->set_source( type, %args )\n" unless $type;
	
	## Select data source
	my $f = 'set_source_'.lc($type);
	if ( $self->can( $f ) ) {
		$self->$f( %args );
	} else {
		die "Unknown Source type ".$type.".\n";
	}
}


#*************************
## Set Endpoint
#*************************
sub ep { shift->{_ENDPOINT} }
sub _set_endpoint {
	# $fw->_set_endpoint ( type, %args )
	#	type => database or memory
	#	args => {...}
    my ($self, $type, %args) = @_;
	die "Missing 'type' in method ->_set_endpoint( type, %args )\n" unless $type;
	
	## Import parent endpoint Class
	my $class = ref($self).'::Endpoint::'.$type;
	eval "use parent '$class'; 1;" or die("Unable to load class '".$class."'. $@");
	die("Missing Endpoint '".$class."->_init' method\n") unless $self->can( '_init' );
	$self->_init( %args );
}


##################################################################
## FIREWALL methods
##################################################################
sub name { $_[0]->{name} }
sub type { $_[0]->{type} }
sub is_ready { $_[0]->{_READY} }


##################################################################
## FIND RULES
##################################################################
## Store rules matching in an hash tree.
## %h = ( 
## 		src => {									## field (src, dst, etc...)
##				'10.1.1.1' => [ 1, 4, 100, 345 ]	## search value + rules matching
sub find_rules_id_tree {
	my ( $self, %args ) = @_;		## keys: src dst service target
	die "The firewall is not yet ready. Firewall source has not yet been parsed.\n" unless $self->is_ready;
	my %h;	
	#------------------
	## Loop through all IP fields
	foreach my $field ( qw( src dst target ) ) {
		next unless $args{$field};
		my $vals = ref($args{$field}) eq 'ARRAY' ? $args{$field} : [ split /\s*[,; ]\s*/, $args{$field} ];
		foreach my $val ( @$vals ) {
			$h{$field}{$val} = $self->find_rules_matching_ipaddr_or_ipnet_or_range( $field, $val );
		}
	}
	#------------------
	## Service field
	if ( $args{service} ) {
		my $vals = ref($args{service}) eq 'ARRAY' ? $args{service} : [ split /\s*[,; ]\s*/, $args{service} ];
		foreach my $val ( @$vals ) {
			$h{service}{$val} = $self->find_rules_matching_service_or_servicerange( $val );
		}
	}
	#------------------
	return \%h;
}

sub find_rules {
	my ( $self, %args ) = @_;		## keys: opt src dst service target
	die "The firewall is not yet ready. Firewall source has not yet been parsed.\n" unless $self->is_ready;
	#------------------
	## Get rules tree
	my $h = $self->find_rules_id_tree( %args );
	#------------------
	## Result intersection: Keep only rules matching branches
	my $result;			# array ref
	foreach my $field ( qw( src dst target service ) ) {
		next unless $args{$field};			# skip empty fields
		foreach my $a ( values %{$h->{$field}} ) {
			( $result = $a and next ) unless defined($result);
			$result = intersect_arrays( $result, $a );
		}
	}
	#------------------
	## Output
	if ( ! $args{opt} || $args{opt} eq 'numbers' ) {	## Return rules sequence number
		@$result = sort { $a <=> $b } @$result;
		return $result;
	} elsif ( $args{opt} eq 'full' ) {			## Return Built rules
		return $self->build_rules( $result );	## input = array of rules seq numbers
	}
}

sub get_rules {
	my ( $self, %args ) = @_;
	#------------------
	## Output
	if ( ! $args{opt} || $args{opt} eq 'numbers' ) {	## Return rules sequence number
		my $result = $self->get_all_rules_seq;
		# nkeysort_inplace { $_->{seq} } @$result;
		return $result;
	} elsif ( $args{opt} eq 'full' && ( !$args{format} || $args{format} eq 'hash' ) ) {			## Return Built rules
		my $a = $self->get_all_rules;	## input = array of prebuilt rules (json)
		@$a = map{ decode_json($_) } @$a;
		return $a;
	} elsif ( $args{opt} eq 'full' && $args{format} eq 'json' ) {			## Return Built rules
		return '['.join(',', @{$self->get_all_rules}).']';	## input = array of prebuilt rules (json)
	}
}










1;