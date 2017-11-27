package Firewall;

use strict;
use warnings;
use Firewall::Utils qw( intersect_arrays intersect_multiple_arrays );
use Sort::Key qw(nkeysort_inplace);
use JSON::XS qw(decode_json);
use Data::Dumper qw(Dumper);		## Temporary


my $FIELD_SEPARATOR = qr/(?:,\s+|\s+|[\|;])/;
my @FIELDS = qw( src dst service target );

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
## 		src => {									## field (src, dst, service, etc...)
##				'10.1.1.1' => [ 1, 4, 100, 345 ]	## search value + rules matching
sub find_rules_tree {
	my ( $self, %args ) = @_;		## keys: src dst service target
	die "The firewall is not yet ready. Firewall source has not yet been parsed.\n" unless $self->is_ready;
	my %h;	
	#------------------
	## Loop through all IP fields
	foreach my $field ( qw( src dst target ) ) {
		next unless $args{$field};
		my $vals = ref($args{$field}) eq 'ARRAY' ? $args{$field} : [ split $FIELD_SEPARATOR, $args{$field} ];
		foreach my $val ( @$vals ) {
			$h{$field}{$val} = $self->find_rules_matching_ipaddr_or_ipnet_or_range( $field, $val );
		}
	}
	#------------------
	## Service field
	if ( $args{service} ) {
		my $vals = ref($args{service}) eq 'ARRAY' ? $args{service} : [ split $FIELD_SEPARATOR, $args{service} ];
		foreach my $val ( @$vals ) {
			$h{service}{$val} = $self->find_rules_matching_service_or_servicerange($val);
		}
	}
	#------------------
	return \%h;
}

sub find_rules {
	my ( $self, %args ) = @_;		## keys: opt src dst service target
	die "The firewall is not ready. Firewall source has not yet been parsed.\n" unless $self->is_ready;
	#------------------
	## Get rules tree
	my $h = $self->find_rules_tree( %args );
	#------------------
	## Result EACH: Keep rules matching all given branches
	my (%h, $r);
	foreach my $field ( @FIELDS ) {
		next unless $args{$field};	# skip empty fields
		if ( ! defined($r) ) {
			foreach ( keys %{$h->{$field}} ) {
				push @$r, {
					fields => { $field => $_ },
					rules => $h->{$field}{$_}
				};
			}
		} else {
			my @tmp;
			for my $i ( 0..$#{$r} ) {
				my $res = $r->[$i];		# current tree				
				foreach ( keys %{$h->{$field}} ) {
					my %resnew;		# new tree
					%{$resnew{fields}} = %{$res->{fields}};		# copy it (don't use ref)
					$resnew{fields}{$field} = $_;
					$resnew{rules} = intersect_arrays( $res->{rules}, $h->{$field}{$_} );
					push @tmp, \%resnew;
				}
			}
			$r = \@tmp;
		}
	}
	$h{each} = $r;
	#------------------
	## Result ALL: Only keep rules matching all branches
	my $rall;
	foreach my $field ( qw( src dst target service ) ) {
		next unless $args{$field};			# skip empty fields
		foreach my $a ( values %{$h->{$field}} ) {
			( $rall = $a and next ) unless defined($rall);
			$rall = intersect_arrays( $rall, $a );
		}
	}
	$h{all} = $rall;
	#------------------
	## Sort rules
	nkeysort_inplace { $_ } @{$h{all}};
	nkeysort_inplace { $_ } @{$_->{rules}} for @{$h{each}};
	#------------------
	## Output
	return \%h;
}

sub get_rules {
	my ( $self, %args ) = @_;
	#------------------
	## Input
	my @rules;
	my $nb_rules = $self->nb_rules;
	if ( ref($args{rules}) eq 'ARRAY' ) {
		foreach ( @{$args{rules}} ) {
			if ( $_ =~ m/^\d+$/ ) {
				push @rules, $_ if $_ <= $nb_rules;;
			} elsif ( $_ =~ m/^(\d+)\-(\d+)$/ ) {
				next if $1 >= $nb_rules;
				my $high = $2 > $nb_rules ? $nb_rules : $2;
				push @rules, ( $1..$high ) if $1 <= $high;
			}	## silently skip bad values
		}
	}
	#------------------
	## Output
	if ( $args{opt} eq 'full' && ( !$args{format} || $args{format} eq 'hash' ) ) {			## Return Built rules
		my $a = $args{rules} && !@rules ? [] : @rules ? $self->get_rules_from_seq(\@rules) : $self->get_all_rules;		## @$a = array of prebuilt rules (json)
		@$a = map{ decode_json($_) } @$a;
		return $a;
	} elsif ( $args{opt} eq 'full' && $args{format} eq 'json' ) {			## Return Built rules
		my $a = $args{rules} && !@rules ? [] : @rules ? $self->get_rules_from_seq(\@rules) : $self->get_all_rules;		## @$a = array of prebuilt rules (json)
		return '['.join(',', @$a).']';	## input = array of prebuilt rules (json)
	}
}


##################################################################
## MATCHING TREE (ranking tree)
##################################################################
## Store rules matching in an hash tree.
## %h = ( 
## 		451 => {									## rule seq (rule number)
##			fields => {
##				src => {							## field (src, dst, service, etc...)
##					match => 4,						## number of matches (equal or included)
##					exact => 4						## number of exact matches (only equal)
##			all => {								## all fields merged
##				match => 4,							## sum of all matches (equal or included)
##				exact => 4							## sum of all exact matches (only equal)
sub find_ranking_tree {
	my ( $self, %args ) = @_;		## keys: src dst service target
	die "The firewall is not yet ready. Firewall source has not yet been parsed.\n" unless $self->is_ready;
	my %tree;	
	#------------------
	## Args
	$args{limit} //= 2;
	#------------------
	## Loop through all IP fields
	foreach my $field ( qw( src dst target ) ) {
		next unless $args{$field};
		my $vals = ref($args{$field}) eq 'ARRAY' ? $args{$field} : [ split $FIELD_SEPARATOR, $args{$field} ];
		foreach my $val ( @$vals ) {
			foreach my $seq ( @{$self->find_rules_matching_ipaddr_or_ipnet_or_range($field,$val) } ) {
				$tree{$seq}{fields}{$field}{match}++;
				$tree{$seq}{all}{match}++;
			}
			foreach my $seq ( @{$self->find_rules_with_ipaddr_or_ipnet_or_range($field,$val) } ) {
				$tree{$seq}{fields}{$field}{exact}++;
				$tree{$seq}{all}{exact}++;
			}
		}
	}
	#------------------
	## Service field
	if ( $args{service} ) {
		my $vals = ref($args{service}) eq 'ARRAY' ? $args{service} : [ split /(?:,\s+|\s+|[\|;])/, $args{service} ];
		foreach my $val ( @$vals ) {
			foreach my $seq ( @{$self->find_rules_matching_service_or_servicerange($val) } ) {
				$tree{$seq}{fields}{service}{match}++;
				$tree{$seq}{all}{match}++;
			}
			foreach my $seq ( @{$self->find_rules_with_service_or_servicerange($val) } ) {
				$tree{$seq}{fields}{service}{exact}++;
				$tree{$seq}{all}{exact}++;
			}
		}
	}
	#------------------
	## Reformat result tree
	my %rank;
	foreach ( keys %tree ) {
		next unless $tree{$_}{all}{match} >= $args{limit};
		$tree{$_}{seq} = $_;
		push @{ $rank{$tree{$_}{all}{match}} }, $tree{$_};
	}
	#------------------
	## Sort result tree (put results with most "exact matches" on top then sort by seq number)
	foreach ( values %rank ) {
		@$_ = sort { ( $b->{all}{exact} || 0 ) <=> ( $a->{all}{exact} || 0 ) || $a->{seq} <=> $b->{seq} } @$_;
	}
	#------------------
	## Output
	return \%rank;
}




1;