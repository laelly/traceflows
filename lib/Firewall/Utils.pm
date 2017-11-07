package Firewall::Utils;

use strict;
use warnings;
use Sereal qw(sereal_encode_with_object sereal_decode_with_object decode_sereal encode_sereal);
use Exporter qw(import);
use Sort::Key qw(keysort_inplace);

## Export
our @EXPORT = qw();

our @EXPORT_OK = qw(
	data_store data_load
	is_valid_ip is_valid_ip_or_network
	data_serialize data_deserialize
	netmask_to_cidr
	extract_port
	intersect_arrays intersect_multiple_arrays merge_arrays
	normalize_action_value
	sort_ipaddr sort_ipaddr_inplace sort_by_type_then_ipaddr_inplace
	sort_services sort_services_inplace sort_by_type_then_services_inplace
);


#################################################
## FILE
#################################################
sub data_store {
	my ($file, $data, $args) = @_;
	
	## File
	die "A file must be provided\n" unless $file;
	
	## Encoder & Compression 
	my $enc = $args->{compress} ? Sereal::Encoder->new( {compress => Sereal::Encoder::SRL_SNAPPY } ) : Sereal::Encoder->new;
	
	## Store
	open FH, '>', $file or die "Can't open file '".$file."' ".$!;
	print FH sereal_encode_with_object($enc,$data);
	close FH;
}

sub data_load {
	my ($file, $args) = @_;
	
	## File
	die "A file must be provided\n" unless $file;
	
	## Decoder
	my $dec = Sereal::Decoder->new();
	
	## Load
	open FH, '<', $file or die "Can't open file '".$file."' ".$!;
	my $data = sereal_decode_with_object($dec, do { local $/; <FH> } );
	close FH;
	
	return $data;
}


#################################################
## Serialization
#################################################
sub data_serialize { return encode_sereal($_[0]); }
sub data_deserialize { return decode_sereal($_[0]); }


#################################################
## IP / NETWORKS
#################################################
sub is_valid_ip {
	if ( $_[0] && $_[0] =~ /^
					(?:
						(?: 
							(?: 2(?:5[0-5]|[0-4][0-9])\. )
							|
							(?: 1[0-9][0-9]\. )
							|
							(?: (?:[1-9][0-9]?|[0-9])\. )
						){3}						
						(?: 
							(?: 2(?:5[0-5]|[0-4][0-9]) )
							|
							(?: 1[0-9][0-9] )
							|
							(?: (?:[1-9][0-9]?|[0-9]) )
						)
					)$/x ) {
		return 1;
	} else { return 0; }
}
sub is_valid_ip_or_network {
	if ( $_[0] && $_[0] =~ /^
					(?:
						(?: 
							(?: 2(?:5[0-5]|[0-4][0-9])\. )
							|
							(?: 1[0-9][0-9]\. )
							|
							(?: (?:[1-9][0-9]?|[0-9])\. )
						){3}						
						(?: 
							(?: 2(?:5[0-5]|[0-4][0-9]) )
							|
							(?: 1[0-9][0-9] )
							|
							(?: (?:[1-9][0-9]?|[0-9]) )
						)
					)
					(?:\/(?:3[0-2]|[12][0-9]|[0-9]))?$/x ) {
		return 1;
	} else { return 0; }
}

my $netmasks = {
	'255.255.255.255' => 32,
	'255.255.255.254' => 31,
	'255.255.255.252' => 30,
	'255.255.255.248' => 29,
	'255.255.255.240' => 28,
	'255.255.255.224' => 27,
	'255.255.255.192' => 26,
	'255.255.255.128' => 25,
	'255.255.255.0' => 24,
	'255.255.254.0' => 23,
	'255.255.252.0' => 22,
	'255.255.248.0' => 21,
	'255.255.240.0' => 20,
	'255.255.224.0' => 19,
	'255.255.192.0' => 18,
	'255.255.128.0' => 17,
	'255.255.0.0' => 16,
	'255.254.0.0' => 15,
	'255.252.0.0' => 14,
	'255.248.0.0' => 13,
	'255.240.0.0' => 12,
	'255.224.0.0' => 11,
	'255.192.0.0' => 10,
	'255.128.0.0' => 9,
	'255.0.0.0' => 8,	  
	'254.0.0.0' => 7,
	'252.0.0.0' => 6,
	'248.0.0.0' => 5,
	'240.0.0.0' => 4,
	'224.0.0.0' => 3,
	'192.0.0.0' => 2,
	'128.0.0.0' => 1,
	'0.0.0.0' => 0
};
sub netmask_to_cidr {
	return $netmasks->{$_[0]};	
}

sub sort_ipaddr_inplace {
	keysort_inplace { 
		my @a = split /\./;
		return $_ unless @a == 4;
		$a[3] =~ s/(?:\/\d+)$//;
		($a[0] >= 100 ? $a[0] : $a[0] >= 10 ? '0'.$a[0] : '00'.$a[0]).
		($a[1] >= 100 ? $a[1] : $a[1] >= 10 ? '0'.$a[1] : '00'.$a[1]).
		($a[2] >= 100 ? $a[2] : $a[2] >= 10 ? '0'.$a[2] : '00'.$a[2]).
		($a[3] >= 100 ? $a[3] : $a[3] >= 10 ? '0'.$a[3] : '00'.$a[3])
	} @{$_[0]};
}
sub sort_ipaddr {
	my @a = keysort { 
		my @a = split /\./;
		return $_ unless @a == 4;
		$a[3] =~ s/(?:\/\d+)$//;
		($a[0] >= 100 ? $a[0] : $a[0] >= 10 ? '0'.$a[0] : '00'.$a[0]).
		($a[1] >= 100 ? $a[1] : $a[1] >= 10 ? '0'.$a[1] : '00'.$a[1]).
		($a[2] >= 100 ? $a[2] : $a[2] >= 10 ? '0'.$a[2] : '00'.$a[2]).
		($a[3] >= 100 ? $a[3] : $a[3] >= 10 ? '0'.$a[3] : '00'.$a[3])
	} @{$_[0]};
	return \@a;
}

sub sort_by_type_then_ipaddr_inplace {
	keysort_inplace {
		if ( $_->{type} eq 'ipgroup' ) {
			return '.0'.$_->{name};
		} elsif ( $_->{type} eq 'ipgroup_with_exclusion' ) {
			return '.1'.$_->{name};
		} else {
			my @a = split /\./;
			return '.9'.$_ unless @a == 4;
			$a[3] =~ s/(?:\/\d+)$//;
			return '.9'.($a[0] >= 100 ? $a[0] : $a[0] >= 10 ? '0'.$a[0] : '00'.$a[0]).
			($a[1] >= 100 ? $a[1] : $a[1] >= 10 ? '0'.$a[1] : '00'.$a[1]).
			($a[2] >= 100 ? $a[2] : $a[2] >= 10 ? '0'.$a[2] : '00'.$a[2]).
			($a[3] >= 100 ? $a[3] : $a[3] >= 10 ? '0'.$a[3] : '00'.$a[3])
		}
	} @{$_[0]};
}


#################################################
## Ports / Services
#################################################
sub extract_port {
	my $port = shift;
	if ( !$port ) {
		return ( 'service', {} );
	} elsif ( $port =~ m/^\d+$/ ) {
		return ( 'service', { port => $port } );
	} elsif ( $port =~ m/^(\d+)\-(\d+)$/ ) {
		return ( 'servicerange', { port_low => $1, port_high => $2 } );
	} elsif ( $port =~ m/^"?\>(\d+)"?$/ ) {
		return ( 'servicerange', { port_low => $1, port_high => 65535 } );
	} elsif ( $port =~ m/^"?\<(\d+)"?$/ ) {
		return ( 'servicerange', { port_low => 1, port_high => $1 } );
	} else {
		die "Invalid port: '".$port."'\n";
	}
}

sub sort_services_inplace {
	keysort_inplace {
		if ( m/^((?:[A-Za-z]+)_)(\d+)$/ ) {
			return $1.($2 >= 10000 ? $2 : $2 >= 1000 ? '0'.$2 : $2 >= 100 ? '00'.$2 : $2 >= 10 ? '000'.$2 : '0000'.$2);
		} else {
			return $_;
		}
	} @{$_[0]};
}
sub sort_services {
	my @a = keysort {
		if ( m/^((?:[A-Za-z]+)_)(\d+)$/ ) {
			return $1.($2 >= 10000 ? $2 : $2 >= 1000 ? '0'.$2 : $2 >= 100 ? '00'.$2 : $2 >= 10 ? '000'.$2 : '0000'.$2);
		} else {
			return $_;
		}
	} @{$_[0]};
	return \@a;
}

sub sort_by_type_then_services_inplace {
	keysort_inplace {
		if ( $_->{type} eq 'servicegroup' ) {
			return '.0'.$_->{name};
		} elsif ( $_->{type} eq 'servicegroup_with_exclusion' ) {
			return '.1'.$_->{name};
		} else {
			if ( m/^((?:[A-Za-z]+)_)(\d+)$/ ) {
				return '.9'.$1.($2 >= 10000 ? $2 : $2 >= 1000 ? '0'.$2 : $2 >= 100 ? '00'.$2 : $2 >= 10 ? '000'.$2 : '0000'.$2);
			} else {
				return '.9'.$_;
			}
		}
	} @{$_[0]};
}


#################################################
## Arrays
#################################################
sub intersect_arrays {
	my ($a1,$a2) = @_;
	return [] unless ref($a1) eq 'ARRAY' && ref($a2) eq 'ARRAY';	
	my %e = map { $_ => undef } @$a1;
	my @a = grep { exists( $e{$_} ) } @$a2;
	return \@a;
}

sub intersect_multiple_arrays {
	my $current = shift;
	foreach ( @_ ) {
		return [] unless ref($_) eq 'ARRAY';
		$current = intersect_array( $current, $_ );
	}
	return $current;
}

sub merge_arrays {
	my ($a1,$a2) = @_;
	push @$a1, @$a2;
	return $a1;
}


#################################################
## Firewall objects
#################################################
sub normalize_action_value {
	my $action = shift;
	if ( $action eq 'accept' ) {
		return 'allow';
	} else {
		return $action;
	}
}


1;