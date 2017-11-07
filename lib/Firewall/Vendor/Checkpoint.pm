package Firewall::Vendor::Checkpoint;

use strict;
use warnings;
use CPparser;
use base 'Firewall';
use Firewall::Utils qw( data_store data_load );	## temporary
use Firewall::Utils qw( data_serialize data_deserialize );
use Firewall::Utils qw( netmask_to_cidr extract_port );
use Parallel::ForkManager 0.7.6;
use MyFork; $MyFork::TIMEOUT = 30;
use IPprotocol;
use Time::HiRes qw(time);		## temproary
use Data::Dumper;	## temporary
our @ISA;

##################################################################
## INITIALIZATION
##################################################################
##*********************************
## NEW
##*********************************
sub new {
    my ($class, %args) = @_;
	die('A name must be specified when calling $h->new( name => FIREWALL_NAME )') unless $args{'name'};
	die('Missing endpoint configuraion') unless $args{endpoint}{type};
	
    my $self = bless {
		'name'			=> $args{'name'},
		'type'			=> 'Checkpoint'
	}, $class;
	$self->_set_endpoint( $args{endpoint}{type}, %{$args{endpoint}} );
    return $self;
}


##################################################################
## DATA
##################################################################
## Logging types
my $track = {
	Log					=> 1,
	None				=> 0,
	SnmpTrap			=> 0,
	Mail				=> 0,
	Long				=> 0,
	'Exception Alert'	=> 0,
	AuthAlert			=> 0,
	Short				=> 0,
	'IP Options Alert'	=> 0,
	Account				=> 0,
	VPNddcateAcceptLog	=> 0,
	'UserDefined 3'		=> 1,
	'UserDefined 2'		=> 1,
	'UserDefined'		=> 1,
	Auth				=> 0,
	Duplicate			=> 0,
	Alert				=> 0,
	'IP Options'		=> 0,
	spoofalert			=> 0,
};


##################################################################
## METHODS
##################################################################
#*************************
## Set Endpoint 
#*************************
## from Firewall.pm
# sub ep --> endpoint ref 
# _set_endpoint( $self, type, %args ) --> load parent endpoint and inherit its classes


#*************************
## Set Data Source
#*************************
## from Firewall.pm
# set_source( $self, type, %args ) --> define data source

sub set_source_file {
    my ($self, %args) = @_;	
	die "Missing 'objects_file' and/or 'rulebases_file' for type 'file' " unless $args{'objects_file'} && $args{'rulebases_file'};
	$self->{_SOURCE}{type} = 'file';
	$self->{_SOURCE}{objects_file} = $args{'objects_file'};
	$self->{_SOURCE}{rulebases_file} = $args{'rulebases_file'};
}

sub set_source_ssh {
	die "Not Yet Implemented.\n";
}


#*************************
## [INTERNAL] Parse Data from Source
#*************************
sub _parse_data_from_ssh {
    die "Not Yet Implemented.\n";
}

sub _parse_data_from_file {
	my $self = shift;
	die "Missing 'objects_file' and/or 'rulebases_file' for type 'file' " unless $self->{_SOURCE}{objects_file} && $self->{_SOURCE}{rulebases_file};
	die "Can't read file ".$self->{_SOURCE}{objects_file}."\n" unless -r $self->{_SOURCE}{objects_file};
	die "Can't read file ".$self->{_SOURCE}{rulebases_file}."\n" unless -r $self->{_SOURCE}{rulebases_file};
	
	## Parse
	my $parser = CPparser->new;
	return $parser->parse($self->{_SOURCE}{objects_file}, $self->{_SOURCE}{rulebases_file});
}


##################################################################
## Parse and Extract useful data
##################################################################
sub parse {
	my $self = shift;
	
	## Check endpoint
	die "Can't parse data unless a valid Endpoint is defined\n" unless $self->{_ENDPOINT};
	
	#************************************
	## Parse data source in a separate process to cleanup memory after execution
	#************************************
	my $s = time;
	my ($data, $err) = forkme( sub{
		my $parser = {};
		# if ( ! $self->{_SOURCE}{type} ) {
			# die "Undefined Data source!\n";
		# } elsif ( $self->{_SOURCE}{type} eq 'file' ) {
			# $parser = $self->_parse_data_from_file;
		# } elsif ( $self->{_SOURCE}{type} eq 'ssh' ) {
			# $parser = $self->_parse_data_from_ssh;
		# } else {
			# die "Unknown data source ".$self->data_source."\n";
		# }
		
		return {
			network_objects	=> $parser->{'network_objects'},
			services		=> $parser->{'services'},
			rulebase		=> $parser->{'rule-base'},
			policies		=> $parser->{'policies_collections'},
			# times			=> $parser->{'times'},		## Data about rule schedules
		};
	});	
	die $err if $err;	
	
	## Temporary Store/load data
	# data_store( 'TMP/test.srl', $data);exit;
	$data = data_load('TMP/test.srl');
	# print Dumper($data); exit;
	warn sprintf "[$$]Parsing fw config files: took %.5f ms\n", (time - $s)*1000;
	
	
	#************************************
	## Pre-processing
	#************************************
	$self->_pre_processing if $self->can('_pre_processing');
	
	
	#************************************
	## Get network objects ( IP and groups )
	#************************************
	## Extract
	$s = time;
	my $addresses = $self->_extract_addresses( $data->{network_objects} );
	warn sprintf "[$$]EXTRACT Addresses: took %.5f ms\n", (time - $s)*1000;
	
	## Store
	$self->_store_addresses( $addresses );

	
	#************************************
	## Get service objects ( ports and groups )
	#************************************
	## Extract
	$s = time;
	my $services = $self->_extract_services( $data->{services} );
	warn sprintf "[$$]EXTRACT services: took %.5f ms\n", (time - $s)*1000;
	
	## Store
	$self->_store_services( $services );
	
	
	#************************************
	## Get rules
	#************************************
	## Extract
	$s = time;
	my $default_policy = $self->_extract_policy( $data->{policies} );
	warn sprintf "[$$]EXTRACT default_policy (".$default_policy."): took %.5f ms\n", (time - $s)*1000;
	$s = time;
	my $rules = $self->_extract_rules( $default_policy, $data->{rulebase} );
	warn sprintf "[$$]EXTRACT rules: took %.5f ms\n", (time - $s)*1000;
	$s = time;
	my $rules_nat = $self->_extract_rules_nat( $default_policy, $data->{rulebase} );
	warn sprintf "[$$]EXTRACT rules nat: took %.5f ms\n", (time - $s)*1000;
	
	## Store
	$s = time;
	$self->_store_rules( $rules );
	warn sprintf "[$$]Store rules: took %.5f ms\n", (time - $s)*1000;
	$s = time;
	$self->_store_rules_nat( $rules_nat );
	warn sprintf "[$$]Store rules nat: took %.5f ms\n", (time - $s)*1000;
	

	#************************************
	## Mapping & prebuilding
	#************************************
	$self->_mapping_obj_rule;
	$self->_mapping_obj_rule_nat;
	$self->_prebuild_rules;
	
	
	#************************************
	## Post processing
	#************************************
	$self->_post_processing if $self->can('_post_processing');
	
	
	## Mark firewall as ready
	$self->{_READY} = 1;
}


##################################################################
## Extract functions
##################################################################
sub _extract_addresses {
	my ($self,$p) = @_;
	die "Can't find Network Objects ! Has the file containing objects correctly been parsed?" unless ref($p) eq 'HASH';

	my ( @ipgroup, @ipgroup_with_exclusion, @ipaddr, @ipnet, @iprange );
	foreach my $name ( keys %$p ) {
		my $c = $p->{$name};
		#------------------
		## Object group
		if ( $c->{'type'} eq 'group' ) {
			my $group = {
				name	=> $name,
				uid		=> $c->{'AdminInfo'}{'chkpf_uid'}
			};
			foreach my $inGroup ( @{ $c->{'ReferenceObject'} } ) {
				push @{$group->{content}}, $inGroup->{'Name'} =~ m/^(?:Any|All)$/i ? 'ipany' : $inGroup->{'Uid'};
			}
			push @ipgroup, $group;
		#------------------
		## Networks
		} elsif ( $c->{'type'} eq 'network' ) {
			push @ipnet, {
				name	=> $name,
				ipaddr	=> $c->{'ipaddr'}.'/'.netmask_to_cidr($c->{'netmask'}),
				uid		=> $c->{'AdminInfo'}{'chkpf_uid'}
			};
		#------------------
		## IP Addresses
		} elsif ( $c->{'type'} =~ m/^(host|gateway|cluster_member|gateway_cluster)$/ ) {
			push @ipaddr, {
				name	=> $name,
				ipaddr	=> $c->{'ipaddr'},
				uid		=> $c->{'AdminInfo'}{'chkpf_uid'}
			};
		#------------------
		## IP Ranges
		} elsif ( $c->{'type'} eq 'machines_range' ) {
			push @iprange, {
				name => $name,
				ipaddr_low	=> $c->{'ipaddr_first'},
				ipaddr_high	=> $c->{'ipaddr_last'},
				uid			=> $c->{'AdminInfo'}{'chkpf_uid'}
			};
		#------------------
		## Group with exclusion
		} elsif ( $c->{'type'} eq 'group_with_exclusion' ) {
			push @ipgroup_with_exclusion, {
				name	=> $name,
				content	=> [ $c->{base}{Name} =~ m/^(?:Any|All)$/i ? 'ipany' : $c->{base}{Uid} ],
				exclusion => [ $c->{exception}{Name} =~ m/^(?:Any|All)$/i ? 'ipany' : $c->{exception}{Uid} ],
				uid		=> $c->{'AdminInfo'}{'chkpf_uid'}
			};
		#------------------
		## Ignored: Create empty objects
		} elsif ( $c->{'type'} =~ m/^(security_zone_obj|gateway_cluster|dynamic_net_obj|hostname|voip_gw)$/i ) {
			push @ipaddr, {
				name	=> $name,
				uid		=> $c->{'AdminInfo'}{'chkpf_uid'}
			};
		#------------------
		## Others
		} else {
			warn "Unknown object type: ".$c->{'type'}." for object named ".$name;
		}
	}	
	
	## Add object Any
	push @ipnet, {
		name	=> 'Any',
		ipaddr	=> '0.0.0.0/0',
		type	=> 'ipnet',
		uid		=> 'ipany',
	};
	
	return {
		ipaddr					=> \@ipaddr,
		ipnet					=> \@ipnet,
		iprange					=> \@iprange,
		ipgroup					=> \@ipgroup,
		ipgroup_with_exclusion	=> \@ipgroup_with_exclusion,
	};
}

sub _extract_services {
	my ($self,$p) = @_;
	die "Can't find Services Objects ! Has the file containing objects correctly been parsed?" unless ref($p) eq 'HASH';

	my ( @service, @servicerange, @servicegroup );
	foreach my $name ( keys %$p ) {
		my $c = $p->{$name};
		#------------------
		## Services groups
		if ( $c->{'type'} eq 'group' ) {
			my $group = {
				name	=> $name,
				uid		=> $c->{'AdminInfo'}{'chkpf_uid'}
			};
			foreach my $inGroup ( @{ $c->{'ReferenceObject'} } ) {
				push @{$group->{content}}, $inGroup->{'Name'} =~ m/^(?:Any|All)$/i ? 'serviceany' : $inGroup->{'Uid'};
			}
			push @servicegroup, $group;
		#------------------
		## Services TCP/UDP
		} elsif ( $c->{'type'} =~ m/^(Tcp|Udp)/i ) {
			my ($type,$port) = extract_port( $c->{'port'} );
			my %h = (
				name		=> $name,
				uid			=> $c->{'AdminInfo'}{'chkpf_uid'},
				content		=> [ { protocol => uc($1), %$port } ]
			);
			$type eq 'service' ? push(@service,\%h) : push(@servicerange,\%h);
		#------------------
		## Other IP protocols
		} elsif ( $c->{'type'} =~ m/^Other$/i ) {
			my $protocol = $c->{'protocol'} || 'none';
			$protocol = $IPprotocol::IP{ $protocol } || 'IP_'.$protocol;
			push @service, {
				name		=> $name,
				uid			=> $c->{'AdminInfo'}{'chkpf_uid'},
				content		=> [ { protocol => $protocol } ]
			};
		#------------------
		## ICMP
		} elsif ( $c->{'type'} =~ m/^Icmp/i ) {
			my %h = (
				name		=> $name,
				uid			=> $c->{'AdminInfo'}{'chkpf_uid'},
				content		=> [ { protocol => 'ICMP' } ]
			);
			$h{content}[0]{'icmp_type'} = $c->{'icmp_type'} if $c->{'icmp_type'};
			$h{content}[0]{'icmp_code'} = $c->{'icmp_code'} if $c->{'icmp_code'};
			push @service, \%h;
		#------------------
		## RPC(NYI) : create empty service
		} elsif ( $c->{'type'} =~ m/^(Rpc|dcerpc)$/i ) {
			push @service, {
				name		=> $name,
				uid			=> $c->{'AdminInfo'}{'chkpf_uid'}
			};
		#------------------
		## GTP
		} elsif ( $c->{'type'} =~ m/^gtp/i ) {
			my ($type,$port) = extract_port( $c->{'port'} || $c->{'control_port'} );
			my %h = (
				name		=> $name,
				uid			=> $c->{'AdminInfo'}{'chkpf_uid'},
				content 	=> [ { protocol => 'TCP', %$port }, { protocol => 'UDP', %$port } ]
			);
			$type eq 'service' ? push(@service,\%h) : push(@servicerange,\%h);
		#------------------
		## ELSE	
		} else {
			warn "Unknown service type ".$c->{'type'}." for service ".$name;
		}
	}
	
	## Add object Any
	push @servicerange, {
		name		=> 'Any',
		uid			=> 'serviceany',,
		content 	=> [ { protocol => 'TCP', port_low => 1, port_high => 65535 }, { protocol => 'UDP', port_low => 1, port_high => 65535 } ]
	};
	
	return {
		service			=> \@service,
		servicerange	=> \@servicerange,
		servicegroup	=> \@servicegroup,
	};
}

sub _extract_policy {
	my ($self,$p) = @_;
	die "Can't find Policies Objects ! Has the file containing the rules correctly been parsed?" unless ref($p) eq 'HASH';
	
	my $policy;
	foreach my $policy_name ( keys %$p ) {
		next unless $p->{$policy_name}{default} && $p->{$policy_name}{default} eq '1';
		$policy = $policy_name;
		last;
	}
	die "Can't find any policy!" unless $policy;
	return $policy;
}

sub _extract_rules {
	my ($self, $policy_name, $p) = @_;
	die "Can't find Rules Objects ! Has the file containing the rules correctly been parsed?" unless ref($p) eq 'HASH';
	
	my $ruleset;
	#------------------
	## Find the right policy
	foreach my $policy ( ref($p) eq 'ARRAY' ? @$p : ( $p ) ) {
		next unless $policy->{'collection'}{'Name'} && $policy->{'collection'}{'Name'} eq $policy_name;
		$ruleset = $policy;
		last;
	}
	die "Can't find the right ruleset!" unless $ruleset;

	#------------------
	## Analyze rules
	my $current_section = '';
	my @rules;
	my $seq = 0;
	foreach my $rule ( @{$ruleset->{'rule'}} ) {
		## New section
		if ( my $section = $rule->{'header_text'} ) {
			( $current_section = $section ) =~ s/^[\s"]*(.*?)[\s"]*$/$1/;
			next;
		}
		## Rule
		push @rules, {
			seq				=> ++$seq,
			enable			=> $rule->{'disabled'} && $rule->{'disabled'} eq 'false' ? 1 : 0,
			is_global_rule	=> $rule->{'AdminInfo'}{'global_level'} ? 1 : 0,
			section			=> $current_section,
			action			=> (keys %{$rule->{'action'}})[0],
			schedule		=> $rule->{'time'}{'ReferenceObject'}[0]{Name},
			logging			=> $track->{ $rule->{'track'}{'ReferenceObject'}[0]{Name} } //= 0,
			comment			=> $rule->{'comments'} =~ m/^[\s"]*(.*?)[\s"]*$/ ? $1 : $rule->{'comments'},
			
			src				=> __extract_field_ip_obj( $rule->{'src'} ),
			dst				=> __extract_field_ip_obj( $rule->{'dst'} ),
			service			=> __extract_field_service_obj( $rule->{'services'} ),
		};
	}
	return {
		rule => \@rules
	};
}

sub _extract_rules_nat {
	my ($self, $policy_name, $p) = @_;
	die "Can't find Rules Objects ! Has the file containing the rules correctly been parsed?" unless ref($p) eq 'HASH';
	
	my $ruleset;
	#------------------
	## Find the right policy
	foreach my $policy ( ref($p) eq 'ARRAY' ? @$p : ( $p ) ) {
		next unless $policy->{'collection'}{'Name'} && $policy->{'collection'}{'Name'} eq $policy_name;
		$ruleset = $policy;
		last;
	}
	die "Can't find the right ruleset!" unless $ruleset;

	#------------------
	## Analyze rules
	my $current_section = '';
	my @rules;
	my $seq = 0;
	foreach my $rule ( @{$ruleset->{'rule_adtr'}} ) {
		## New section
		if ( my $section = $rule->{'header_text'} ) {
			( $current_section = $section ) =~ s/^[\s"]*(.*?)[\s"]*$/$1/;
			next;
		}
		## Rule
		push @rules, {
			seq				=> ++$seq,
			enable			=> $rule->{'disabled'} && $rule->{'disabled'} eq 'false' ? 1 : 0,
			is_global_rule	=> $rule->{'AdminInfo'}{'global_level'} ? 1 : 0,
			section			=> $current_section,
			comment			=> $rule->{'comments'} =~ m/^[\s"]*(.*?)[\s"]*$/ ? $1 : $rule->{'comments'},
			
			src				=> __extract_field_ip_obj( $rule->{'src_adtr'} ),
			src_nat			=> __extract_field_ip_obj( $rule->{'src_adtr_translated'} ),
			dst				=> __extract_field_ip_obj( $rule->{'dst_adtr'} ),
			dst_nat			=> __extract_field_ip_obj( $rule->{'dst_adtr_translated'} ),
			service			=> __extract_field_service_obj( $rule->{'services_adtr'} ),
			service_nat		=> __extract_field_service_obj( $rule->{'services_adtr_translated'} ),
		};
	}
	return {
		rule => \@rules
	};
}


##################################################################
## Internal functions
##################################################################
sub __extract_field_ip_obj {
	my $data = $_[0]->{'ReferenceObject'};
	my @list;
	foreach my $obj ( @{$data} ) {
		push @list, $obj->{'Name'} =~ m/^(?:Any|All)$/i ? 'ipany' : $obj->{'Uid'};
	}
	return \@list;
}

sub __extract_field_service_obj {
	my $data = $_[0]->{'ReferenceObject'};
	my @list;
	foreach my $obj ( @{$data} ) {
		push @list, $obj->{'Name'} =~ m/^(?:Any|All)$/i ? 'serviceany' : $obj->{'Uid'};
	}
	return \@list;
}


#*************************
## Update
#*************************
sub update {}




1;