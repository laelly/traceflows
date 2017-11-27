package Firewall::Endpoint::Database;

use strict;
use warnings;
use DBI;
use parent 'Firewall::Endpoint::Database::Objects';
use Firewall::Utils qw( is_valid_ip is_valid_ip_or_network );
use Data::Dumper qw(Dumper);	## temporary
use Time::HiRes qw(time);		## temproary
use JSON::XS qw(encode_json);
use Firewall::Utils qw(sort_ipaddr_inplace sort_services_inplace sort_by_type_then_ipaddr_inplace sort_by_type_then_services_inplace);


######################################################
## Init
######################################################
sub _init {	
    my ($self, %args) = @_;	
	die "Missing Database Endpoint parameters!\n" unless $args{dsn} && $args{username} && $args{password};
	$args{options} = ref($args{options}) eq 'HASH' ? $args{options} : {AutoCommit => 1, RaiseError => 1, PrintError => 1};
	
	## Store some data in self
	$self->{_ENDPOINT} = 'database';
	$self->{_ENDPOINT_DATA}{dsn} = $args{dsn};
	$self->{_ENDPOINT_DATA}{username} = $args{username};
	$self->{_ENDPOINT_DATA}{password} = $args{password};
	$self->{_ENDPOINT_DATA}{options} = $args{options};
	
	## Set fw_id if it already exists in database
	$self->{_ENDPOINT_DATA}{fw_id} = $self->_select_firewall_entry;
	$self->dbh->disconnect;
}

sub _select_firewall_entry {
    my ($self) = @_;
	$self->{_ENDPOINT_DATA}{fw_id} = $self->select_firewall( $self->name, $self->type );
}

sub _insert_firewall_entry {
    my ($self) = @_;
	$self->{_ENDPOINT_DATA}{fw_id} = $self->insert_firewall( $self->name, $self->type, ref($self) );
}

sub _update_firewall_entry {
    my ($self) = @_;
	$self->{_ENDPOINT_DATA}{fw_id} = $self->update_firewall( $self->name, $self->type, ref($self) );
}


######################################################
## Database functions
######################################################
sub dbh_cached {
	$_[0]->{_ENDPOINT_DATA}{_DBH} //= $_[0]->dbh_new;
	return $_[0]->{_ENDPOINT_DATA}{_DBH};
}

sub dbh {
	return DBI->connect_cached(
		$_[0]->{_ENDPOINT_DATA}{dsn},
		$_[0]->{_ENDPOINT_DATA}{username},
		$_[0]->{_ENDPOINT_DATA}{password},
		$_[0]->{_ENDPOINT_DATA}{options}
	);
}

sub dbh_new {
	return DBI->connect(
		$_[0]->{_ENDPOINT_DATA}{dsn},
		$_[0]->{_ENDPOINT_DATA}{username},
		$_[0]->{_ENDPOINT_DATA}{password},
		$_[0]->{_ENDPOINT_DATA}{options}
	);
}

sub dbh_cached_disconnect {
	$_[0]->disconnect;
	$_[0]->{_ENDPOINT_DATA}{_DBH} = undef;
}


######################################################
## Shortcut
######################################################
sub fw_id { return $_[0]->{_ENDPOINT_DATA}{fw_id} }
sub set_fw_id { $_[0]->{_ENDPOINT_DATA}{fw_id} = $_[1] }


######################################################
## Mapping methods
######################################################
sub _mapping_obj_rule {
	my $self = shift;
	my $dbh = $self->dbh;
	#------------------
	# Build mapping
	my $s = time;
	my $mapping = $self->select_recursive_mapping_obj_rule;
	warn sprintf "[$$]Building mapping obj<->rule: took %.5f ms\n", (time - $s)*1000;
	#------------------
	# Store mapping
	$s = time;
	$self->do_copy_mapping_obj_rule;
	foreach my $obj ( @{$mapping} ) {
		$dbh->pg_putcopydata ( join("\t",@$obj)."\n" );
	}
	$dbh->pg_putcopyend();
	warn sprintf "[$$]Store mapping obj<->rule: took %.5f ms\n", (time - $s)*1000;
}

sub _mapping_obj_rule_nat {
	my $self = shift;
	my $dbh = $self->dbh;
	#------------------
	# Build mapping
	my $s = time;
	my $mapping = $self->select_recursive_mapping_obj_rule_nat;
	warn sprintf "[$$]Building mapping obj<->rule_nat: took %.5f ms\n", (time - $s)*1000;
	#------------------
	# Store mapping
	$s = time;
	$self->do_copy_mapping_obj_rule_nat;
	foreach my $obj ( @{$mapping} ) {
		$dbh->pg_putcopydata ( join("\t",@$obj)."\n" );
	}
	$dbh->pg_putcopyend();
	warn sprintf "[$$]Store mapping obj<->rule_nat: took %.5f ms\n", (time - $s)*1000;
}


######################################################
## Prebuild rules
######################################################
sub _prebuild_rules {
	my $self = shift;
	my $dbh = $self->dbh;
	my $s;
	#------------------
	## Get rules seq list
	$s = time;
	my $result = $self->get_all_rules_seq;	## [ARRAY] rules' sequence numbers
	warn sprintf "[$$]Getting all rules seq: took %.5f ms\n", (time - $s)*1000;
	#------------------
	## Build rules
	$s = time;
	my $rules = $self->build_rules( $result );	## [ARRAY] rules hash structure
	warn sprintf "[$$]Building rules structure: took %.5f ms\n", (time - $s)*1000;
	#------------------
	## Updating rules in Database
	$s = time;
	my $sth = $self->prepare_update_rule_adding_prebuilt;
	foreach my $seq ( keys %$rules ) {
		$sth->execute( $self->fw_id, $seq, encode_json($rules->{$seq}) );
	}
	warn sprintf "[$$]Updating rules table with prebuilt rules: took %.5f ms\n", (time - $s)*1000;
	#------------------
}

######################################################
## Search methods
######################################################
#*************************
## Find Rules matching object (containing it)
#*************************
sub find_rules_matching_ipaddr_or_ipnet_or_range {
	my ( $self, $field, $ipaddr ) = @_;
	my @a = split('-',$ipaddr);
	if ( @a == 2 ) {
		my ( $ipaddr_low, $ipaddr_high ) = @a;
		return [] unless is_valid_ip($ipaddr_low) && is_valid_ip($ipaddr_high);
		return $self->select_rules_matching_iprange( $field, $ipaddr_low, $ipaddr_high );
	} else {
		return [] unless is_valid_ip_or_network($ipaddr);		
		return $self->select_rules_matching_ipaddr_or_ipnet( $field, $ipaddr );
	}
}	# return: array of rules seq

sub find_rules_matching_service_or_servicerange {
	my ( $self, $service ) = @_;
	if ( $service && $service =~ m/^(TCP|UDP)[\-_](\d+)$/i ) {
		return $self->select_rules_matching_service( $1, $2 );
	} elsif ( $service && $service =~ m/^(TCP|UDP)[\-_](\d+)[\-_](\d+)$/i ) {	
		return $self->select_rules_matching_servicerange( $1, $2, $3 );
	} elsif ( $service && $service =~ m/^\d+$/i ) {
		return $self->select_rules_matching_port( $service );
	} elsif ( $service && $service =~ m/^(\d+)[\-_](\d+)$/i ) {	
		return $self->select_rules_matching_portrange( $1, $2 );
	} else {
		return [];
	}
}	# return: array of rules seq

#*************************
## Find Rules with object (exact match)
#*************************
sub find_rules_with_ipaddr_or_ipnet_or_range {
	my ( $self, $field, $ipaddr ) = @_;
	my @a = split('-',$ipaddr);
	if ( @a == 2 ) {
		my ( $ipaddr_low, $ipaddr_high ) = @a;
		return [] unless is_valid_ip($ipaddr_low) && is_valid_ip($ipaddr_high);
		return $self->select_rules_with_iprange( $field, $ipaddr_low, $ipaddr_high );
	} else {
		return [] unless is_valid_ip_or_network($ipaddr);		
		return $self->select_rules_with_ipaddr_or_ipnet( $field, $ipaddr );
	}
}	# return: array of rules seq

sub find_rules_with_service_or_servicerange {
	my ( $self, $service ) = @_;
	if ( $service && $service =~ m/^(TCP|UDP)[\-_](\d+)$/i ) {
		return $self->select_rules_with_service( $1, $2 );
	} elsif ( $service && $service =~ m/^(TCP|UDP)[\-_](\d+)[\-_](\d+)$/i ) {	
		return $self->select_rules_with_servicerange( $1, $2, $3 );
	} elsif ( $service && $service =~ m/^\d+$/i ) {	
		return $self->select_rules_with_port( $service );
	} elsif ( $service && $service =~ m/^(\d+)[\-_](\d+)$/i ) {	
		return $self->select_rules_with_portrange( $1, $2 );
	} else {
		return [];
	}
}	# return: array of rules seq


######################################################
## Get methods
######################################################
sub get_all_rules_seq {
	return $_[0]->select_all_rules_seq;
}

sub get_all_rules {
	return $_[0]->select_all_rules;
}

sub get_rules_from_seq {		## array of rules seq
	return $_[0]->select_rules($_[1]);
}

sub nb_rules {		## nb
	$_[0]->{STATS}{nb_rules} //= $_[0]->select_number_of_rules($_[1]);
	return $_[0]->{STATS}{nb_rules};
}
sub nb_rules_nat {		## nb
	$_[0]->{STATS}{nb_rules_nat} //= $_[0]->select_number_of_rules_nat($_[1]);
	return $_[0]->{STATS}{nb_rules_nat};
}


##################################################################
## BUILD RULES (only used during mapping)
##################################################################
sub build_rules {
	my ( $self, $rules ) = @_;
	return {} unless ref($rules) eq 'ARRAY';
	my (%h, %htmp, %hobj, %hgroup);			## TODO: remove %htmp and only use %obj
	#------------------------------
	## Query all objects matching rules
	my $objects = $self->select_rules_obj($rules);	# [ARRAY] 0:rule_seq, 1:rule_field, 2:obj_id, 3:obj_name, 4:obj_type
	foreach ( @$objects ) {
		push @{ $htmp{$_->[4]} }, $_->[2];			# 4:obj_type, 2:obj_id
		$hobj{$_->[4]}{$_->[2]}{name} = $_->[3];	# 4:obj_type, 2:obj_id, 3:obj_name
		$hobj{$_->[4]}{$_->[2]}{type} = $_->[4];	# 4:obj_type, 2:obj_id, 4:obj_type
	}
	#------------------------------
	## Query object groups
	foreach my $type ( qw( ipgroup ipgroup_with_exclusion servicegroup ) ) {
		next unless $htmp{$type};	## skip if empty
		my $select_func = $type eq 'servicegroup' ? 'select_servicegroup_by_id' : 'select_ipgroup_by_id';
		my $groups = $self->$select_func( $htmp{$type}  );	# [ARRAY] 0:parent_id, 1:obj_type, 2:obj_id, 3:obj_name, 4:obj_negate
		foreach ( @$groups ) {
			push @{$hgroup{$type}{$_->[0]}}, {	# 0:parent_id, 1:obj_type, 2:obj_id, 3:obj_name, 4:obj_negate
				type => $_->[1],
				id => $_->[2],
				name => $_->[3],
				negate => $_->[4]
			};
			next if $_->[1] eq 'ipgroup' || $_->[1] eq 'ipgroup_with_exclusion' || $_->[1] eq 'servicegroup';
			push @{ $htmp{$_->[1]} }, $_->[2];			# 1:obj_type, 2:obj_id 
		}
	}
	#------------------------------
	## Query rules data
	my $rules_data = $self->select_rules_data($rules);
	foreach ( @$rules_data ) {
		my ( $seq, $enable, $section, $action, $logging, $comment ) = @$_;
		$h{$seq} = {
			seq => $seq,
			enable => $enable,
			section => $section,
			action => $action,
			logging => $logging,
			comment => $comment,
		};
	}
	#------------------------------
	## Query objects by type
	foreach my $type ( keys %htmp ) {	# servicegroup, service, ipnet, iprange, ipaddr, ipgroup, servicerange, ipgroup_with_exclusion
		next unless $htmp{$type};
		if ( $type eq 'ipaddr' or $type eq 'ipnet' ) {
			my $a = $self->select_ipaddr_by_id( $htmp{$type} );
			foreach ( @$a ) {				# 0: obj_id, 1: name, 2: value
				push @{$hobj{$type}{$_->[0]}{value}}, $_->[2];
			}
		} elsif ( $type eq 'iprange' ) {
			my $a = $self->select_iprange_by_id( $htmp{$type} );
			foreach ( @$a ) {				# 0: obj_id, 1: name, 2: value 
				push @{$hobj{$type}{$_->[0]}{value}}, $_->[2];
			}
		} elsif ( $type eq 'ipgroup' || $type eq 'ipgroup_with_exclusion' || $type eq 'servicegroup' ) {
			# skip (already done above)
		} elsif ( $type eq 'service' ) {
			my $a = $self->select_service_by_id( $htmp{$type} );
			foreach ( @$a ) {				# 0: obj_id, 1: name, 2: value 
				push @{$hobj{$type}{$_->[0]}{value}}, $_->[2];
			}
		} elsif ( $type eq 'servicerange' ) {
			my $a = $self->select_servicerange_by_id( $htmp{$type} );
			foreach ( @$a ) {				# 0: obj_id, 1: name, 2: value
				push @{$hobj{$type}{$_->[0]}{value}}, $_->[2];
			}
		} else {
			die "Type not handled!\n";
		}
	}
	#------------------------------
	## build groups
	foreach my $type ( qw( ipgroup ipgroup_with_exclusion servicegroup ) ) {
		next unless $hgroup{$type};	## skip if empty
		foreach my $grp_id ( keys %{$hgroup{$type}} ) {
			foreach my $obj ( @{$hgroup{$type}{$grp_id}} ) {		## [HASH] obj_type, obj_id, name, negate
				if ( $obj->{type} eq 'ipgroup' || $obj->{type} eq 'ipgroup_with_exclusion' || $obj->{type} eq 'servicegroup'  ) {	## object is a group
					my $content = $obj->{negate} ? 'content_groups_negate' : 'content_groups';
					push @{$hobj{$type}{$grp_id}{$content}}, $obj->{name};
				} else {			## object is not a group: ipaddr, iprange, service, etc...
					my $content = $obj->{negate} ? 'content_negate' : 'content';
					push @{$hobj{$type}{$grp_id}{$content}}, @{$hobj{$obj->{type}}{$obj->{id}}{value}};
				}
			}
			## sort content
			my $func = $type eq 'servicegroup' ? \&sort_services_inplace : \&sort_ipaddr_inplace;
			$func->( $hobj{$type}{$grp_id}{'content_groups_negate'} ) if $hobj{$type}{$grp_id}{'content_groups_negate'};
			$func->( $hobj{$type}{$grp_id}{'content_groups'} ) if $hobj{$type}{$grp_id}{'content_groups'};
			$func->( $hobj{$type}{$grp_id}{'content_negate'} ) if $hobj{$type}{$grp_id}{'content_negate'};
			$func->( $hobj{$type}{$grp_id}{'content'} ) if $hobj{$type}{$grp_id}{'content'};
		}
	}
	#------------------------------
	## build rules
	foreach ( @$objects ) {			# [ARRAY] 0:rule_seq, 1:rule_field, 2:obj_id, 3:obj_name, 4:obj_type
		push @{ $h{$_->[0]}{$_->[1]} }, $hobj{$_->[4]}{$_->[2]};	# 0:rule_seq, 1:rule_field, 4:obj_type, 2:obj_id
	}
	#------------------------------
	## sort objects in fields by type then value
	foreach my $seq ( keys %h ) {		## foreach rule seq
		foreach my $field ( qw(src dst service target) ) {	## foreach rule's field
			$field eq 'service' ? sort_by_type_then_services_inplace($h{$seq}{'service'}) : sort_by_type_then_ipaddr_inplace($h{$seq}{$field});
		}
	}
	#------------------------------
	return \%h;
}








1;