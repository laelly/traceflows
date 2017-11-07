package Firewall::Vendor::Checkpoint::Endpoint::Database;

use strict;
use warnings;
use base 'Firewall::Endpoint::Database';
use Data::Dumper;				## temporary
use Time::HiRes qw(time);		## temproary
use Firewall::Utils qw(normalize_action_value);

##################################################################
## INITIALIZATION
##################################################################
# $self->_init(%args) --> Firewall::Endpoint::Database


##################################################################
## METHODS
##################################################################
#****************************************
## Database Handler
#****************************************
# $self->dbh --> Firewall::Endpoint::Database


#****************************************
## Store pre/post-processing functions
#****************************************
sub _pre_processing {
	my $self = shift;
	$self->{_ENDPOINT_DATA}{options}{AutoCommit} = 0;		## Disable Autocommit	
	#--------------------------
	## Select, Insert or Update firewall
	my $s = time;
	my $fw_id = $self->_select_firewall_entry ? $self->_update_firewall_entry : $self->_insert_firewall_entry;
	$self->set_fw_id( $fw_id );
	warn sprintf "[$$]UPDATE firewall: took %.5f ms\n", (time - $s)*1000;
	#--------------------------
	## Delete objects
	$s = time;
	$self->delete_all_fw_objects($fw_id);
	warn sprintf "[$$]DELETE objects: took %.5f ms\n", (time - $s)*1000;	
	#--------------------------
	## Delete rules
	$s = time;
	$self->delete_all_fw_rules($fw_id);
	warn sprintf "[$$]DELETE rules: took %.5f ms\n", (time - $s)*1000;	
	#--------------------------
	## Delete rules nat
	$s = time;
	$self->delete_all_fw_rules_nat($fw_id);
	warn sprintf "[$$]DELETE rules nat: took %.5f ms\n", (time - $s)*1000;	
}

sub _post_processing {
	my $self = shift;
	#--------------------------
	my $s = time;
	$self->dbh->commit;
	$self->dbh->disconnect;
	$self->{_ENDPOINT_DATA}{options}{AutoCommit} = 1;		## Re-enable Autocommit
	warn sprintf "[$$]COMMIT: took %.5f ms\n", (time - $s)*1000;
}


#****************************************
## Store methods
#****************************************
sub _store_addresses {
	my ($self, $addresses) = @_;	
	#------------------
	# IPADDR
	my $s = time;
	$self->_store_ipaddr_or_ipnet( $addresses->{ipaddr}, 'ipaddr' );
	warn sprintf "[$$]Store ipaddr: took %.5f ms\n", (time - $s)*1000;
	#------------------
	# IPNET
	$s = time;
	$self->_store_ipaddr_or_ipnet( $addresses->{ipnet}, 'ipnet' );
	warn sprintf "[$$]Store ipnet: took %.5f ms\n", (time - $s)*1000;
	#------------------
	# IPRANGE
	$s = time;
	$self->_store_iprange( $addresses->{iprange} );
	warn sprintf "[$$]Store iprange: took %.5f ms\n", (time - $s)*1000;
	#------------------
	# ipgroup
	$s = time;
	$self->_store_ipgroup( { ipgroup => $addresses->{ipgroup}, ipgroup_with_exclusion => $addresses->{ipgroup_with_exclusion} } );
	warn sprintf "[$$]Store ipgroup: took %.5f ms\n", (time - $s)*1000;
}

sub _store_services {
	my ($self, $services) = @_;	
	#------------------
	# service
	my $s = time;
	$self->_store_service( $services->{service} );
	warn sprintf "[$$]Store service: took %.5f ms\n", (time - $s)*1000;	
	#------------------
	# servicerange
	$s = time;
	$self->_store_servicerange( $services->{servicerange} );
	warn sprintf "[$$]Store servicerange: took %.5f ms\n", (time - $s)*1000;	
	#------------------
	# servicegroup
	$s = time;
	$self->_store_servicegroup( $services->{servicegroup} );
	warn sprintf "[$$]Store servicegroup: took %.5f ms\n", (time - $s)*1000;
}

sub _store_rules {
	my ($self, $data) = @_;
	my $fw_id = $self->fw_id;
	my $dbh = $self->dbh;
	my ($h_obj, $h_rule);
	#-------------------
	## Store rules
	$self->do_copy_rule;
	foreach my $obj ( @{$data->{rule}} ) {
		$dbh->pg_putcopydata (
			$fw_id."\t".
			$obj->{seq}."\t".
			$obj->{enable}."\t".
			$obj->{is_global_rule}."\t".
			$obj->{section}."\t".
			normalize_action_value($obj->{action})."\t".
			$obj->{schedule}."\t".
			$obj->{logging}."\t".
			$obj->{comment}."\n"
		);
	}
	$dbh->pg_putcopyend();
	#-------------------
	## Get id list
	$h_obj = $self->select_all_fw_objects_on_uid;
	$h_rule = $self->select_all_fw_rules_on_seq;
	#-------------------
	## Store rules objects
	$self->do_copy_rule_obj;
	foreach my $obj ( @{$data->{rule}} ) {
		foreach my $field ( keys %$obj ) {
			next unless ref($obj->{$field}) eq 'ARRAY';		# keep only src dst service
			foreach my $c ( @{$obj->{$field}} ) {
				$dbh->pg_putcopydata (
					$h_rule->{$obj->{seq}}{id}."\t".
					$field."\t".
					($h_obj->{$c}{id}||'null')."\n"
				);
			}
		}
	}
	$dbh->pg_putcopyend();
}

sub _store_rules_nat {
	my ($self, $data) = @_;	
	my $fw_id = $self->fw_id;
	my $dbh = $self->dbh;
	my ($h_obj, $h_rule);
	#-------------------
	## Store rules
	$self->do_copy_rule_nat;
	foreach my $obj ( @{$data->{rule}} ) {
		$dbh->pg_putcopydata (
			$fw_id."\t".
			$obj->{seq}."\t".
			$obj->{enable}."\t".
			$obj->{is_global_rule}."\t".
			($obj->{section}||'NULL')."\t".
			$obj->{comment}."\n"
		);
	}
	$dbh->pg_putcopyend();
	#-------------------
	## Get id list
	$h_obj = $self->select_all_fw_objects_on_uid;
	$h_rule = $self->select_all_fw_rules_nat_on_seq;
	#-------------------
	## Store rules objects
	$self->do_copy_rule_nat_obj;
	foreach my $obj ( @{$data->{rule}} ) {
		foreach my $field ( keys %$obj ) {
			next unless ref($obj->{$field}) eq 'ARRAY';		# keep only src src_nat dst dst_nat service service_nat
			foreach my $c ( @{$obj->{$field}} ) {
				$dbh->pg_putcopydata (
					$h_rule->{$obj->{seq}}{id}."\t".
					$field."\t".
					($h_obj->{$c}{id}||'null')."\n"
				);
			}
		}
	}
	$dbh->pg_putcopyend();
}


#****************************************
## Store submethods
#****************************************
sub _store_ipaddr_or_ipnet {
	my ($self, $data, $type) = @_;	
	my $fw_id = $self->fw_id;
	my $dbh = $self->dbh;
	my $h;
	#-------------------
	## Store Objects
	$self->do_copy_object;
	foreach my $obj ( @{$data} ) {
		$dbh->pg_putcopydata (
			$fw_id."\t".
			$type."\t".
			$obj->{name}."\t".
			$obj->{uid}."\n"
		);
	}
	$dbh->pg_putcopyend();
	#-------------------
	## Get id list
	$h = $self->select_object_id_name_by_fw_and_type($fw_id,$type);
	#-------------------
	## Store IPADDR
	$self->do_copy_ipaddr;
	foreach my $obj ( @{$data} ) {
		$dbh->pg_putcopydata (
			$h->{$obj->{name}}{id}."\t".
			($obj->{ipaddr}||'null')."\n"
		);
	}
	$dbh->pg_putcopyend();
}

sub _store_iprange {
	my ($self, $data) = @_;	
	my $fw_id = $self->fw_id;
	my $dbh = $self->dbh;
	my $h;
	#-------------------
	## Store Objects
	$self->do_copy_object;
	foreach my $obj ( @{$data} ) {
		$dbh->pg_putcopydata (
			$fw_id."\t".
			"iprange\t".
			$obj->{name}."\t".
			$obj->{uid}."\n"
		);
	}
	$dbh->pg_putcopyend();
	#-------------------
	## Get id list
	$h = $self->select_object_id_name_by_fw_and_type($fw_id,'iprange');
	#-------------------
	## Store IPRANGE
	$self->do_copy_iprange;
	foreach my $obj ( @{$data} ) {
		$dbh->pg_putcopydata (
			$h->{$obj->{name}}{id}."\t".
			($obj->{ipaddr_low}||'null')."\t".
			($obj->{ipaddr_high}||'null')."\n"
		);
	}
	$dbh->pg_putcopyend();
}

sub _store_ipgroup {
	my ($self, $data) = @_;	
	my $fw_id = $self->fw_id;
	my $dbh = $self->dbh;
	my $h;
	#-------------------	
	## Store Objects
	$self->do_copy_object;
	foreach my $type ( qw( ipgroup ipgroup_with_exclusion ) ) {
		foreach my $obj ( @{$data->{$type}} ) {
			$dbh->pg_putcopydata (
				$fw_id."\t".
				$type."\t".
				$obj->{name}."\t".
				$obj->{uid}."\n"
			);
		}
	}
	$dbh->pg_putcopyend();
	#-------------------
	## Get all objects list
	$h = $self->select_all_fw_objects_on_uid;
	#-------------------
	## Store IPGROUP
	$self->do_copy_ipgroup;
	foreach my $type ( qw( ipgroup ipgroup_with_exclusion ) ) {
		foreach my $obj ( @{$data->{$type}} ) {
			foreach my $c ( @{$obj->{content}} ) {
				$dbh->pg_putcopydata (
					$h->{$obj->{uid}}{id}."\t".
					"content\t".
					($h->{$c}{id}||'null')."\n"
				);
			}
			foreach my $c ( @{$obj->{exclusion}} ) {
				$dbh->pg_putcopydata (
					$h->{$obj->{uid}}{id}."\t".
					"exclusion\t".
					($h->{$c}{id}||'null')."\n"
				);
			}
		}
	}
	$dbh->pg_putcopyend();	
}
	
sub _store_service {
	my ($self, $data) = @_;	
	my $fw_id = $self->fw_id;
	my $dbh = $self->dbh;
	my $h;
	#-------------------
	## Store Objects
	$self->do_copy_object;
	foreach my $obj ( @{$data} ) {
		$dbh->pg_putcopydata (
			$fw_id."\t".
			"service\t".
			$obj->{name}."\t".
			$obj->{uid}."\n"
		);
	}
	$dbh->pg_putcopyend();
	#-------------------
	## Get id list
	$h = $self->select_object_id_name_by_fw_and_type($fw_id,'service');
	#-------------------
	## Store SERVICE
	$self->do_copy_service;
	foreach my $obj ( @{$data} ) {
		foreach my $c ( @{$obj->{content}} ) {
			$dbh->pg_putcopydata (
				$h->{$obj->{name}}{id}."\t".
				($c->{protocol}||'null')."\t".
				($c->{port}||'null')."\n"
			);
		}
		$dbh->pg_putcopydata( $h->{$obj->{name}}{id}."\tnull\tnull\n" ) unless @{$obj->{content}};	## for empty services
	}
	$dbh->pg_putcopyend();
}

sub _store_servicerange {
	my ($self, $data) = @_;	
	my $fw_id = $self->fw_id;
	my $dbh = $self->dbh;
	my $h;
	#-------------------
	## Store Objects
	$self->do_copy_object;
	foreach my $obj ( @{$data} ) {
		$dbh->pg_putcopydata (
			$fw_id."\t".
			"servicerange\t".
			$obj->{name}."\t".
			$obj->{uid}."\n"
		);
	}
	$dbh->pg_putcopyend();
	#-------------------
	## Get id list
	$h = $self->select_object_id_name_by_fw_and_type($fw_id,'servicerange');
	#-------------------
	## Store SERVICERANGE
	$self->do_copy_servicerange;
	foreach my $obj ( @{$data} ) {
		foreach my $c ( @{$obj->{content}} ) {
			$dbh->pg_putcopydata (
				$h->{$obj->{name}}{id}."\t".
				($c->{protocol}||'null')."\t".
				($c->{port_low}||'null')."\t".
				($c->{port_high}||'null')."\n"
			);
		}
	}
	$dbh->pg_putcopyend();
}

sub _store_servicegroup {
	my ($self, $data) = @_;	
	my $fw_id = $self->fw_id;
	my $dbh = $self->dbh;
	my $h;
	#-------------------
	## Store Objects
	$self->do_copy_object;
	foreach my $obj ( @{$data} ) {
		$dbh->pg_putcopydata (
			$fw_id."\t".
			"servicegroup\t".
			$obj->{name}."\t".
			$obj->{uid}."\n"
		);
	}
	$dbh->pg_putcopyend();
	#-------------------
	## Get id list
	$h = $self->select_all_fw_objects_on_uid;
	#-------------------
	## Store SERVICEGROUP	
	$self->do_copy_servicegroup;
	foreach my $obj ( @{$data} ) {
		foreach my $c ( @{$obj->{content}} ) {
			$dbh->pg_putcopydata (
				$h->{$obj->{uid}}{id}."\t".
				"content\t".
				($h->{$c}{id}||'null')."\n"
			);
		}
	}
	$dbh->pg_putcopyend();
}


#****************************************
## Mapping
#****************************************
# $self->_mapping_obj_rule		--> Firewall::Endpoint::Database
# $self->_mapping_obj_rule_nat	--> Firewall::Endpoint::Database





1;