package Firewall::Endpoint::Database::Queries;

use strict;
use warnings;


######################################################################################################################
######################################################################################################################
########### GENERIC
######################################################################################################################
##################################################################
## FIREWALL
##################################################################
sub select_firewall {
	my ($self, $fw_name, $fw_type) = @_;
	# VALUES: name, type, class
my $SQL = <<_SQL_;
SELECT
	id
FROM firewall
WHERE
	name = ? AND
	type = ?;
_SQL_
	return $self->dbh->selectcol_arrayref( $SQL, {}, $fw_name, $fw_type )->[0];
}

sub insert_firewall {
	my ($self, $fw_name, $fw_type, $fw_class) = @_;
	# VALUES: name, type, class
my $SQL = <<_SQL_;
INSERT INTO firewall(
	name,
	type,
	class
) VALUES (?, ?, ?)
RETURNING id;
_SQL_
	return $self->dbh->selectcol_arrayref( $SQL, {}, $fw_name, $fw_type, $fw_class )->[0];
}

sub update_firewall {
	my ($self, $fw_name, $fw_type, $fw_class) = @_;
	# VALUES: class, name, type 
my $SQL = <<_SQL_;
UPDATE firewall SET
	date_modification = NOW(),
	class = ?
WHERE
	name = ? AND
	type = ?
RETURNING id;
_SQL_
	return $self->dbh->selectcol_arrayref( $SQL, {}, $fw_class, $fw_name, $fw_type )->[0];
}


######################################################################################################################
######################################################################################################################
########### Methods used for building the firewall's database
######################################################################################################################
##################################################################
## PREPARE: DELETE
##################################################################
sub delete_all_fw_objects {
	my ($self,$fw_id) = @_;
	my $dbh = $self->dbh;
	# VALUES: fw_id
	my $SQL = <<_SQL_;
DELETE
FROM objects
WHERE fw_id = ?;
_SQL_
	my $sth = $dbh->prepare( $SQL );
	$sth->execute($fw_id);
	$sth->finish;
}

sub delete_all_fw_rules {
	my ($self,$fw_id) = @_;
	my $dbh = $self->dbh;
	# VALUES: fw_id
	my $SQL = <<_SQL_;
DELETE
FROM rules
WHERE fw_id = ?;
_SQL_
	my $sth = $dbh->prepare( $SQL );
	$sth->execute($fw_id);
	$sth->finish;
}

sub delete_all_fw_rules_nat {
	my ($self,$fw_id) = @_;
	my $dbh = $self->dbh;
	# VALUES: fw_id
	my $SQL = <<_SQL_;
DELETE
FROM rules_nat
WHERE fw_id = ?;
_SQL_
	my $sth = $dbh->prepare( $SQL );
	$sth->execute($fw_id);
	$sth->finish;
}


##################################################################
## SELECT
##################################################################
sub select_object_id_name_by_fw_and_type {
	my ($self, @val) = @_;
	# VALUES: fw_id, type
my $SQL = <<_SQL_;
SELECT
	id,
	name
FROM objects
WHERE fw_id = ? AND type = ?
_SQL_
	return $self->dbh->selectall_hashref( $SQL, 'name', {}, @val );
}

sub select_all_fw_objects_on_name {
	my $self = shift;
	# VALUES: fw_id, type
my $SQL = <<_SQL_;
SELECT
	id,
	name
FROM objects
WHERE fw_id = ?
_SQL_
	return $self->dbh->selectall_hashref( $SQL, 'name', {}, $self->fw_id );
}

sub select_all_fw_objects_on_uid {
	my $self = shift;
	# VALUES: fw_id
my $SQL = <<_SQL_;
SELECT
	id,
	uid
FROM objects
WHERE fw_id = ?
_SQL_
	return $self->dbh->selectall_hashref( $SQL, 'uid', {}, $self->fw_id );
}

sub select_all_fw_rules_on_seq {
	my $self = shift;
	# VALUES: fw_id
my $SQL = <<_SQL_;
SELECT
	id,
	seq
FROM rules
WHERE fw_id = ?
_SQL_
	return $self->dbh->selectall_hashref( $SQL, 'seq', {}, $self->fw_id );
}

sub select_all_fw_rules_nat_on_seq {
	my $self = shift;
	# VALUES: fw_id
my $SQL = <<_SQL_;
SELECT
	id,
	seq
FROM rules_nat
WHERE fw_id = ?
_SQL_
	return $self->dbh->selectall_hashref( $SQL, 'seq', {}, $self->fw_id );
}


##################################################################
## SELECT RECURSIVE
##################################################################
sub select_recursive_mapping_obj_rule {
	my ( $self, $nat ) = @_;
	# VALUES: fw_id
my $rules_table = $nat ? 'rules_nat' : 'rules';
my $rulesobj_table = $nat ? 'rules_nat_obj' : 'rules_obj';
my $SQL = <<_SQL_;
WITH RECURSIVE ipgroup_content AS (
	SELECT
		oipg.obj_id AS parent_id,
		o2.id AS id,
		CASE WHEN oipg.field = 'exclusion' THEN TRUE
			 ELSE FALSE END as negate
	FROM obj_ipgroup oipg
	LEFT JOIN objects o2 ON o2.id = oipg.field_obj_id
	UNION
	SELECT
		oc.parent_id AS parent_id,
		o2.id AS id,
		oc.negate AS negate
	FROM obj_ipgroup oipg
	LEFT JOIN objects o2 ON o2.id = oipg.field_obj_id 
	INNER JOIN ipgroup_content oc ON oc.id = oipg.obj_id
),
servicegroup_content AS (
	SELECT
		osg.obj_id AS parent_id,
		o2.id AS id,
		CASE WHEN osg.field = 'exclusion' THEN TRUE
			 ELSE FALSE END as negate
	FROM obj_servicegroup osg
	LEFT JOIN objects o2 ON o2.id = osg.field_obj_id
	UNION
	SELECT
		oc.parent_id AS parent_id,
		o2.id AS id,
		oc.negate AS negate
	FROM obj_servicegroup osg
	LEFT JOIN objects o2 ON o2.id = osg.field_obj_id 
	INNER JOIN servicegroup_content oc ON oc.id = osg.obj_id
),
rule AS (
	SELECT
		ro.rule_id,
		ro.field,
		ro.field_obj_id AS obj_id,
		ro.negate
	FROM ${rulesobj_table} ro
	INNER JOIN ${rules_table} r ON r.id = ro.rule_id
	WHERE r.fw_id = ?
)
SELECT DISTINCT	
	id AS obj_id,
	field,
	rule_id,
	negate
FROM (
	SELECT
		ipgc.id,
		r.field,
		r.rule_id,
		CASE WHEN ipgc.negate THEN TRUE
			 ELSE r.negate END AS negate
	FROM rule r
	INNER JOIN ipgroup_content ipgc ON r.obj_id = ipgc.parent_id
	UNION
		SELECT
			sgc.id,
			r.field,
			r.rule_id,
			CASE WHEN sgc.negate THEN TRUE
				 ELSE r.negate END AS negate
		FROM rule r
		INNER JOIN servicegroup_content sgc ON r.obj_id = sgc.parent_id
	UNION
		SELECT
			o.id,
			r.field,
			r.rule_id,
			r.negate
		FROM rule r
		INNER JOIN objects o ON r.obj_id = o.id
) AS q1
_SQL_
	return $self->dbh->selectall_arrayref( $SQL, {}, $self->fw_id );

}
sub select_recursive_mapping_obj_rule_nat { $_[0]->select_recursive_mapping_obj_rule( 'nat' ) }


##################################################################
## DO: COPY
##################################################################
#*************************
## OBJECT
#*************************
sub do_copy_object {
	my ($self) = @_;
	# VALUES: fw_id, type, name, uid
my $SQL = <<_SQL_;
COPY objects (
	fw_id,
	type,
	name,
	uid
) FROM STDIN
_SQL_
	$self->dbh->do( $SQL );
}

#*************************
## IPADDR
#*************************
sub do_copy_ipaddr {
	my ($self) = @_;
	# VALUES: obj_id, ipaddr
my $SQL = <<_SQL_;
COPY obj_ipaddr (
	obj_id,
	ipaddr
) FROM STDIN
WITH NULL AS 'null'
_SQL_
	$self->dbh->do( $SQL );
}

sub do_copy_iprange {
	my ($self) = @_;
	# VALUES: obj_id, ipaddr_low, ipaddr_high
my $SQL = <<_SQL_;
COPY obj_ipaddr (
	obj_id,
	ipaddr_low,
	ipaddr_high
) FROM STDIN
WITH NULL AS 'null'
_SQL_
	$self->dbh->do( $SQL );
}

sub do_copy_ipgroup {
	my ($self) = @_;
	# VALUES: obj_id, field, field_obj_id
my $SQL = <<_SQL_;
COPY obj_ipgroup (
	obj_id,
	field,
	field_obj_id
) FROM STDIN
WITH NULL AS 'null'
_SQL_
	$self->dbh->do( $SQL );
}

#*************************
## SERVICES
#*************************
sub do_copy_service {
	my ($self) = @_;
	# VALUES: obj_id, protocol, port
my $SQL = <<_SQL_;
COPY obj_service (
	obj_id,
	protocol,
	port
) FROM STDIN
WITH NULL AS 'null'
_SQL_
	$self->dbh->do( $SQL );
}

sub do_copy_servicerange {
	my ($self) = @_;
	# VALUES: obj_id, protocol, port_low, port_high
my $SQL = <<_SQL_;
COPY obj_service (
	obj_id,
	protocol,
	port_low,
	port_high
) FROM STDIN
WITH NULL AS 'null'
_SQL_
	$self->dbh->do( $SQL );
}

sub do_copy_servicegroup {
	my ($self) = @_;
	# VALUES: obj_id, field, field_obj_id
my $SQL = <<_SQL_;
COPY obj_servicegroup (
	obj_id,
	field,
	field_obj_id
) FROM STDIN
WITH NULL AS 'null'
_SQL_
	$self->dbh->do( $SQL );
}

#*************************
## RULES
#*************************
sub do_copy_rule {
	my ($self) = @_;
	# VALUES: fw_id, seq, enable, is_global_rule, section, action, schedule, logging, comment
my $SQL = <<_SQL_;
COPY rules (
	fw_id,
	seq,
	enable,
	is_global_rule,
	section,
	action,
	schedule,
	logging,
	comment
) FROM STDIN
WITH NULL AS 'null'
_SQL_
	$self->dbh->do( $SQL );
}

sub do_copy_rule_obj {
	my ($self) = @_;
	# VALUES: rule_id, field, field_obj_id
my $SQL = <<_SQL_;
COPY rules_obj (
	rule_id,
	field,
	field_obj_id
) FROM STDIN
WITH NULL AS 'null'
_SQL_
	$self->dbh->do( $SQL );
}

#*************************
## RULES NAT
#*************************
sub do_copy_rule_nat {
	my ($self) = @_;
	# VALUES: fw_id, seq, enable, is_global_rule, section, comment
my $SQL = <<_SQL_;
COPY rules_nat (
	fw_id,
	seq,
	enable,
	is_global_rule,
	section,
	comment
) FROM STDIN
WITH NULL AS 'null'
_SQL_
	$self->dbh->do( $SQL );
}

sub do_copy_rule_nat_obj {
	my ($self) = @_;
	# VALUES: rule_id, field, field_obj_id
my $SQL = <<_SQL_;
COPY rules_nat_obj (
	rule_id,
	field,
	field_obj_id
) FROM STDIN
WITH NULL AS 'null'
_SQL_
	$self->dbh->do( $SQL );
}


##################################################################
## MAPPING
##################################################################
sub do_copy_mapping_obj_rule {
	my ($self,$nat) = @_;
	# VALUES: obj_id, field, rule_id, negate
my $table = $nat ? 'mapping_obj_rule_nat' : 'mapping_obj_rule';
my $SQL = <<_SQL_;
COPY ${table} (
	obj_id,
	field,
	rule_id,
	negate
) FROM STDIN
WITH NULL AS 'null'
_SQL_
	$self->dbh->do( $SQL );
}

sub do_copy_mapping_obj_rule_nat { $_[0]->do_copy_mapping_obj_rule('nat') }


##################################################################
## PREPARE: UPDATE
##################################################################
#*************************
## RULES
#*************************
sub prepare_update_rule_adding_prebuilt {
	# VALUES: fw_id, seq, prebuilt
my $SQL = <<_SQL_;
UPDATE rules SET
	prebuilt = \$3
WHERE
	fw_id = \$1 AND
	seq = \$2
;
_SQL_
	return $_[0]->dbh->prepare( $SQL );
}


######################################################################################################################
######################################################################################################################
########### Methods used for searches
######################################################################################################################
##################################################################
## SELECT
##################################################################
#*************************
## Find Rules matching object (containing it)
#*************************
sub select_rules_matching_ipaddr_or_ipnet {
	my ( $self, $field , $ipaddr) = @_;
	# VALUES: fw_id, ipaddr
my $SQL = <<_SQL_;
WITH matched_rules AS (
	SELECT DISTINCT
		mor.rule_id,
		mor.negate
	FROM obj_ipaddr oip
	INNER JOIN objects o ON o.id = oip.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = oip.obj_id
	WHERE o.fw_id = \$1 AND
		  mor.field = \$2 AND (
			( oip.ipaddr >>= \$3 ) OR
			( oip.ipaddr_low <= \$3 AND oip.ipaddr_high >= \$3  )
		  )
),
rules_with_obj_with_exclusion AS (
	SELECT
		mor.rule_id
	FROM mapping_obj_rule mor
	INNER JOIN objects o ON o.id = mor.obj_id
	WHERE o.fw_id = \$1 AND
		  mor.field = \$2 AND
		  o.type = 'ipgroup_with_exclusion'
),
rules_with_negate AS (
	SELECT 
		mor.rule_id
	FROM mapping_obj_rule mor
	INNER JOIN objects o ON o.id = mor.obj_id
	WHERE o.fw_id = \$1 AND
		  mor.field = \$2 AND
		  mor.negate AND
		  mor.rule_id NOT IN ( SELECT * FROM rules_with_obj_with_exclusion )
),
matched_rules_with_negate AS (
	SELECT DISTINCT
		mor.rule_id
	FROM obj_ipaddr oip
	INNER JOIN objects o ON o.id = oip.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = oip.obj_id
	WHERE mor.rule_id IN ( SELECT * FROM rules_with_negate ) AND (
			( oip.ipaddr >>= \$3 ) OR
			( oip.ipaddr_low <= \$3 AND oip.ipaddr_high >= \$3  )
		  )
)
SELECT
	r.seq
FROM (
	SELECT
		rule_id
	FROM matched_rules
	WHERE NOT negate 
	EXCEPT
	SELECT
		rule_id
	FROM matched_rules
	WHERE negate
	UNION
	SELECT
		rule_id
	FROM rules_with_negate
	EXCEPT
	SELECT
		rule_id
	FROM matched_rules_with_negate
) q1
INNER JOIN rules r ON q1.rule_id = r.id
_SQL_
	return $self->dbh->selectcol_arrayref( $SQL, {}, $self->fw_id, $field, $ipaddr );		# array of rules id
}

sub select_rules_matching_iprange {
	my ( $self, $field, $ipaddr_low, $ipaddr_high ) = @_;
	# VALUES: fw_id, ipaddr_low, ipaddr_high
my $SQL = <<_SQL_;
WITH matched_rules AS (
	SELECT DISTINCT
		mor.rule_id,
		mor.negate
	FROM obj_ipaddr oip
	INNER JOIN objects o ON o.id = oip.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = oip.obj_id
	WHERE o.fw_id = \$1 AND
		  mor.field = \$2 AND (
			( oip.ipaddr >>= \$3 AND oip.ipaddr >>= \$4 ) OR
			( oip.ipaddr_low <= \$3 AND oip.ipaddr_high >= \$4  )
		  ) AND
		  inet(\$3) <= inet(\$4)
),
rules_with_obj_with_exclusion AS (
	SELECT
		mor.rule_id
	FROM mapping_obj_rule mor
	INNER JOIN objects o ON o.id = mor.obj_id
	WHERE o.fw_id = \$1 AND
		  mor.field = \$2 AND
		  o.type = 'ipgroup_with_exclusion'
),
rules_with_negate AS (
	SELECT 
		mor.rule_id
	FROM mapping_obj_rule mor
	INNER JOIN objects o ON o.id = mor.obj_id
	WHERE o.fw_id = \$1 AND
		  mor.field = \$2 AND
		  mor.negate AND
		  mor.rule_id NOT IN ( SELECT * FROM rules_with_obj_with_exclusion )
),
matched_rules_with_negate AS (
	SELECT DISTINCT
		mor.rule_id
	FROM obj_ipaddr oip
	INNER JOIN objects o ON o.id = oip.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = oip.obj_id
	WHERE mor.rule_id IN ( SELECT * FROM rules_with_negate ) AND (
			( oip.ipaddr >>= \$3 AND oip.ipaddr >>= \$4 ) OR
			( oip.ipaddr_low <= \$3 AND oip.ipaddr_high >= \$4  )
		  ) AND
		  inet(\$3) <= inet(\$4)
)
SELECT
	r.seq
FROM (
	SELECT
		rule_id
	FROM matched_rules
	WHERE NOT negate 
	EXCEPT
	SELECT
		rule_id
	FROM matched_rules
	WHERE negate
	UNION
	SELECT
		rule_id
	FROM rules_with_negate
	EXCEPT
	SELECT
		rule_id
	FROM matched_rules_with_negate
) q1
INNER JOIN rules r ON q1.rule_id = r.id
_SQL_
	return $self->dbh->selectcol_arrayref( $SQL, {}, $self->fw_id, $field, $ipaddr_low, $ipaddr_high );		# array of rules id
}

sub select_rules_matching_service {
	my ( $self, $protocol, $port ) = @_;
	# VALUES: fw_id, port
my $SQL = <<_SQL_;
WITH matched_rules AS (
	SELECT DISTINCT
		mor.rule_id,
		mor.negate
	FROM obj_service os
	INNER JOIN objects o ON o.id = os.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = os.obj_id
	WHERE o.fw_id = \$1 AND
		  os.protocol = \$2 AND
		  mor.field = 'service' AND (
			( os.port = \$3 ) OR
			( os.port_low <= \$3 AND os.port_high >= \$3 )
		  )
),
rules_with_obj_with_exclusion AS (
	SELECT
		mor.rule_id
	FROM mapping_obj_rule mor
	INNER JOIN objects o ON o.id = mor.obj_id
	INNER JOIN obj_service os ON o.id = os.obj_id
	WHERE o.fw_id = \$1 AND
		  os.protocol = \$2 AND
		  mor.field = 'service' AND
		  o.type = 'servicegroup_with_exclusion'
),
rules_with_negate AS (
	SELECT 
		mor.rule_id
	FROM mapping_obj_rule mor
	INNER JOIN objects o ON o.id = mor.obj_id
	INNER JOIN obj_service os ON o.id = os.obj_id
	WHERE o.fw_id = \$1 AND
		  os.protocol = \$2 AND
		  mor.field = 'service' AND
		  mor.negate AND
		  mor.rule_id NOT IN ( SELECT * FROM rules_with_obj_with_exclusion )
),
matched_rules_with_negate AS (
	SELECT DISTINCT
		mor.rule_id
	FROM obj_service os
	INNER JOIN objects o ON o.id = os.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = os.obj_id
	WHERE mor.rule_id IN ( SELECT * FROM rules_with_negate ) AND (
			( os.port = \$3 ) OR
			( os.port_low <= \$3 AND os.port_high >= \$3 )
		  )
)
SELECT
	r.seq
FROM (
	SELECT
		rule_id
	FROM matched_rules
	WHERE NOT negate 
	EXCEPT
	SELECT
		rule_id
	FROM matched_rules
	WHERE negate
	UNION
	SELECT
		rule_id
	FROM rules_with_negate
	EXCEPT
	SELECT
		rule_id
	FROM matched_rules_with_negate
) q1
INNER JOIN rules r ON q1.rule_id = r.id
_SQL_
	return $self->dbh->selectcol_arrayref( $SQL, {}, $self->fw_id, $protocol, $port );		# array of rules id
}

sub select_rules_matching_port {
	my ( $self, $port ) = @_;
	# VALUES: fw_id, port
my $SQL = <<_SQL_;
WITH matched_rules AS (
	SELECT DISTINCT
		mor.rule_id,
		mor.negate
	FROM obj_service os
	INNER JOIN objects o ON o.id = os.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = os.obj_id
	WHERE o.fw_id = \$1 AND
		  mor.field = 'service' AND (
			( os.port = \$2 ) OR
			( os.port_low <= \$2 AND os.port_high >= \$2 )
		  )
),
rules_with_obj_with_exclusion AS (
	SELECT
		mor.rule_id
	FROM mapping_obj_rule mor
	INNER JOIN objects o ON o.id = mor.obj_id
	INNER JOIN obj_service os ON o.id = os.obj_id
	WHERE o.fw_id = \$1 AND
		  mor.field = 'service' AND
		  o.type = 'servicegroup_with_exclusion'
),
rules_with_negate AS (
	SELECT 
		mor.rule_id
	FROM mapping_obj_rule mor
	INNER JOIN objects o ON o.id = mor.obj_id
	INNER JOIN obj_service os ON o.id = os.obj_id
	WHERE o.fw_id = \$1 AND
		  mor.field = 'service' AND
		  mor.negate AND
		  mor.rule_id NOT IN ( SELECT * FROM rules_with_obj_with_exclusion )
),
matched_rules_with_negate AS (
	SELECT DISTINCT
		mor.rule_id
	FROM obj_service os
	INNER JOIN objects o ON o.id = os.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = os.obj_id
	WHERE mor.rule_id IN ( SELECT * FROM rules_with_negate ) AND (
			( os.port = \$2 ) OR
			( os.port_low <= \$2 AND os.port_high >= \$2 )
		  )
)
SELECT
	r.seq
FROM (
	SELECT
		rule_id
	FROM matched_rules
	WHERE NOT negate 
	EXCEPT
	SELECT
		rule_id
	FROM matched_rules
	WHERE negate
	UNION
	SELECT
		rule_id
	FROM rules_with_negate
	EXCEPT
	SELECT
		rule_id
	FROM matched_rules_with_negate
) q1
INNER JOIN rules r ON q1.rule_id = r.id
_SQL_
	return $self->dbh->selectcol_arrayref( $SQL, {}, $self->fw_id, $port );		# array of rules id
}

sub select_rules_matching_servicerange {
	my ( $self, $protocol, $port_low, $port_high ) = @_;
	# VALUES: fw_id, protocol, port_low, port_high
my $SQL = <<_SQL_;
WITH matched_rules AS (
	SELECT DISTINCT
		mor.rule_id,
		mor.negate
	FROM obj_service os
	INNER JOIN objects o ON o.id = os.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = os.obj_id
	WHERE o.fw_id = \$1 AND
		  os.protocol = \$2 AND
		  mor.field = 'service' AND
		  os.port_low <= \$3 AND
		  os.port_high >= \$4 AND
		  \$3 < \$4
),
rules_with_obj_with_exclusion AS (
	SELECT
		mor.rule_id
	FROM mapping_obj_rule mor
	INNER JOIN objects o ON o.id = mor.obj_id
	INNER JOIN obj_service os ON o.id = os.obj_id
	WHERE o.fw_id = \$1 AND
		  os.protocol = \$2 AND
		  mor.field = 'service' AND
		  o.type = 'servicegroup_with_exclusion'
),
rules_with_negate AS (
	SELECT 
		mor.rule_id
	FROM mapping_obj_rule mor
	INNER JOIN objects o ON o.id = mor.obj_id
	INNER JOIN obj_service os ON o.id = os.obj_id
	WHERE o.fw_id = \$1 AND
		  os.protocol = \$2 AND
		  mor.field = 'service' AND
		  mor.negate AND
		  mor.rule_id NOT IN ( SELECT * FROM rules_with_obj_with_exclusion )
),
matched_rules_with_negate AS (
	SELECT DISTINCT
		mor.rule_id
	FROM obj_service os
	INNER JOIN objects o ON o.id = os.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = os.obj_id
	WHERE mor.rule_id IN ( SELECT * FROM rules_with_negate ) AND
		  os.port_low <= \$3 AND
		  os.port_high >= \$4 AND
		  \$3 < \$4
)
SELECT
	r.seq
FROM (
	SELECT
		rule_id
	FROM matched_rules
	WHERE NOT negate 
	EXCEPT
	SELECT
		rule_id
	FROM matched_rules
	WHERE negate
	UNION
	SELECT
		rule_id
	FROM rules_with_negate
	EXCEPT
	SELECT
		rule_id
	FROM matched_rules_with_negate
) q1
INNER JOIN rules r ON q1.rule_id = r.id
_SQL_
	return $self->dbh->selectcol_arrayref( $SQL, {}, $self->fw_id, $protocol, $port_low, $port_high );		# array of rules id
}

sub select_rules_matching_portrange {
	my ( $self, $port_low, $port_high ) = @_;
	# VALUES: fw_id, port_low, port_high
my $SQL = <<_SQL_;
WITH matched_rules AS (
	SELECT DISTINCT
		mor.rule_id,
		mor.negate
	FROM obj_service os
	INNER JOIN objects o ON o.id = os.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = os.obj_id
	WHERE o.fw_id = \$1 AND
		  mor.field = 'service' AND
		  os.port_low <= \$2 AND
		  os.port_high >= \$3 AND
		  \$2 < \$3
),
rules_with_obj_with_exclusion AS (
	SELECT
		mor.rule_id
	FROM mapping_obj_rule mor
	INNER JOIN objects o ON o.id = mor.obj_id
	INNER JOIN obj_service os ON o.id = os.obj_id
	WHERE o.fw_id = \$1 AND
		  mor.field = 'service' AND
		  o.type = 'servicegroup_with_exclusion'
),
rules_with_negate AS (
	SELECT 
		mor.rule_id
	FROM mapping_obj_rule mor
	INNER JOIN objects o ON o.id = mor.obj_id
	INNER JOIN obj_service os ON o.id = os.obj_id
	WHERE o.fw_id = \$1 AND
		  mor.field = 'service' AND
		  mor.negate AND
		  mor.rule_id NOT IN ( SELECT * FROM rules_with_obj_with_exclusion )
),
matched_rules_with_negate AS (
	SELECT DISTINCT
		mor.rule_id
	FROM obj_service os
	INNER JOIN objects o ON o.id = os.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = os.obj_id
	WHERE mor.rule_id IN ( SELECT * FROM rules_with_negate ) AND
		  os.port_low <= \$2 AND
		  os.port_high >= \$3 AND
		  \$2 < \$3
)
SELECT
	r.seq
FROM (
	SELECT
		rule_id
	FROM matched_rules
	WHERE NOT negate 
	EXCEPT
	SELECT
		rule_id
	FROM matched_rules
	WHERE negate
	UNION
	SELECT
		rule_id
	FROM rules_with_negate
	EXCEPT
	SELECT
		rule_id
	FROM matched_rules_with_negate
) q1
INNER JOIN rules r ON q1.rule_id = r.id
_SQL_
	return $self->dbh->selectcol_arrayref( $SQL, {}, $self->fw_id, $port_low, $port_high );		# array of rules id
}


#*************************
## Find Rules with object (exact match)
#*************************
sub select_rules_with_ipaddr_or_ipnet {
	my ( $self, $field , $ipaddr) = @_;
	# VALUES: fw_id, ipaddr
my $SQL = <<_SQL_;
WITH matched_rules AS (
	SELECT DISTINCT
		mor.rule_id
	FROM obj_ipaddr oip
	INNER JOIN objects o ON o.id = oip.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = oip.obj_id
	WHERE o.fw_id = \$1 AND
		  mor.field = \$2 AND
		  oip.ipaddr = \$3 AND
		  NOT negate
),
matched_rules_negate AS (
	SELECT DISTINCT
		mor.rule_id
	FROM obj_ipaddr oip
	INNER JOIN objects o ON o.id = oip.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = oip.obj_id
	WHERE o.fw_id = \$1 AND
		  mor.field = \$2 AND (
			( oip.ipaddr >>= \$3 ) OR
			( oip.ipaddr_low <= \$3 AND oip.ipaddr_high >= \$3  )
		  ) AND
		  negate
)
SELECT
	r.seq
FROM (
	SELECT
		rule_id
	FROM matched_rules
	EXCEPT
	SELECT
		rule_id
	FROM matched_rules_negate
) q1
INNER JOIN rules r ON q1.rule_id = r.id
_SQL_
	return $self->dbh->selectcol_arrayref( $SQL, {}, $self->fw_id, $field, $ipaddr );		# array of rules id
}

sub select_rules_with_iprange {
	my ( $self, $field, $ipaddr_low, $ipaddr_high ) = @_;
	# VALUES: fw_id, ipaddr_low, ipaddr_high
my $SQL = <<_SQL_;
WITH matched_rules AS (
	SELECT DISTINCT
		mor.rule_id
	FROM obj_ipaddr oip
	INNER JOIN objects o ON o.id = oip.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = oip.obj_id
	WHERE o.fw_id = \$1 AND
		  mor.field = \$2 AND
		  ( oip.ipaddr_low = \$3 AND oip.ipaddr_high = \$4 ) AND
		  inet(\$3) <= inet(\$4) AND
		  NOT negate
),
matched_rules_negate AS (
	SELECT DISTINCT
		mor.rule_id
	FROM obj_ipaddr oip
	INNER JOIN objects o ON o.id = oip.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = oip.obj_id
	WHERE o.fw_id = \$1 AND
		  mor.field = \$2 AND (
			( oip.ipaddr >>= \$3 AND oip.ipaddr >>= \$4 ) OR
			( oip.ipaddr_low <= \$3 AND oip.ipaddr_high >= \$4  )
		  ) AND
		  inet(\$3) <= inet(\$4) AND
		  negate
)
SELECT
	r.seq
FROM (
	SELECT
		rule_id
	FROM matched_rules
	EXCEPT
	SELECT
		rule_id
	FROM matched_rules_negate
) q1
INNER JOIN rules r ON q1.rule_id = r.id
_SQL_
	return $self->dbh->selectcol_arrayref( $SQL, {}, $self->fw_id, $field, $ipaddr_low, $ipaddr_high );		# array of rules id
}

sub select_rules_with_service {
	my ( $self, $protocol, $port ) = @_;
	# VALUES: fw_id, port
my $SQL = <<_SQL_;
WITH matched_rules AS (
	SELECT DISTINCT
		mor.rule_id,
		mor.negate
	FROM obj_service os
	INNER JOIN objects o ON o.id = os.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = os.obj_id
	WHERE o.fw_id = \$1 AND
		  os.protocol = \$2 AND
		  mor.field = 'service' AND
		  os.port = \$3 AND
		  NOT negate
),
matched_rules_negate AS (
	SELECT DISTINCT
		mor.rule_id,
		mor.negate
	FROM obj_service os
	INNER JOIN objects o ON o.id = os.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = os.obj_id
	WHERE o.fw_id = \$1 AND
		  os.protocol = \$2 AND
		  mor.field = 'service' AND (
			( os.port = \$3 ) OR
			( os.port_low <= \$3 AND os.port_high >= \$3 )
		  ) AND
		  negate
)
SELECT
	r.seq
FROM (
	SELECT
		rule_id
	FROM matched_rules
	EXCEPT
	SELECT
		rule_id
	FROM matched_rules_negate
) q1
INNER JOIN rules r ON q1.rule_id = r.id
_SQL_
	return $self->dbh->selectcol_arrayref( $SQL, {}, $self->fw_id, $protocol, $port );		# array of rules id
}

sub select_rules_with_port {
	my ( $self, $port ) = @_;
	# VALUES: fw_id, port
my $SQL = <<_SQL_;
WITH matched_rules AS (
	SELECT DISTINCT
		mor.rule_id,
		mor.negate
	FROM obj_service os
	INNER JOIN objects o ON o.id = os.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = os.obj_id
	WHERE o.fw_id = \$1 AND
		  mor.field = 'service' AND
		  os.port = \$2 AND
		  NOT negate
),
matched_rules_negate AS (
	SELECT DISTINCT
		mor.rule_id,
		mor.negate
	FROM obj_service os
	INNER JOIN objects o ON o.id = os.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = os.obj_id
	WHERE o.fw_id = \$1 AND
		  mor.field = 'service' AND (
			( os.port = \$2 ) OR
			( os.port_low <= \$2 AND os.port_high >= \$2 )
		  ) AND
		  negate
)
SELECT
	r.seq
FROM (
	SELECT
		rule_id
	FROM matched_rules
	EXCEPT
	SELECT
		rule_id
	FROM matched_rules_negate
) q1
INNER JOIN rules r ON q1.rule_id = r.id
_SQL_
	return $self->dbh->selectcol_arrayref( $SQL, {}, $self->fw_id, $port );		# array of rules id
}

sub select_rules_with_servicerange {
	my ( $self, $protocol, $port_low, $port_high ) = @_;
	# VALUES: fw_id, protocol, port_low, port_high
my $SQL = <<_SQL_;
WITH matched_rules AS (
	SELECT DISTINCT
		mor.rule_id,
		mor.negate
	FROM obj_service os
	INNER JOIN objects o ON o.id = os.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = os.obj_id
	WHERE o.fw_id = \$1 AND
		  os.protocol = \$2 AND
		  mor.field = 'service' AND
		  os.port_low = \$3 AND
		  os.port_high = \$4 AND
		  \$3 < \$4 AND
		  NOT negate
),
matched_rules_negate AS (
	SELECT DISTINCT
		mor.rule_id,
		mor.negate
	FROM obj_service os
	INNER JOIN objects o ON o.id = os.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = os.obj_id
	WHERE o.fw_id = \$1 AND
		  os.protocol = \$2 AND
		  mor.field = 'service' AND
		  os.port_low <= \$3 AND
		  os.port_high >= \$4 AND
		  \$3 < \$4 AND
		  negate
)
SELECT
	r.seq
FROM (
	SELECT
		rule_id
	FROM matched_rules
	EXCEPT
	SELECT
		rule_id
	FROM matched_rules_negate
) q1
INNER JOIN rules r ON q1.rule_id = r.id
_SQL_
	return $self->dbh->selectcol_arrayref( $SQL, {}, $self->fw_id, $protocol, $port_low, $port_high );		# array of rules id
}

sub select_rules_with_portrange {
	my ( $self, $port_low, $port_high ) = @_;
	# VALUES: fw_id, port_low, port_high
my $SQL = <<_SQL_;
WITH matched_rules AS (
	SELECT DISTINCT
		mor.rule_id,
		mor.negate
	FROM obj_service os
	INNER JOIN objects o ON o.id = os.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = os.obj_id
	WHERE o.fw_id = \$1 AND
		  mor.field = 'service' AND
		  os.port_low = \$2 AND
		  os.port_high = \$3 AND
		  \$2 < \$3 AND
		  NOT negate
),
matched_rules_negate AS (
	SELECT DISTINCT
		mor.rule_id,
		mor.negate
	FROM obj_service os
	INNER JOIN objects o ON o.id = os.obj_id
	INNER JOIN mapping_obj_rule mor ON mor.obj_id = os.obj_id
	WHERE o.fw_id = \$1 AND
		  mor.field = 'service' AND
		  os.port_low <= \$2 AND
		  os.port_high >= \$3 AND
		  \$2 < \$3 AND
		  negate
)
SELECT
	r.seq
FROM (
	SELECT
		rule_id
	FROM matched_rules
	EXCEPT
	SELECT
		rule_id
	FROM matched_rules_negate
) q1
INNER JOIN rules r ON q1.rule_id = r.id
_SQL_
	return $self->dbh->selectcol_arrayref( $SQL, {}, $self->fw_id, $port_low, $port_high );		# array of rules id
}


#*************************
## Find Rules contained by object
#*************************



#*************************
## Get rules
#*************************
sub select_all_rules_seq {
	my $self = shift;
	# VALUES: fw_id
my $SQL = <<_SQL_;
SELECT
	seq
FROM rules
WHERE fw_id = ?
ORDER BY seq ASC
_SQL_
	return $self->dbh->selectcol_arrayref( $SQL, {}, $self->fw_id );		# array of rules id
}

sub select_all_rules {
	my $self = shift;
	# VALUES: fw_id
my $SQL = <<_SQL_;
SELECT
	prebuilt
FROM rules
WHERE fw_id = ?
ORDER BY seq ASC
_SQL_
	return $self->dbh->selectcol_arrayref( $SQL, {}, $self->fw_id );	# [ARRAY] prebuilt rules
}

sub select_rules {
	my ( $self, $vals ) = @_;
	# VALUES: fw_id, array of rules seq
my $where_in = join(',', ('?') x @$vals);
my $SQL = <<_SQL_;
SELECT
	prebuilt
FROM rules
WHERE fw_id = ? AND seq IN ( ${where_in} )
ORDER BY seq ASC
_SQL_
	return $self->dbh->selectcol_arrayref( $SQL, {}, $self->fw_id, @$vals );	# [ARRAY] prebuilt rules
}


#*************************
## Rules
#*************************
sub select_rules_obj {
	my ( $self, $rules ) = @_;
	# VALUES: fw_id, array of rules
my $SQL = "
SELECT
	r.seq,
	ro.field,
	o.id,
	o.name,
	o.type
FROM rules_obj ro
INNER JOIN rules r ON r.id = ro.rule_id
INNER JOIN objects o ON ro.field_obj_id = o.id
WHERE r.fw_id = ? AND r.seq IN (".join(',', ('?') x @$rules).")
;";
	return $self->dbh->selectall_arrayref( $SQL, {}, $self->fw_id, @$rules );
}

sub select_rules_data {
	my ( $self, $rules ) = @_;
	# VALUES: fw_id, array of rules
my $SQL = "
SELECT
	seq,
	enable,
	section,
	action,
	logging,
	comment
FROM rules
WHERE fw_id = ? AND seq IN (".join(',', ('?') x @$rules).")
;";
	return $self->dbh->selectall_arrayref( $SQL, {}, $self->fw_id, @$rules );
}


#*************************
## Objects
#*************************
sub select_ipgroup {
	my ( $self, $vals ) = @_;
	# VALUES: array of obj_id
my $where_in = join(',', ('?') x @$vals);
my $SQL = <<_SQL_;
WITH RECURSIVE ipgroup_content AS (
	SELECT
		oipg.obj_id AS parent_id,
		o2.type AS obj_type,
		o2.id AS obj_id,
		o2.name AS obj_name,
		CASE WHEN oipg.field = 'exclusion' THEN TRUE
			 ELSE FALSE END as obj_negate
	FROM obj_ipgroup oipg
	LEFT JOIN objects o2 ON o2.id = oipg.field_obj_id
	WHERE oipg.obj_id IN ( ${where_in} )
	UNION
	SELECT
		oc.parent_id AS parent_id,
		o2.type AS obj_type,
		o2.id AS obj_id,
		o2.name AS obj_name,
		oc.obj_negate AS obj_negate
	FROM obj_ipgroup oipg
	LEFT JOIN objects o2 ON o2.id = oipg.field_obj_id 
	INNER JOIN ipgroup_content oc ON oc.obj_id = oipg.obj_id
)
SELECT	
	*
FROM ipgroup_content
_SQL_
	return $self->dbh->selectall_arrayref( $SQL, {}, @$vals );	# [ARRAY] 0:parent_id, 1:obj_type, 2:obj_id, 3:obj_name, 4:obj_negate
}

sub select_servicegroup {
	my ( $self, $vals ) = @_;
	# VALUES: array of obj_id
my $where_in = join(',', ('?') x @$vals);
my $SQL = <<_SQL_;
WITH RECURSIVE servicegroup_content AS (
	SELECT
		osg.obj_id AS parent_id,
		o2.type AS obj_type,
		o2.id AS obj_id,
		o2.name AS obj_name,
		CASE WHEN osg.field = 'exclusion' THEN TRUE
			 ELSE FALSE END as obj_negate
	FROM obj_servicegroup osg
	LEFT JOIN objects o2 ON o2.id = osg.field_obj_id
	WHERE osg.obj_id IN ( ${where_in} )
	UNION
	SELECT
		oc.parent_id AS parent_id,
		o2.type AS obj_type,
		o2.id AS obj_id,
		o2.name AS obj_name,
		oc.obj_negate AS obj_negate
	FROM obj_servicegroup osg
	LEFT JOIN objects o2 ON o2.id = osg.field_obj_id 
	INNER JOIN servicegroup_content oc ON oc.obj_id = osg.obj_id
)
SELECT	
	*
FROM servicegroup_content
_SQL_
	return $self->dbh->selectall_arrayref( $SQL, {}, @$vals );	# [ARRAY] 0:parent_id, 1:obj_type, 2:obj_id, 3:negate
}

sub select_ipaddr {
	my ( $self, $vals ) = @_;
	# VALUES: array of obj_id
my $SQL = "
SELECT DISTINCT ON (obj_id)
	obj_id,
	name,
	COALESCE( abbrev(ipaddr), name ) AS ipaddr	
FROM obj_ipaddr oip
INNER JOIN objects o ON o.id = oip.obj_id
WHERE obj_id IN (".join(',', ('?') x @$vals).")
;";
	return $self->dbh->selectall_arrayref( $SQL, {}, @$vals );
}

sub select_iprange {
	my ( $self, $vals ) = @_;
	# VALUES: array of obj_id
my $SQL = "
SELECT DISTINCT ON (obj_id)
	obj_id,
	name,
	host(ipaddr_low) || '-' || host(ipaddr_high) AS iprange	
FROM obj_ipaddr oip
INNER JOIN objects o ON o.id = oip.obj_id
WHERE obj_id IN (".join(',', ('?') x @$vals).")
;";
	return $self->dbh->selectall_arrayref( $SQL, {}, @$vals );
}

sub select_service {
	my ( $self, $vals ) = @_;
	# VALUES: array of obj_id
my $SQL = "
SELECT DISTINCT
	obj_id,
	name,
	CASE WHEN protocol = 'ICMP' THEN name
		 ELSE COALESCE( protocol || '_' || port, protocol, name ) 
		 END AS service
FROM obj_service os
INNER JOIN objects o ON o.id = os.obj_id
WHERE obj_id IN (".join(',', ('?') x @$vals).")
;";
	return $self->dbh->selectall_arrayref( $SQL, {}, @$vals );
}

sub select_servicerange {
	my ( $self, $vals ) = @_;
	# VALUES: array of obj_id
my $SQL = "
SELECT DISTINCT
	obj_id,
	name,
	protocol || '_' || port_low || '-' || port_high AS service
FROM obj_service os
INNER JOIN objects o ON o.id = os.obj_id
WHERE obj_id IN (".join(',', ('?') x @$vals).")
;";
	return $self->dbh->selectall_arrayref( $SQL, {}, @$vals );
}



1;