package MyApp::Database::Firewall;
use strict;
use warnings;
use base 'Mojolicious::Plugin';
use Firewall;


##################################################
## Register plugin
##################################################
sub register {
	my ($self, $app, $args) = @_;
	
	$app->helper( select_firewalls => \&select_firewalls );
	$app->helper( select_firewall => \&select_firewall );
	
	my %firewalls;
	$app->attr( "_firewalls" => sub{ return \%firewalls } );
	$app->helper( get_firewall => \&get_firewall );
	$app->helper( new_firewall => \&new_firewall );
	
	_store_db_data_as_helpers($app);
}


##################################################
## Functions (helpers)
##################################################
#***************************************
## Database
#***************************************
sub _store_db_data_as_helpers {
	my $app = shift;
	my $cfg = $app->get_app_config('database') or die "Missing Database configuration from config file!\n";
	my $dsn = 'dbi:Pg:dbname='.$cfg->{db_name};
	$dsn .= ';host='.$cfg->{db_host} if $cfg->{db_host};
	$dsn .= ';port='.$cfg->{db_port} if $cfg->{db_port};
	$app->attr( "_db_dsn" => sub{ return $dsn } );
	$app->attr( "_db_username" => sub{ return $cfg->{db_username} } );
	$app->attr( "_db_password" => sub{ return $cfg->{db_password} } );
}

#***************************************
## Firewalls Queries
#***************************************
sub get_firewall {
	my ( $self, $name ) = @_;
	my $fw = $self->app->_firewalls;
	$fw->{$name} //= $self->new_firewall($name);
	return $fw->{$name};
}

#***************************************
## Firewalls Queries
#***************************************
sub select_firewalls {
	my $SQL = <<_SQL_;
SELECT
	id,
	name,
	type,
	date_creation,
	date_modification
FROM firewall
_SQL_
	return $_[0]->pg->db->dbh->selectall_arrayref( $SQL, { Slice => {} } ) || [];
}

sub select_firewall {
	my ( $self, $params ) = @_;
	return [] unless ref($params) eq 'HASH';
	
	my $where = $params->{id} ? 'id = ?' : 
						$params->{name} ? 'LOWER(name)=LOWER( ? )' :
						return [];
	my $SQL = <<_SQL_;
SELECT
	id,
	name,
	type,
	date_creation,
	date_modification
FROM firewall
WHERE ${where}
_SQL_
	return $self->pg->db->dbh->selectall_arrayref( $SQL, { Slice => {} }, $params->{id} || $params->{name} ) || [];
}


#***************************************
# Rendering
#***************************************

sub new_firewall {
	my ( $self, $name ) = @_;
	
	my $fw_data = $self->select_firewall( { name => $name } );
	( warn "Firewall '".($name||'')."'does not exist, can't create it...\n" and return undef ) unless @$fw_data;
	my $fw = Firewall->new(
		type => $fw_data->[0]{type},
		name => $fw_data->[0]{name},
		endpoint => {
			type => 'Database',
			dsn => $self->app->_db_dsn,
			username => $self->app->_db_username,
			password => $self->app->_db_password
		}
	);
	$fw->{_READY} = 1;
	return $fw;
}


1;