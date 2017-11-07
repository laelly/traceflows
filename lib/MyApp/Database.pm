package MyApp::Database;
use Mojo::Base 'Mojolicious::Plugin';
use Mojo::Pg;


#***************************************
## Register plugin
#***************************************
sub register {
	my ($self, $app, $args) = @_;
	$app->plugin('MyApp::Database::Queries');
	$app->plugin('MyApp::Database::Firewall');
	
	## Register database (create 'pg' helper)
	$self->_register_db( $app );
}


#***************************************
## Functions (internal)
#***************************************
sub _register_db {
	my ($self, $app) = @_;
	my $cfg = $app->get_app_config('database') or die "Missing Database configuration from config file!\n";
	
	my $db = 'postgresql://';
	$db .= $cfg->{db_username}.':'.$cfg->{db_password}.'@' if $cfg->{db_username} && $cfg->{db_password};
	$db .= $cfg->{db_username}.'@' if $cfg->{db_username} && ! $cfg->{db_password};
	$db .= $cfg->{db_host} if $cfg->{db_host};
	$db .= ':'.$cfg->{db_port} if $cfg->{db_port};
	$db .= '/';
	$db .= $cfg->{db_name};
	$db .= '?RaiseError=1&PrintError=1';
	
	## register as helper
	$app->helper( pg => sub { state $pg = Mojo::Pg->new($db) } );
}



1;