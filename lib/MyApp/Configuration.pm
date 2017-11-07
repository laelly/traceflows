package MyApp::Configuration;
use strict;
use warnings;
use base 'Mojolicious::Plugin';
use Config::Tiny;

## HELPERS
# get_app_config : server configuration
# get_config : plugins & other configuration
# add_config : add configuration files (plugins & others)


#***************************************
## Register plugin
#***************************************
sub register {
	my ($self, $app, $args) = @_;
	
	## Args
	die "A configuration file must be provided for package ".__PACKAGE__."\n" unless $args->{conf_file};
	
	## Init
	_init_config( $app, $args->{conf_file} );		## also register 'get_app_config' helper
	
	## Helpers
	my %additional_config;
	$app->attr( "_additional_config" => sub{ return \%additional_config } );
	$app->helper( get_config => \&get_config );
	$app->helper( add_config => \&add_config );
	
	## Init server configuration
	_init_logging( $app );
	_init_hypnotoad( $app );
	_init_application( $app );
}


#***************************************
## Functions (helpers)
#***************************************
sub add_config {
	my ($self, $config_file) = @_;
	my $h = $self->app->_additional_config();
	die "Can't read configuration file '".$config_file."'\n" unless -r $config_file;
	my $cfg = Config::Tiny->read( $config_file ) or die "Error when parsing configuration file:\n".$Config::Tiny::errstr;
	
	foreach my $k ( keys %$cfg ) {
		if ( $h->{$k} ) {	## copy single section parameters if section already exists
			foreach my $k2 ( keys %{$cfg->{$k}} ) {
				$h->{$k}{$k2} = $cfg->{$k}{$k2} unless $h->{$k}{$k2};	# do not overwrite
			}
		} else {	## copy the whole section if it does not exists
			$h->{$k} = $cfg->{$k} unless $h->{$k};
		}
	}
}
sub get_config {
	my ( $self, $val ) = @_;
	my $cfg = $self->app->_additional_config();
	return $val ? $cfg->{$val} : $cfg;
}


#***************************************
## Functions (init)
#***************************************
sub _init_config {
	my ($app, $config_file) = @_;
	die "Can't read configuration file '".$config_file."'\n" unless -r $config_file;
	my $cfg = Config::Tiny->read( $config_file ) or die "Error when parsing configuration file:\n".$Config::Tiny::errstr;
	$app->helper(get_app_config => sub{ $_[1] ? $cfg->{$_[1]} : $cfg; } );	## config file
}

sub _init_logging {
	my $app = shift;	
	my $cfg = $app->get_app_config('logging');
	
	## Application Logs
	$app->log( Mojo::Log->new(
		path => $cfg->{'log'},
		level => $cfg->{'log_level'} || 'info',
	) ) if $cfg->{'log'};
		
	## Access Logs
	if ( $cfg->{'access_log'} ) {
		$app->plugin( 'AccessLog', {
			log => $cfg->{'access_log'},
			format => $cfg->{'access_log_format'} || 'common',
		});
	}
}

sub _init_hypnotoad {
	my $app = shift;
	my %hypnotoad_conf;
	
	my $cfg = $app->get_app_config('hypnotoad');
	if ( ref($cfg) eq 'HASH' ) {
		foreach my $param ( keys %$cfg ) {
			($hypnotoad_conf{$param} = ref($cfg->{$param}) eq 'ARRAY' ? @{$cfg->{$param}} : [ $cfg->{$param} ]) if $param eq 'listen';
			$hypnotoad_conf{$param} = $cfg->{$param} if grep { $param eq $_ } qw( accepts backlog graceful_timeout heartbeat_interval heartbeat_timeout inactivity_timeout pid_file proxy requests upgrade_timeout workers );
		}
	} else {
		die 'Missing [hypnotoad] section from application configuration file';
	}
	$app->config( hypnotoad => \%hypnotoad_conf );
}

sub _init_application {
	my $app = shift;
	my $cfg = $app->get_app_config('application');
	$app->secrets( $cfg->{'secrets'} ) if $cfg->{'secrets'};	## secret for generating signed cookies
	$app->mode( $cfg->{'mode'} || 'production' );
	$app->types->type( xsl => 'application/xml' );		## adding mime-type
	$app->helper( log => sub{ return $app->log } );		## alow controllers to log in application log file
	$app->sessions->default_expiration( $cfg->{'session_expiration'} || 3600 );		# sessions last 1H
	$app->sessions->cookie_name( $cfg->{'cookie_name'} || 'Traceflows' );		# Cookie name
}


#***************************************
## Functions (others)
#***************************************



1;
