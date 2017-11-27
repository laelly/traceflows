#!/usr/bin/perl

use File::Basename;
chdir(dirname(__FILE__)) or die("Can't change to dir ".dirname(__FILE__).": $!\n");
use lib dirname(__FILE__).'/lib';
use Mojolicious::Lite;		## include strict, warnings
use Data::Dumper; $Data::Dumper::Sortkeys = 1;		## temporary


########################################################################################
### Configuration
########################################################################################
#***************************************
## Config files
#***************************************
plugin 'MyApp::Configuration', { conf_file => 'conf/MyApp.cfg' };


#***************************************
## Plugins
#***************************************
push @{app->routes->namespaces}, 'MyApp::Controllers';		## Directory for controllers (lib/MyApp/Controllers)
plugin 'MyApp::Database';				## Database Connector
plugin 'MyApp::Helpers';				## Helpers


#***************************************
## Hook
#***************************************
## prepend a base uri if behind a reverse proxy (as setup in the reverse proxy)
# hook before_dispatch => sub {
	# my $c = shift;
	# $c->req->url->base->path('/app/') if $c->req->headers->header('X-Forwarded-For')‌​;;
# };

## Add cache headers on static files ( 1H cache )
hook after_static => sub {
    my $c = shift;
	$c->res->headers->remove('Cache-Control');
    $c->res->headers->remove('Set-Cookie');	

    my $type = $c->res->headers->content_type;
    if ($type) {
        if ( $type =~ /(?:javascript|image|x-icon|text\/css)/ ) {
            $c->res->headers->header("Cache-Control" => "public");
			$c->res->headers->header(Expires => Mojo::Date->new(time+3600));
        }
    }
};



########################################################################################
### CORE (Routing)
########################################################################################
#***************************************
## GUI
#***************************************
## Home
get "/" => sub {
	my $c = shift;
	$c->redirect_to('/home');
};


#***************************************
## API
#***************************************
## Firewalls
get('/API/firewalls')->to('API#firewalls');
any('/API/rules')->to('API#rules');

## Inventaire
get('/home')->to('GUI#home');
any('/query')->to('GUI#query');



#***************************************
## Debug
#***************************************
## Prevent template caching (temporary)
app->hook(before_dispatch => sub {
	my $c = shift;
	$c->app->renderer->cache(Mojo::Cache->new);
});


	
########################################################################################
### SIGNALS
########################################################################################
$SIG{ __DIE__ } = sub {
	require Devel::StackTrace;
	app->log->fatal( Devel::StackTrace->new->as_string() );
	require Carp; Carp::confess( @_ ) 
};
$SIG{ __WARN__ } = sub { app->log->warn( $_ ) for @_ };
	
	
########################################################################################
### START DAEMON
########################################################################################
## Nothing after this line (except DATA)
app->log->info("Starting WebApp.");
app->start;
