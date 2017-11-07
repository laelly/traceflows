package MyApp::Controllers::GUI;

use Mojo::Base 'Mojolicious::Controller';
use Data::Dumper qw(Dumper); $Data::Dumper::Sortkeys = 1;		## Temporary
use JSON::XS qw(encode_json);


##################################################
## GUI functions called from routing (dispatch)
##################################################
##******************
## Inventory
##******************


##******************
## Inventory
##******************
sub inventory {
	my $c = shift;
	my $data = [];
	$c->render( template => 'inventory', format => 'html', mydata => $data );
}

sub inventory_post {
	my $c = shift;
	my $p = $c->req->params->to_hash;
	my $data = [];
	$c->render( text => encode_json( { data => $data } ), format => 'json' );
}





1;