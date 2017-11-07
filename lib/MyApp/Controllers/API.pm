package MyApp::Controllers::API;

use Mojo::Base 'Mojolicious::Controller';
use Data::Dumper qw(Dumper); $Data::Dumper::Sortkeys = 1; $Data::Dumper::Deepcopy = 1;
use XML::Hash::XS qw(hash2xml);


##################################################
## API functions called from routing (dispatch)
##################################################
##******************
## Firewalls
##******************
sub firewalls {
	my $c = shift;
	my $data = $c->select_firewalls;
	
	# $c->render( text => encode_json( { data => $data } ), format => 'json' );
	$c->rendering_from_hash( { firewalls => $data } );
}


##******************
## Rules
##******************
sub rules {
	my $c = shift;
	my $p = $c->req->params->to_hash;
	
	if ( $p->{fw} ) {
		$c->respond_to(
			json => sub {
				my $data = $c->get_firewall( $p->{fw} )->get_rules( opt => $p->{opt} //= 'full', format => 'json' );
				$c->render( text => '{"rules":'.$data.'}', format => 'json' );
			},
			xml => sub {
				my $h = $c->get_firewall( $p->{fw} )->get_rules( opt => $p->{opt} //= 'full' );
				$c->render( text => hash2xml(  { rules => $h }, xml_decl => 0, use_attr => 1, canonical => 0, indent => 0 ), format => 'xml' );	# canonical = sorted by keys
			},
			dump => sub {
				my $h = $c->get_firewall( $p->{fw} )->get_rules( opt => $p->{opt} //= 'full' );
				$c->render( text => Dumper( {rules=>$h} ), format => 'text' );
			},
			any => sub {
				my $data = $c->get_firewall( $p->{fw} )->get_rules( opt => $p->{opt} //= 'full', format => 'json' );
				$c->render( text => '{"rules":'.$data.'}', format => 'json' );
			},
		);
	} else {
		$c->render( text => "Missing parameter 'fw' in query", status => 400 );
	}
}





1;