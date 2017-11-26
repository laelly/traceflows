package MyApp::Controllers::API;

use Mojo::Base 'Mojolicious::Controller';
use Data::Dumper qw(Dumper); $Data::Dumper::Sortkeys = 1; $Data::Dumper::Deepcopy = 1;
use XML::Hash::XS qw(hash2xml);
use Mojo::Util qw(xml_escape);


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
		#------------------
		# Filter
		my %filters;
		foreach my $field ( qw(src dst service target) ) {
			$filters{$field} = $p->{$field} if $p->{$field};
		}
		#------------------
		# Input
		if ( !$c->is_safe_input( $p->{fw} ) ||  !$c->is_safe_input( $p->{rules} ) ) {
			return $c->render( text => "Bad input!", status => 400 );
		}
		my $rules = [ split( /\s*[,;]\s*/, $p->{rules} ) ] if defined($p->{rules});
		#------------------
		# Query firewall
		if ( my $fw = $c->get_firewall( $p->{fw} ) ) {
			#------------------
			# Render output
			$c->respond_to(
				json => sub {
					my $data = $fw->get_rules( opt => $p->{opt} //= 'full', format => 'json', rules => $rules, %filters );
					$c->render( text => '{"rules":'.$data.'}', format => 'json' );
				},
				xml => sub {
					my $h = $fw->get_rules( opt => $p->{opt} //= 'full', rules => $rules, %filters );
					$c->render( text => hash2xml(  { rules => $h }, xml_decl => 0, use_attr => 1, canonical => 0, indent => 0 ), format => 'xml' );	# canonical = sorted by keys
				},
				dump => sub {
					my $h = $fw->get_rules( opt => $p->{opt} //= 'full', rules => $rules, %filters );
					$c->render( text => Dumper( {rules=>$h} ), format => 'text' );
				},
				any => sub {
					my $data = $fw->get_rules( opt => $p->{opt} //= 'full', format => 'json', rules => $rules, %filters );
					$c->render( text => '{"rules":'.$data.'}', format => 'json' );
				},
			);
		} else {
			# $c->rendering_from_hash( { rules => [], error_message => "Requested firewall ".$p->{fw}." does not exist" } );
			$c->render( text => "Requested firewall ".$p->{fw}." does not exist in database", status => 400 );
		}
	} else {
		$c->render( text => "Missing firewall parameter in query", status => 400 );
	}
}


1;