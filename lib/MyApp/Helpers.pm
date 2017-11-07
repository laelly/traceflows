package MyApp::Helpers;
use strict;
use warnings;
use base 'Mojolicious::Plugin';
use Data::Dumper qw(Dumper); $Data::Dumper::Sortkeys = 1; $Data::Dumper::Deepcopy = 1;
use XML::Hash::XS qw(hash2xml);
use JSON::XS qw(encode_json);



##################################################
## Register plugin
##################################################
sub register {
	my ($self, $app, $args) = @_;
	
	$app->helper( rendering_from_hash => \&rendering_from_hash );
}


##################################################
## Functions (helpers)
##################################################
#***************************************
# Rendering
#***************************************
sub rendering_from_hash {
	my ( $c, $h ) = @_;

	## rendering
	$c->respond_to(
		json => sub {
			$c->render( text => encode_json( $h ), format => 'json' );
		},
		xml => sub {
			$c->render( text => hash2xml( $h, xml_decl => 0, use_attr => 1, canonical => 0, indent => 0 ), format => 'xml' );	# canonical = sorted by keys
		},
		dump => sub {
			$c->render( text => Dumper($h), format => 'text' );
		},
		any => sub {
			$c->render( text => encode_json( $h ), format => 'json' );
		},
	);
};



1;