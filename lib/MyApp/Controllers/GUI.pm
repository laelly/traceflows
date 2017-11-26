package MyApp::Controllers::GUI;

use Mojo::Base 'Mojolicious::Controller';
use Data::Dumper qw(Dumper); $Data::Dumper::Sortkeys = 1;		## Temporary
use JSON::XS qw(encode_json);


##################################################
## DATA
##################################################
my @FIELDS = qw( src dst service target );
my $FIELD_SEPARATOR = qr/(?:,\s+|\s+|[\|;])/;
my $QUERYREG = {
	search => qr/^\s*
			(?=.*?
				(?:\bSRC\b|\bSOURCE\b)
				\s*
				(?<src>.*?)
				\s*
				(?:DST|DESTINATION|SRV|SERVICE|TGT|TARGET|$)
			)?
			(?=.*?
				(?:\bDST\b|\bDESTINATION\b)
				\s*
				(?<dst>.*?)
				\s*
				(?:SRC|SOURCE|SRV|SERVICE|TGT|TARGET|$)
			)?
			(?=.*?
				(?:\bSRV\b|\bSERVICE\b)
				\s*
				(?<service>.*?)
				\s*
				(?:SRC|SOURCE|DST|DESTINATION|TGT|TARGET|$)
			)?
			(?=.*?
				(?:\bTGT\b|\bTARGET\b)
				\s*
				(?<target>.*?)
				\s*
				(?:SRC|SOURCE|DST|DESTINATION|SRV|SERVICE|$)
			)?
		\s*/six,
	show				=> qr/^\s*show\s*(.*?)\s*$/i,
	show_values	=> qr/^((?:\d+\s*[,;\-]\s*)*\d+)$/,
};


##################################################
## GUI rendering functions called from routing (dispatch)
##################################################
##******************
## Home
##******************
sub home {
	my $c = shift;
	my $user = { uid => 'test', role => 'admin' };
	$c->render( template => 'home', format => 'html', user => $user );
	# if ($c->check_if_authenticated ) {
		# my $user = $c->current_user;	# hash ref as returned by 'load_user' routine
		# $c->render(template => 'home', format => 'html', user => $user, status => [], checked => [ '' ] );
	# } else {
		# $c->redirect_to('/login');
	# }
};


##******************
## Query
##******************
sub query {
	my $c = shift;
	my $p = $c->req->params->to_hash;
	
	#------------------
	# Input
	if ( !$c->is_safe_input($p->{fw}) ) {
		return $c->render( text => "Bad input!", status => 400 );
	}
	#------------------
	# Query
	if ( my $query = $p->{query} ) {
		if ( my $fw_name = $p->{fw} ) {
			##***********************
			## Show rules
			if ( $query =~ $QUERYREG->{show} ) {		## show ruleset or specific rules
				#----------------------
				# Show whole ruleset
				if ( ! $1 ) {
					return $c->render(
						template => 'parts/query', format => 'html',
						fw => $fw_name,
						active_part => 'rules',
						parts => { rules => undef }
					);
				#----------------------
				# Show requested rules
				} elsif ( $1 =~ $QUERYREG->{show_values} ) {
					my @rules = split( $FIELD_SEPARATOR, $1 );
					return $c->render(
						template => 'parts/query', format => 'html',
						fw => $fw_name,
						active_part => 'rules',
						parts => { rules => \@rules }
					);
				#----------------------
				# Bad request
				} else {
					$c->render( text => 'Bad values in "show" query!', status => 400 );
				}
			##***********************
			## Search rules
			} elsif ( $query =~ $QUERYREG->{search} ) {		## extract fields from query (src, dst, etc...)
				if ( my $fw = $c->get_firewall( $fw_name ) ) {
					my %query;
					#----------------------
					# Extract fields
					my $nb_val = 0;
					foreach my $f ( @FIELDS ) {
						if ( $+{$f} ) {
							@{$query{$f}} = split( $FIELD_SEPARATOR, $+{$f} );
							$nb_val += @{$query{$f}};
						}
					}
					#----------------------
					# Get matching rules
					my $rules = $fw->find_rules( %query, opt => 'numbers' );
					#----------------------
					# Get rank
					my $rank = $fw->find_ranking_tree ( %query, limit => $nb_val >= 3 ? 2 : 1 );
					#----------------------
					# Rendering
					return $c->render(
						template => 'parts/query', format => 'html',
						fw => $fw_name,
						active_part => 'summary',
						parts => {
							rules => $rules,
							rank => $rank
						}
					);
				} else {
					return $c->render( text => "Requested firewall ".$fw_name." does not exist in database", status => 400 );
				}
			##***********************
			## Else (unknown query)
			} else {
				warn "'".$query."'\n";
				$c->render( text => "Unknown query! Please check syntax.", status => 400 );
			}
			##***********************
		} else {
			$c->render( text => "A firewall must be selected!", status => 400 );
		}
	} else {
		$c->render( text => "Missing query!", status => 400 );
	}
}


##################################################
## Functions
##################################################
##******************
## Check query parameters
##******************


1;