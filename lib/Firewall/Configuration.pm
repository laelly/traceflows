package Firewall::Configuration;
use strict;
use warnings;
use Config::Tiny;


##################################################################
## INITIALIZATION
##################################################################
##*********************************
## NEW
##*********************************
sub new {
    my ($class, %args) = @_;
	
	die "A configuration file must be provided for package ".__PACKAGE__."\n" unless $args->{file};
	
    my $self = bless {
		_CONFIG => _init_config($args->{file})
	}, $class;
    return $self;
}


##################################################################
## FUNCTIONS
##################################################################
sub _init_config {
	my $cfg = shift;
	die "Can't read configuration file '".$cfg."'\n" unless -r $cfg;
	return Config::Tiny->read( $cfg ) or die "Error when parsing configuration file:\n".$Config::Tiny::errstr;
}


##################################################################
## METHODS
##################################################################
sub add {
	my ($self, $config_file) = @_;
	my $h = $self->{_CONFIG};
	my $cfg = _init_config($config_file);
	
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

sub get {
	my ( $self, $val ) = @_;
	my $cfg = $self->{_CONFIG};
	return $val ? $cfg->{$val} : $cfg;
}



1;