#!/usr/bin/perl
##########################################################################
# CheckPoint.pm - CheckPoint database support library
#
# Copyright (C) 2007 Peter-Paul Worm
#
# Note: this script is unsupported by Checkpoint or representatives.
##########################################################################
# Modifications made on the original script
##########################################################################
package CPparser;
use strict;
no warnings 'uninitialized';


##########################################################################
## NEW
##########################################################################
sub new {
    my $class = shift;	
    my $self = bless {}, $class;
    return $self;
}

##########################################################################
## FUNCTIONS
##########################################################################
##########################################################################
## CORE
##########################################################################
sub parse {
	my ($self,@files) = @_;
	die "Wrong use of method GetObjects " unless ref($self) eq __PACKAGE__;
	
	foreach my $file ( @files ) {
		open DATA, "<", $file or die "Cannot read file '$file' !\n\n";
		$self->_ReadObject(undef, undef, $self, 0);    
		close DATA;
	}
	return $self;
}

sub _ReadObject {
	my $self = shift;
	die "Wrong use of method _ReadObject" unless ref($self) eq __PACKAGE__;
	
	my ($line, $EndOfFile, $EndOfSection);
	my ($child, $key, $ref, $val);

	my ($parent, $parent_key, $current, $level) = @_;

	$EndOfSection=0; $EndOfFile=0;

	while (($EndOfSection==0) && ($EndOfFile==0)) {
		if ($line = <DATA>) {
			# chomp($line);

			# Determine SYNTAX of line ...
			$key=undef; $ref=undef; $val=undef;
			if    ( $line =~ /:"(.*?)"\s\((.*)/ ) { $key='"'.$1.'"'; $ref=$2 }
			elsif ( $line =~ /:"(.*)"/ )          { $key='"'.$1.'"' }
			elsif ( $line =~ /:(.*?)\s\((.*)/ )   { $key=$1; $ref=$2 }
			elsif ( $line =~ /:(.*)\s(.*)/ )      { $key=$1; $val=$2 }
			elsif ( $line =~ /:(.*)/ )            { $key=$1 }

			# Determine if reference is VALUE ...
			if ( $ref =~ /\)$/ )                  { $val=$ref; $ref=undef; $val =~ s/\)$// }

			# Determine if reference is Anonymous ...
			# ': ('
			if (((defined($key)) && ($key eq '')) &&
				((defined($ref)) && ($ref eq ''))) { $ref='AnonymousObject' }

			# Clear fields with only whitespaces (only $val can be empty string) ...
			if ($key !~ /\S+/) { undef $key }
			if ($ref !~ /\S+/) { undef $ref }
			
			# Found a VALUE to be set
			# ':key (value)'
			# ': (value)'
			if (defined($val)) {				
				if (defined($key)) {
					$current->{$key} = $val;
				} else {
					# Special case: $parent checks out to be a list of values,
					# thus make the key an array iso a hash element ...
					if (ref($parent->{$parent_key}) eq 'HASH') {
						$parent->{$parent_key} = undef;
					}
					push @{$parent->{$parent_key}}, $val;
				}

			# Found a KEY of the existing object
			# ':key ('
			# ':key (ref' -> ref is used for comments only. ignored
			} elsif (defined($key)) {					
				$child = {};				
				if (defined($current->{$key})) {
					# KEY already in use ...
					if (ref($current->{$key}) eq 'HASH') {
						# Key checks out to be a list of values, thus
						# make the key an array iso of a hash element ...
						$val = $current->{$key};
						$current->{$key}=undef;
						push @{$current->{$key}}, $val;
						$val = undef;
					}
					push @{$current->{$key}}, $child;

				} else {
					$current->{$key} = $child;
				}
				$self->_ReadObject($current, $key, $child, $level+1);

			# Found a reference to an OBJECT called REF
			# ': (ref'
			} elsif (defined($ref)) {				
				# Create new CPobject for REF
				$child = {};

				# In case of a 'ReferenceObject' or 'AnonymousObject'
				# push it on the stack, else reference
				if (($ref eq 'ReferenceObject') ||
					($ref eq 'AnonymousObject')) {
					push @{$current->{$ref}}, $child;
				} else {
					$current->{$ref} = $child;
				}
				$self->_ReadObject($current, $ref, $child, $level+1);

			# Check for new level or termination of existing level ...
			# '('
			# ')'
			} else {
				if ( $line =~ /\((.*)$/ )  {					
					$self->_ReadObject($parent, $parent_key, $current, $level+1);
				} elsif ( $line =~ /\)(.*)$/ )  {
					$EndOfSection=1;
				}
			} # End of IF statement
		} else {
			$EndOfFile=1;
		} # End of IF statement to check for EOF
	} # Until EOF or End Of Section
}


1;