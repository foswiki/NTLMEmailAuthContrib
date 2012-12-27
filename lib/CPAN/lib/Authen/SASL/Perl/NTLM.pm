# Copyright (c) 2012 Timothe Litt <litt at acm dot org>
#
# NTLM authentication for Net::SMTP

package Authen::SASL::Perl::NTLM;

use warnings;
use strict;

our $VERSION = '1.003';

my $avail;

BEGIN {
    eval {
        require Authen::NTLM;
        Authen::NTLM->import;
    };
    $avail = !$@;
    $@     = '';
}

use MIME::Base64 qw/decode_base64 encode_base64/;

our @ISA = qw/Authen::SASL::Perl/;

my %secflags = (
    noplaintext => 1,
    noanonymous => 1,

    #nodictionary => 1,
);

# Priority in selection
#
# ANONYMOUS = 0
# LOGIN, PLAIN = 1
# CRAM-MD5, EXTERNAL 2
# DIGEST-MD5 3
# GSSAPI 4

sub _order {

    #my $self = shift;

    return $avail ? 5 : -10_000;
}

# SASL security attributes of this method
# Input: required attribute names
#
# Returns the number of the required names
# that this method supports.

sub _secflags {
    my $self = shift;

    return scalar grep { $secflags{$_} } @_;
}

# Initialization (called when this method is selected)

sub _init {
    my $class = shift;
    my ($self) = @_;

    die "Unsupported service\n" unless ( ( $self->{service} || '' ) eq 'smtp' );

    #    $self->{debug} = 1;

    return bless $self, $class;
}

# Start a client session.
#
# Initialize NTLM state
# Return an initial string to send after the mechanism,
# or undef to wait for a challenge.

sub client_start {
    my $self = shift;

    $self->{error} = undef;

    if ($avail) {
        ntlm_reset();
        ntlmv2(1);
        $self->{need_step} = 1;
    }
    else {
        $self->{error}     = "Authen::NTLM is not available";
        $self->{need_step} = 0;
    }

    return undef;
}

# Return the mechanism string sent in the first transaction
# to the host.  The data is the NTLM Type1 request message.
#
# Although the data can in theory be sent after waiting for a
# null challenge, apparently Exchange requires the data with
# the initial AUTH commmand.

sub mechanism {
    my $self = shift;

    return 'Broken: Authen::NTLM is not available'
      unless ($avail);

    my $user = $self->_call('user');
    $user = '' unless ( defined $user );
    if ( $user =~ s/^V([12])://i ) {
        ntlmv2($1-1);
    }

    my $domain = '';
    if ( $user =~ /^([^\\]+)\\(.*)$/ ) {
        $domain = $1;
        $user   = $2;
    }
    ntlm_domain($domain);
    ntlm_user($user);

    my $pass = $self->_call('pass');
    $pass = '' unless ( defined $pass );
    ntlm_password($pass);

    return join( ' ', 'NTLM', ntlm() );
}

# State machine for each client step.  There's only one since
# the type 1 request was sent initially.
#
# Returns the NTLM type 3 response to the Type 2 challenge.
#
# The challenge has been decoded, and the response will be
# base64 encoded by the caller.  Authen::NTLM wants the
# challenge base64 encoded.  The response will be encoded
# by the caller.

sub client_step {
    my $self = shift;
    my ($challenge) = @_;

    my $response;

    # Defend against garbage input that produces a slew of
    # errors when ntlm() decodes without validating.

    local $SIG{__WARN__} = sub {
        $self->{error} = $_[0];
        return undef;
    };

    eval {
        $response = decode_base64( ntlm( encode_base64( $challenge, '' ) ) );
    };
    if( $@ ) {
        $self->{error} = $@;
    }

    ntlm_reset();

    $self->{need_step} = 0;

    return '' if( $self->{error} );

    return $response;
}

# Fail any server request.

sub server_start {
    my $self     = shift;
    my $response = shift;
    my $user_cb  = shift || sub { };

    $self->{error} = undef;

    return $self->set_error("Server mode NTLM is not supported.");
}

1;

__END__

=head1 NAME

Authen::SASL::Perl::NTLM - NTLM Login Authentication class

=head1 SYNOPSIS

  use Authen::SASL qw(Perl);

  $sasl = Authen::SASL->new(
    mechanism => 'NTLM',
    callback  => {
      user => $user,
      pass => $pass
    },
  );

=head1 DESCRIPTION

This module implements the client part of the NTLM SASL algorithm.

This is the minimal subset of NTLM auth required by Net::SMTP's
use of Authen::SASL.  It does not support server authentication,
and probably doesn't support other uses of Authen::SASL.

B<Authen::NTLM must be installed for this module to function.>

Missing Authen:::NTLM is reported in an odd fashion to prevent
Net::SMTP from crashing; instead it will send a silly AUTH
request to the sever - which will be rejected, but hopefully
appear in logs.  Of course, if this documentation has been read,
Authen::NTLM is installed and the issue will never come up.

=head2 CALLBACK

The callbacks used are:

=over 4

=item user

The username to be used for authentication.  The (optional) domain
name is encoded in the username as domain\username.

The user value can be prefixed with V1: or V2: to specify the
desired version of NTLM.  V1 should not be used, as it is quite
old and even less secure than V2, which is the default.

Authen::NTLM may have issues with V1, especially with unicode domains.

    user => 'Domain\username'
    user => 'V2:Domain\username'
    user => 'V2:username'

=item pass

The user's password to be used for authentication.

=back

=head1 SEE ALSO

L<Authen::SASL>,
L<Authen::SASL::Perl>
L<Authen::NTLM>

=head1 AUTHORS

Code by Timothe Litt <litt at acm dot org>.
Packaging and testing by George Clark of Foswiki.org.

=head1 COPYRIGHT

Copyright (C) 2012 Timothe Litt <litt at acm dot org>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version. For
more details read LICENSE in the root of this distribution.

Alternatively, you can redistribute and/or modify it under the
same terms as Perl itself.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

=cut

