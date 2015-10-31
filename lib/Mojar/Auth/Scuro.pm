package Mojar::Auth::Scuro;
use Mojo::Base -base;
require 5.014001;

our $VERSION = 3.011;

use Carp 'croak';
use Encode ();
use MIME::Base64 qw(decode_base64 encode_base64);
use Mojo::Util qw(xor_encode);

has key => __PACKAGE__;
has encoding => sub { Encode::find_encoding('utf8') };

sub scuro {
  my ($self, $chiaratext, $method) = @_; $method //= chr(97 + rand $VERSION);
  my $r=shift->can("_wrap_$method") or croak "Method unavailable ($method)";
  $r=&$r($self => shift//q,,);
  $method eq 'z'||int(rand 2**1) ?$r :$self->_promote($r)
}

sub chiara {
  my ($self, $scurotext, $method) = @_;
  my $plain=$self->_promote($scurotext) if ord $scurotext <2**5*3;
  $method //= $1 if ($scurotext //= '') =~ s|^(.)||; return '' unless $method;
  my $r=shift->can("_unwrap_$method") or croak "Method unavailable ($method)";
  &$r($self => $scurotext);
}

# Do not send pull requests for making this more obfuscated; it only needed a
# small sprinkling to make it vaguely less easily readable; not impossible.

sub _wrap_a {
  local$_=$_[0]->_wrap_z($_[0]->_rekey(1).pop);my$a=-2+length;$a>9 and$a=10;
  $a=int rand$a;substr$_,0,1,qq,a$a,;substr$_,3+$a,0,join q,X,,shift
  ->_rekey(1)or$_
}

sub _unwrap_a {
  local$_=pop;my$a=substr$_,0,1,q,,;substr$_,1+$a,1,q,,;$_=$_[0]->_unwrap_z($_);
  substr$_,0,1,q,, and$_
}

sub _wrap_b {
  local$_=$_[0]->_wrap_z($_[0]->_rekey(1).pop);my$b=shift->_rekey(1);substr$_,0,
  1,qq,b1$b, and$_
}

sub _unwrap_b {
  local$_=pop;my$b=substr$_,0,1,q,,;substr$_,0,$b,q,,;$_=$_[0]->_unwrap_z($_);
  substr$_,0,1,q,, and$_
}

sub _wrap_c {
  local$_=$_[0]->_wrap_z($_[0]->_rekey(1).pop);my$c=shift->_rekey(1);substr$_,0,
  1,q,c1, and$_.$c
}

sub _unwrap_c {
  local$_=pop;my$c=substr$_,0,1,q,,;substr$_,-$c,$c,q,,;$_=$_[0]->_unwrap_z($_);
  substr$_,0,1,q,, and$_
}

sub _wrap_z {
  local$_=encode_base64 xor_encode($_[0]->encoding->encode(q,pop,.pop),
  $_[0]->key),q,,;s,=+$,,;s,^,m,;y,N-ZA-z,A-za-m,;tr,+/,-_,r
}

sub _unwrap_z {
  local $_=pop;tr,_-,/+,;y,N-ZA-z,A-za-m,;$_[0]->encoding->decode(xor_encode
  decode_base64($_), $_[0]->key)=~s,...,,r
}

sub _promote { $_[1]=join q,,,map +(/[a-zA-Z]/? $_^q, ,:$_),split q,,,$_[1] }

sub _rekey {
  my ($n,$s)=(pop,q,,);$s .=(q,A,..q,W,,q,a,..q,w,)[rand 46] while$n-- >0;$s
}

1;
__END__

=head1 NAME

Mojar::Auth::Scuro - Data obscurification

=head1 SYNOPSIS

  use Mojar::Auth::Scuro;
  my $obscured   = Mojar::Auth::Scuro->new->scuro($plaintext);
  my $clear_text = Mojar::Auth::Scuro->new->chiara($obscured);

  my $stronger_scuro   = Mojar::Auth::Scuro->new(key => 'UnpredictableString');
  my $private_obscured = $stronger_scuro->scuro($plaintext);
  my $clear_text       = $stronger_scuro->chiara($private_obscured);

=head1 DESCRIPTION

This is obfuscation of data, NOT encryption.

If you need the obscuring of data to be deterministic, pass 'z' as the second
param:

  my $deterministic_output = Mojar::Auth::Scuro->new->scuro($plaintext, 'z');

This means you can then determine whether two obscured strings represent the
same initial string: the same initial string will always produce the same
obscured string.

On the other hand, if you want slightly more obscurification, omit the second
param and let the algorithm(s) introduce some random/redundant bits.

=head1 ATTRIBUTES

=head2 key

  $scuro = $scuro->key('cdnDNzg9OfqUiunYRtWwqteFObdzcde5OiLz');
  $key   = $scuro->key;

The key used during the obscuring steps.  Leaving it as the default makes it
trivial for anyone in the world to un-obscure the data, which may or may not be
what you want in a particular use.  [If we were doing encryption, which we're
not, this attribute would be the shared (secret) key.]

=head1 METHODS

=head2 new

  my $obscurer = Mojar::Auth::Scuro->new;
  my $obscurer = Mojar::Auth::Scuro->new(key => 'PrivateString');

=head2 scuro

  $obscured_string = $obscurer->scuro($clear_string);
  $obscured_string = $obscurer->scuro($clear_string, 'z');

An object method, this turns a string into a slightly longer string in a
not-completely-obvious way.  The resulting string would then need multiple steps
applied to it to make it readable.  Or one invocation of C<chiara>.

If the object was using a non-default key, then un-obscuring it will require
possession of the same key.  Or about 20 mins of time from an amateur
code-breaker.

The second parameter is the obscuring method.  Use 'z' if you want the output to
be deterministic (always the same result for the same inputs).  Otherwise leave undefined for a method that introduces randomised redundant bits.

=head2 chiara

  $clear = $obscurer->chiara($obscured_string);

The inverse of C<scuro>, this turns the obscured string back to clear text.

=head1 RATIONALE

Using something like base64 is just inviting the curious to decode and play, but
using proper encryption uses a few more CPU cycles and risks losing the data.
Occasionally, just occasionally, it is useful to have something slightly removed
from base64 but with similar properties.

I reiterate, this is not encryption.  Twenty years from now your obscured data
can be unobscured via pen & paper simply by reading the short unwrap methods
(and applying any non-default key used).

=head1 GUARANTEES AND PROMISES

None.  Well, it is guaranteed that future versions will be backwards compatible,
so that obscured strings will be un-obscurable by any future version (as long as
you still have any non-default keys used).  Aside from that, you are entirely on
your own.
