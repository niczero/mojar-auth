use Mojo::Base -strict;
use Test::More;

use Cwd 'abs_path';
use Mojar::Auth::Scuro;
use Pod::Perldoc;
#use open ':locale';

my $s = Mojar::Auth::Scuro->new;

subtest q{Empty string} => sub {
  my $t = '';
  ok length $s->scuro($t, 'z'), 'empty z';
  ok length $s->scuro($t, 'a'), 'empty a';
  ok length $s->scuro($t, 'b'), 'empty b';
  ok length $s->scuro($t, 'c'), 'empty c';

  is $s->chiara($s->scuro($t, 'z')), $t, 'RT empty z';
  is $s->chiara($s->scuro($t, 'a')), $t, 'RT empty a';
  is $s->chiara($s->scuro($t, 'b')), $t, 'RT empty b';
  is $s->chiara($s->scuro($t, 'c')), $t, 'RT empty c';
};

subtest q{Hello} => sub {
  my $t = '123 hello x,y,z';
  ok $s->scuro($t, 'z'), 'hello z';
  ok $s->scuro($t, 'a'), 'hello a';
  ok $s->scuro($t, 'b'), 'hello b';
  ok $s->scuro($t, 'c'), 'hello c';

  is $s->chiara($s->scuro($t, 'z')), $t, 'RT hello z';
  is $s->chiara($s->scuro($t, 'a')), $t, 'RT hello a';
  is $s->chiara($s->scuro($t, 'b')), $t, 'RT hello b';
  is $s->chiara($s->scuro($t, 'c')), $t, 'RT hello c';
};

subtest q{Module} => sub {
  my $p = Pod::Perldoc->new->searchfor(1, 'Mojolicious::Controller', @INC);
  chomp($p);
  ok $p, 'found something';
  like $p, qr[/], 'found a path';
  my $found_lines;
  open my $fh, '<:encoding(UTF-8)', $p or diag "$p: $!";
  while (defined(my $line = <$fh>) and ++$found_lines) {
    is $s->chiara($s->scuro($line, 'z')), $line, 'line z';
    is $s->chiara($s->scuro($line, 'a')), $line, 'line a';
    is $s->chiara($s->scuro($line, 'b')), $line, 'line b';
    is $s->chiara($s->scuro($line, 'c')), $line, 'line c';
  }
  close $fh;
  ok $found_lines, 'processed some lines';
};

done_testing();
