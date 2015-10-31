use Mojo::Base -strict;
use Test::More;

use_ok 'Mojar::Auth';
diag "Testing Mojar::Auth $Mojar::Auth::VERSION, Perl $], $^X";
use_ok 'Mojar::Auth::Scuro';

done_testing();
