use 5.014_002;
use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(
  NAME         => 'Mojar::Auth',
  VERSION_FROM => 'lib/Mojar/Auth.pm',
  ABSTRACT     => 'Authentication & authorisation tools',
  AUTHOR       => 'Nic Sandfield <niczero@cpan.org>',
  LICENSE      => 'artistic_2',
  META_MERGE   => {
    no_index  => {directory => [qw(test)]},
    requires  => {perl => 5.014002},
    resources => {
      homepage   => 'http://niczero.github.io/mojar',
      license    => 'http://www.opensource.org/licenses/artistic-license-2.0',
      repository => 'http://github.com/niczero/mojar-auth',
      bugtracker =>
          'http://github.com/niczero/mojar-auth/issues'
    }
  },
  BUILD_REQUIRES => {'Test::More' => 0},
  CONFIGURE_REQUIRES => {'ExtUtils::MakeMaker' => 6.3},
  PREREQ_PM => {Mojolicious => 6},
  EXE_FILES => [],
  test => {TESTS => 'test/*.t'}
);
