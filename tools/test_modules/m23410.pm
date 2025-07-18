#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use MIME::Base64 qw (encode_base64 decode_base64);

sub module_constraints { [[0, 256], [1, 256], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word  = shift;
  my $salt  = shift;
  my $salt2 = shift // random_bytes (16);
  my $iter  = shift // 10000;
  my $iter2 = shift // 10000;

  my $kdf1 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => $iter,
    output_len => 32
  );

  my $kdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => 1,
    output_len => 32
  );

  my $kdf3 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => $iter2,
    output_len => 32
  );

  my $email = $salt;

  my $digest1 = $kdf1->PBKDF2 ($email, $word);
  my $digest2 = $kdf2->PBKDF2 ($word, $digest1);
  my $digest3 = $kdf3->PBKDF2 ($salt2, encode_base64 ($digest2, ""));

  my $hash = sprintf ("\$bitwarden-server\$1*%d*%d*%s*%s*%s", $iter, $iter2, encode_base64 ($email, ""), encode_base64 ($salt2, ""), encode_base64 ($digest3, ""));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 19) eq '$bitwarden-server$1';

  my ($type, $iter, $iter2, $salt_base64, $salt2_base64, $hash_base64) = split ('\*', $hash);

  return unless defined ($type);
  return unless defined ($iter);
  return unless defined ($iter2);
  return unless defined ($salt_base64);
  return unless defined ($salt2_base64);
  return unless defined ($hash_base64);

  $type = substr ($type, 11);

  return unless ($type eq '1');
  return unless ($iter  =~ m/^[0-9]{1,7}$/);
  return unless ($iter2 =~ m/^[0-9]{1,7}$/);
  return unless ($salt_base64 =~ m/^[a-zA-Z0-9+\/=]+$/);
  return unless ($salt2_base64 =~ m/^[a-zA-Z0-9+\/=]+$/);
  return unless ($hash_base64 =~ m/^[a-zA-Z0-9+\/=]+$/);

  my $salt = decode_base64 ($salt_base64);

  my $salt2 = decode_base64 ($salt2_base64);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $salt2, $iter, $iter2);

  return ($new_hash, $word);
}

1;
