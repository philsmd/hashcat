#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use MIME::Base64 qw (encode_base64 decode_base64);
use POSIX        qw (strftime);
use Crypt::PBKDF2;
use Crypt::AuthEnc::CCM;

sub module_constraints { [[0, 252], [8, 8], [-1, -1], [-1, -1], [-1, -1]] }

my $BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

sub random_base58_string
{
  my $len = shift;

  my $str = "";

  for (my $i = 0; $i < $len; $i++)
  {
    $str .= substr ($BASE58_CHARS, random_number (0, 57), 1);
  }

  return $str;
}

sub module_generate_hash
{
  my $word       = shift;
  my $salt       = shift;
  my $iterations = shift // 1000;
  my $iv         = shift;
  my $data       = shift;

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => $iterations,
    output_len => 32
  );

  my $len_and_pass = length ($word) . '|' . $word;

  my $key = $pbkdf2->PBKDF2 ($salt, $len_and_pass);

  my $ADATA   = '';
  my $TAG_LEN = 8;

  my $ct = "";

  if (defined ($data)) # decrypt
  {
    my $data_len = length ($data) - $TAG_LEN;
    my $ccm_data = substr ($data,         0, $data_len);
    my $ccm_tag  = substr ($data, $data_len, $TAG_LEN); # or just use -8

    my $aes = Crypt::AuthEnc::CCM->new ("AES", $key, $iv, $ADATA, $TAG_LEN, $data_len);

    $aes->decrypt_add ($ccm_data); # we don't need the result (plaintext) for the verification

    my $result_tag = $aes->decrypt_done ();

    $result_tag = substr ($result_tag, 0, $TAG_LEN);

    if ($result_tag ne $ccm_tag) # failed/wrong
    {
      $ct = random_bytes (length ($data)); # fake data to make it fail
    }
    else
    {
      $ct = $data;
    }
  }
  else # encrypt
  {
    $iv = random_bytes (16);

    my $rand_masterkey  = random_base58_string (29); # not sure if 100% valid key
    my $rand_account_id = random_base58_string (34);
    my $rand_timestamp  = strftime ("%Y-%m-%dT%H:%M:%S.", localtime (time)) .
                          random_number (0, 999) . "Z";

    $data = "{" .
              "\"masterkey\":\""  . $rand_masterkey  . "\"," .
              "\"account_id\":\"" . $rand_account_id . "\"," .
              "\"contacts\":[],"  .
              "\"created\":\""    . $rand_timestamp  . "\""  .
            "}";

    my $aes = Crypt::AuthEnc::CCM->new ("AES", $key, $iv, $ADATA, $TAG_LEN, length ($data));

    $ct = $aes->encrypt_add ($data);

    my $ccm_tag = $aes->encrypt_done ();

    $ct .= substr ($ccm_tag, 0, $TAG_LEN);
  }

  my $base64_ct   = encode_base64 ($ct,   '');
  my $base64_salt = encode_base64 ($salt, '');
  my $base64_iv   = encode_base64 ($iv,   '');

  my $hash = sprintf ("\$rippex\$*%i*%s*%s*%s", $iterations, $base64_salt, $base64_iv, $base64_ct);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($digest, $word) = split (/:([^:]+)$/, $line);

  return unless defined $digest;
  return unless defined $word;

  my @data = split ('\*', $digest);

  return unless scalar (@data) == 5;

  my $signature = shift @data;

  return unless ($signature eq '$rippex$');

  my $iterations = int (shift @data);

  my $salt = decode_base64 (shift @data);
  my $iv   = decode_base64 (shift @data);
  my $data = decode_base64 (shift @data);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iterations, $iv, $data);

  return ($new_hash, $word);
}

1;
