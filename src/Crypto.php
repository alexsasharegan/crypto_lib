<?php

namespace Crypto;
use Crypto\Exceptions\Maximum_Length_Exceeded;

class Crypto {

  public static $algorithm = PASSWORD_BCRYPT;
  public static $encryption_options = [
    'cost' => 12,
  ];

  public static function encrypt( $password ) {
    return self::hash( $password );
  }

  public static function hash( $password ) {
    $length = strlen( $password );

    if ( $length > 72 ) {
      throw new Maximum_Length_Exceeded( $length, 1 );
    }

    return password_hash( $password, self::$algorithm, self::$encryption_options );
  }

  public static function validate( $password, $hashedPassword ) {
    return self::verify( $password, $hashedPassword );
  }

  public static function compare( $password, $hashedPassword ) {
    return self::verify( $password, $hashedPassword );
  }

  public static function verify( $password, $hashedPassword ) {
    return password_verify( $password, $hashedPassword );
  }

  public static function passwordOutdated( $hashedPassword ) {
    return self::password_needs_rehash( $hashedPassword );
  }

  public static function password_needs_rehash( $hashedPassword ) {
    return password_needs_rehash( $hashedPassword, self::$algorithm, self::$encryption_options );
  }

  function __construct() {
    #code
  }
}
