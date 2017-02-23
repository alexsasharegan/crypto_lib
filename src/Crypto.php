<?php

namespace Crypto;

use Crypto\Exceptions\Maximum_Length_Exceeded;

class Crypto {
	
	public static $algorithm = PASSWORD_BCRYPT;
	
	public static $encryption_options = [
		'cost' => 12,
	];
	
	/**
	 * @param $algorithm
	 */
	public static function setAlgorithm( $algorithm )
	{
		self::$algorithm = $algorithm;
	}
	
	/**
	 * @param array $options
	 */
	public static function setOptions( array $options = [] )
	{
		self::$encryption_options = array_merge( self::$encryption_options, $options );
	}
	
	/**
	 * @param $password
	 *
	 * @return bool|string
	 */
	public static function encrypt( $password )
	{
		return self::hash( $password );
	}
	
	/**
	 * @param $password
	 *
	 * @return bool|string
	 * @throws Maximum_Length_Exceeded
	 */
	public static function hash( $password )
	{
		$password = strval( $password );
		$length   = strlen( $password );
		
		if ( $length > 72 ) throw new Maximum_Length_Exceeded( $length );
		
		return password_hash( $password, self::$algorithm, self::$encryption_options );
	}
	
	/**
	 * @param $password
	 * @param $hashedPassword
	 *
	 * @return bool
	 */
	public static function validate( $password, $hashedPassword )
	{
		return self::verify( $password, $hashedPassword );
	}
	
	/**
	 * @param $password
	 * @param $hashedPassword
	 *
	 * @return bool
	 */
	public static function verify( $password, $hashedPassword )
	{
		return password_verify( $password, $hashedPassword );
	}
	
	/**
	 * @param $hashedPassword
	 *
	 * @return bool
	 */
	public static function passwordIsOutdated( $hashedPassword )
	{
		return self::password_needs_rehash( $hashedPassword );
	}
	
	/**
	 * @param $hashedPassword
	 *
	 * @return bool
	 */
	public static function password_needs_rehash( $hashedPassword )
	{
		return password_needs_rehash( $hashedPassword, self::$algorithm, self::$encryption_options );
	}
	
	/**
	 * @param $hashedPassword
	 *
	 * @return array
	 */
	public static function getInfo( $hashedPassword )
	{
		return password_get_info( $hashedPassword );
	}
}
