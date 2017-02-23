<?php

namespace Crypto\Exceptions;

class Maximum_Length_Exceeded extends \Exception implements \JsonSerializable {
	
	public function __construct( $length, $code = 0, Exception $previous = NULL )
	{
		$message = "The maximum length of 72 characters was exceeded. The supplied password's length was: $length";
		parent::__construct( $message, $code, $previous );
	}
	
	public function __toString()
	{
		return __CLASS__ . ": [{$this->code}]: {$this->message}\n";
	}
	
	public function jsonSerialize()
	{
		return [ 'message' => $this->message ];
	}
	
}
