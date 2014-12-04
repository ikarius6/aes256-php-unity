<?php
	/*
		AES256 v1.1 MrJack
		https://gist.github.com/1077723/0a9a7c5299a7fb4340e4b2064fd383ef236a5aa5
		https://gist.github.com/RiANOl/1077723
	*/

	/* Unity compatible version */
	function aes256Encrypt_unity($key, $data, $mode = MCRYPT_MODE_CBC, $block_size = MCRYPT_RIJNDAEL_256) {
		$cipher = mcrypt_module_open($block_size, '', $mode, '');
		$iv_size = mcrypt_enc_get_iv_size($cipher);
		$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
		if (mcrypt_generic_init($cipher, $key, $iv) != -1){
			$encrypted = mcrypt_generic($cipher, $data);
			mcrypt_generic_deinit($cipher);
			return $iv.$encrypted;
		}
		return;
	}

	function aes256Decrypt_unity($key, $data, $mode = MCRYPT_MODE_CBC, $block_size = MCRYPT_RIJNDAEL_256) {
		$cipher = mcrypt_module_open($block_size, '', $mode, '');
		$iv_size = mcrypt_enc_get_iv_size($cipher);
		$iv_dec = substr($data, 0, $iv_size);
		if (mcrypt_generic_init($cipher, $key, $iv_dec) != -1){
			$iv_size = mcrypt_get_iv_size($block_size, $mode);
			$decrypted = mdecrypt_generic($cipher, $data);
			mcrypt_generic_deinit($cipher);
			$decrypted = substr($decrypted, $iv_size);
			return $decrypted;
		}
		return;
	}
	
	/* General version */
	function aes256Encrypt($key, $data, $mode = MCRYPT_MODE_CBC) {
		if(32 !== strlen($key)) $key = hash('SHA256', $key, true);
		$padding = 16 - (strlen($data) % 16);
		$data .= str_repeat(chr($padding), $padding);
		$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, $mode);
		$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
		return $iv.mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, $mode, $iv);
	}

	function aes256Decrypt($key, $data, $mode = MCRYPT_MODE_CBC) {
		if(32 !== strlen($key)) $key = hash('SHA256', $key, true);
		$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, $mode);
		$iv_dec = substr($data, 0, $iv_size);
		$data = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $data, $mode, $iv_dec);
		$padding = ord($data[strlen($data) - 1]);
		$data = substr($data, 0, -$padding);
		$data = substr($data, $iv_size);
		return $data; 
	}