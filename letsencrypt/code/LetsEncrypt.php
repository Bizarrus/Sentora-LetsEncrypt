<?php
	require_once('ACMECert.php');
	require_once('TLD.php');
	
	class LetsEncrypt {
		private $acme		= null;
		private $host_path	= null;
		private $account	= null;
		private $tld		= null;
		
		public function __construct($host_path, $cached = false) {
			$this->acme			= new ACMECert();
			$this->host_path	= $host_path;
			$this->tld			= new TLD($cached);
		}
		
		public function register($account, $email) {
			$this->account = $account;
			
			if(!file_exists(sprintf('%s%s/letsencrypt/', $this->host_path, $this->account))) {
				mkdir(sprintf('%s%s/letsencrypt/', $this->host_path, $this->account));
			}
			
			$path = sprintf('%s%s/letsencrypt/account.pem', $this->host_path, $this->account);
				
			try {
				if(!file_exists($path)) {
					file_put_contents($path, $this->acme->generateRSAKey());
				}
				
				$this->acme->loadAccountKey(file_get_contents($path));
				$response = $this->acme->register(true, $email);
				return ($response['status'] === 'valid');
			} catch(Exception $e) {
				return $e->getMessage();
			}
			
			return false;
		}
		
		public function getTLD() {
			return $this->tld;
		}
		
		public function createCertificate($domain, $is_subdomain = false) {
			if(empty($this->account)) {
				return false;
			}
			
			$domain_validation	= ctrl_options::GetSystemOption('letsencrypt_domain_validation');
			$create_www			= false;
			
			if(is_bool($domain_validation) && !$domain_validation) {
				$domain_validation = 'fetch';
			}
			
			switch($domain_validation) {
				case 'fetch':
					$data		= $this->tld->extracts($domain);
					
					if(empty($data)) {
						return false;
					}
					
					$create_www	= empty($data->prefix);
				break;
				case 'database':
					$data		= false;
					$create_www	= !$is_subdomain;
				break;
			}
			
			try {
				$config = [
					$domain	=> [
						'challenge' => 'http-01',
						'docroot'	=> sprintf('%s%s/public_html/%s/', $this->host_path, $this->account, str_replace('.', '_', $domain))
					]
				];
				
				if($create_www) {
					$config['www.' . $domain] = [
						'challenge' => 'http-01',
						'docroot'	=> sprintf('%s%s/public_html/%s/', $this->host_path, $this->account, str_replace('.', '_', $domain))
					];
				}
	
				$path = sprintf('%s%s/letsencrypt/%s', $this->host_path, $this->account, $domain);
				
				file_put_contents($path . '.rsa', $this->acme->generateRSAKey());
				$csr = $this->acme->generateCSR(sprintf('file://%s.rsa', $path), array_keys($config));
				file_put_contents($path . '.csr', $csr);
								
				$fullchain = $this->acme->getCertificateChain($csr, $config, function($options) {
					switch($options['config']['challenge']) {
						case 'http-01':
							$challenge_dir = $options['config']['docroot'] . $options['key'];
							@mkdir(dirname($challenge_dir), 0777, true);
							file_put_contents($challenge_dir, $options['value']);
							
							return function($options) use ($challenge_dir){
								unlink($challenge_dir);
							};
						break;
					}
				});
				
				if(!empty($fullchain)) {
					// Add to DNS
					// example.org. CAA 128 issue "letsencrypt.org"
					
					file_put_contents($path . '.fullchain', $fullchain);
					preg_match_all('/\-\-\-\-\-BEGIN\ CERTIFICATE\-\-\-\-\-(.*)\-\-\-\-\-END\ CERTIFICATE\-\-\-\-\-/Uis', $fullchain, $matches);
					file_put_contents($path . '.cert', $matches[0][0]);
					file_put_contents($path . '.chain', $matches[0][1]);
					return true;
				}
			} catch(Exception $e) {
				return $e->getMessage();
			}
			
			return false;
		}
		
		public function renewCertificate($username, $domain, $is_subdomain = false) {
			if(empty($this->account)) {
				return false;
			}
			
			$domain_validation	= ctrl_options::GetSystemOption('letsencrypt_domain_validation');
			$create_www			= false;
			
			if(is_bool($domain_validation) && !$domain_validation) {
				$domain_validation = 'fetch';
			}
			
			switch($domain_validation) {
				case 'fetch':
					$data		= $this->tld->extracts($domain);
					
					if(empty($data)) {
						return false;
					}
					
					$create_www	= empty($data->prefix);
				break;
				case 'database':
					$data		= false;
					$create_www	= !$is_subdomain;
				break;
			}
			
			try {
				$config = [
					$domain	=> [
						'challenge' => 'http-01',
						'docroot'	=> sprintf('%s%s/public_html/%s/', $this->host_path, $this->account, str_replace('.', '_', $domain))
					]
				];
				
				if($create_www) {
					$config['www.' . $domain] = [
						'challenge' => 'http-01',
						'docroot'	=> sprintf('%s%s/public_html/%s/', $this->host_path, $this->account, str_replace('.', '_', $domain))
					];
				}
	
				$path	= sprintf('%s%s/letsencrypt/%s', $this->host_path, $this->account, $domain);
				$csr	= $this->acme->generateCSR(sprintf('file://%s.rsa', $path), array_keys($config));
								
				$fullchain = $this->acme->getCertificateChain($csr, $config, function($options) {
					switch($options['config']['challenge']) {
						case 'http-01':
							$challenge_dir = $options['config']['docroot'] . $options['key'];
							@mkdir(dirname($challenge_dir), 0777, true);
							file_put_contents($challenge_dir, $options['value']);
							
							return function($options) use ($challenge_dir){
								unlink($challenge_dir);
							};
						break;
					}
				});
				
				if(!empty($fullchain)) {
					// Add to DNS
					// example.org. CAA 128 issue "letsencrypt.org"
					
					file_put_contents($path . '.fullchain', $fullchain);
					preg_match_all('/\-\-\-\-\-BEGIN\ CERTIFICATE\-\-\-\-\-(.*)\-\-\-\-\-END\ CERTIFICATE\-\-\-\-\-/Uis', $fullchain, $matches);
					file_put_contents($path . '.cert', $matches[0][0]);
					file_put_contents($path . '.chain', $matches[0][1]);
					return true;
				}
			} catch(Exception $e) {
				return $e->getMessage();
			}
			
			return false;
		}
		
		public function revokeCertificate($username, $domain) {
			try {
				$path			= sprintf('%s%s/letsencrypt/%s', $this->host_path, $username, $domain);
				$certificate	= $this->acme->revoke(sprintf('file://%s.fullchain', $path));
				
				if(file_exists(sprintf('$s.fullchain', $path))) {
					unlink(sprintf('$s.rsa', $path));
					unlink(sprintf('$s.csr', $path));
					unlink(sprintf('$s.chain', $path));
					unlink(sprintf('$s.cert', $path));
					unlink(sprintf('$s.fullchain', $path));
				}
				
				return true;
			} catch(Exception $e) {
				return $e->getMessage();
			}
			
			return false;
		}
		
		public function getRemainingDays($username, $domain) {
			return $this->acme->getRemainingDays(sprintf('file://%s%s/letsencrypt/%s.fullchain', $this->host_path, $username, $domain));
		}
		
		public function getTime($username, $domain) {
			try {
				$certificate = $this->acme->parseCertificate(sprintf('file://%s%s/letsencrypt/%s.fullchain', $this->host_path, $username, $domain));
				
				return $certificate['validTo_time_t'];
			} catch(Exception $e) {
				return $e->getMessage();
			}
		}
	}
?>