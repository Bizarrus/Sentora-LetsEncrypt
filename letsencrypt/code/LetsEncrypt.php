<?php
	class LetsEncrypt {
		private $acme		= null;
		private $host_path	= null;
		private $account	= null;
		
		public function __construct($host_path) {
			$this->acme			= new ACMECert();
			$this->host_path	= $host_path;
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
		
		public function createCertificate($domain) {
			if(empty($this->account)) {
				return false;
			}
			
			try {
				$config = [
					$domain	=> [
						'challenge' => 'http-01',
						'docroot'	=> sprintf('%s%s/public_html/%s/', $this->host_path, $this->account, str_replace('.', '_', $domain))
					]
				];
				
				if(!(count(explode('.', $domain)) > 2)) {
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
				$certificate = $this->acme->revoke(sprintf('file://%s%s/letsencrypt/%s.fullchain', $this->host_path, $username, $domain));
				
				return true;
			} catch(Exception $e) {
				return $e->getMessage();
			}
			
			return false;
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