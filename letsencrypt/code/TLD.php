<?php
	class TLD {
		private $list		= [];
		private $url		= 'https://publicsuffix.org/list/public_suffix_list.dat';
		private $cache		= './modules/letsencrypt/public_suffix_list.dat';
		private $expiration = 168 * 60 * 60; // 1 Week
		
		public function __construct($cached = false) {
			$temp	= $this->load($cached);
			$lines	= explode(PHP_EOL, $temp);
			
			foreach($lines AS $line) {
				$line = trim($line);
				
				if(empty($line)) {
					continue;
				}
				
				if(strpos($line, '//') === 0) {
					continue;
				}
				
				$this->list[] = $line;
			}
		}
		
		public function getURL() {
			return $this->url;
		}
		
		public function getOnlineList() {
			return file_get_contents($this->url);
		}
		
		public function getCachedList() {
			return file_get_contents($this->cache);
		}
		
		public function getCachedTime() {
			return filemtime($this->cache);
		}
		
		public function isCacheExpired() {
			return (time() - $this->expiration > $this->getCachedTime());
		}
		
		public function hasChanges() {
			if($this->getOnlineList() === $this->getCachedList()) {
				return false;
			}
			
			return true;
		}
		
		public function renew() {
			$content = $this->getOnlineList();
			file_put_contents($this->cache, $content);
			return $content;
		}
		
		public function load($cached = false) {
			if(!$cached) {
				return $this->getOnlineList();
			}
			
			if(file_exists($this->cache) && !$this->isCacheExpired()) {
				return $this->getCachedList();
			} else {
				return $this->renew();
			}
		}
		
		public function extracts($domain, $suffix = null) {
			$parts	= explode('.', $domain);
			$size	= count($parts);
			$result	= (object) [
				'prefix' 	=> null,
				'domain'	=> null,
				'suffix'	=> null,
				'original'	=> $domain
			];
			
			switch($size) {
				// Bad Value
				case 1:
					return null;
				break;
				
				// Default TLD
				case 2:
					$result->domain = $parts[0];
					$result->suffix = $parts[1];
				break;
				
				// Extended TLD or Subdomain
				default:
					if(empty($suffix)) {
						$locator = implode('.', [ $parts[$size - 2], $parts[$size - 1] ]);
					
						// It's a real TLD suffix
						if(in_array($locator, $this->list)) {
							return $this->extracts($domain, $locator);
							
						// Otherwise it's a subdomain
						} else {
							$result->suffix = $parts[$size - 1];
							$result->domain = $parts[$size - 2];
							$result->prefix = $parts[$size - 3];
						}
					} else {
						$result->domain = str_replace(sprintf('.%s', $suffix), '', $domain);
						$result->suffix = $suffix;
						$unmounted		= str_replace($result->suffix, '', $result->domain);
						
						// Check if extended TLD has Subdomain(s)
						if(strrpos($unmounted, '.')) {
							$reparted		= explode('.', $unmounted);
							$result->domain	= array_pop($reparted);
							$result->prefix	= implode('.', $reparted);
						}
					}
				break;
			}
			
			return $result;
		}
	}
?>