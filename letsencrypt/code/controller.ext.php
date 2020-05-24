<?php
	require_once('LetsEncrypt.php');
	
	class module_controller extends ctrl_module {
		static $result;
		static $letsencrypt = null;
		
		static function init() {
			if(empty(self::$letsencrypt)) {
				self::$letsencrypt	= new LetsEncrypt(ctrl_options::GetSystemOption('hosted_dir'), self::getTLDListCacheOption());
			}
		}
		
		static function getDomainValidationOptionFetch() {
			return (self::DomainValidationOption() === 'fetch');
		}
		
		static function getDomainValidationOptionDatabase() {
			return (self::DomainValidationOption() === 'database');
		}
		
		static function DomainValidationOption() {
			$result	= ctrl_options::GetSystemOption('letsencrypt_domain_validation');
			
			if(is_bool($result) && !$result) {
				$result = 'fetch';
			}
			
			return $result;
		}
		
		static function getTLDListCacheOption() {
			$result	= ctrl_options::GetSystemOption('letsencrypt_tld_list_cache');
			
			if(is_bool($result)) {
				return $result;
			}
			
			if(in_array(strtolower($result), [
				'true',
				'1',
				'on',
				'enabled'
			])) {
				return true;
			}
			
			return false;
		}
		
		static function getNotAvailablePermissions() {
			if(!self::getPermissionSingleOption() && self::getPermissionWildcardOption()) {
				return false;
			}
			
			if(!self::getPermissionWildcardOption() && self::getPermissionSingleOption()) {
				return false;
			}
			
			if(!self::getPermissionWildcardOption() && !self::getPermissionSingleOption()) {
				return true;
			}
			
			return false;
		}
		
		static function getPermissionSingleOption() {
			$result	= ctrl_options::GetSystemOption('letsencrypt_permission_single');
			
			if(is_bool($result)) {
				return $result;
			}
			
			if(in_array(strtolower($result), [
				'true',
				'1',
				'on',
				'enabled'
			])) {
				return true;
			}
			
			return false;
		}
		
		static function getPermissionWildcardOption() {
			$result	= ctrl_options::GetSystemOption('letsencrypt_permission_wildcard');
			
			if(is_bool($result)) {
				return $result;
			}
			
			if(in_array(strtolower($result), [
				'true',
				'1',
				'on',
				'enabled'
			])) {
				return true;
			}
			
			return false;
		}
		
		static function getPermissionWildcardSubdomainOption() {
			$result	= ctrl_options::GetSystemOption('letsencrypt_permission_wildcard_subdomains');
			
			if(is_bool($result)) {
				return $result;
			}
			
			if(in_array(strtolower($result), [
				'true',
				'1',
				'on',
				'enabled'
			])) {
				return true;
			}
			
			return false;
		}
		
		static function getHasAndyDomains() {
			global $zdbh;
			
			self::init();
			
			$user		= ctrl_users::GetUserDetail();
			$domains	= [];
			$statement	= $zdbh->prepare('SELECT * FROM `x_vhosts` WHERE `vh_acc_fk`=:user AND `vh_deleted_ts` IS NULL ORDER BY `vh_name_vc` ASC');
			$statement->execute([
				'user'	=> $user['userid']
			]);
			
			return ($statement->rowCount() > 0);
		}
		
		static function getDisabledDomainList() {
			global $zdbh;
			
			self::init();
			
			$user		= ctrl_users::GetUserDetail();
			$domains	= [];
			$statement	= $zdbh->prepare('SELECT * FROM `x_vhosts` WHERE `vh_acc_fk`=:user AND `vh_deleted_ts` IS NULL ORDER BY `vh_name_vc` ASC');
			$statement->execute([
				'user'	=> $user['userid']
			]);
			
			foreach($statement->fetchAll(PDO::FETCH_OBJ) AS $domain) {
				$html		= '';
				$list		= false;
				
				if(self::HasAlreadyCertificateType($user['username'], $domain->vh_name_vc, true) || self::HasAlreadyCertificateType($user['username'], $domain->vh_name_vc)) {
					/* Do Nothing */
				} else {
					$list	= true;
					
					if($domain->vh_type_in === '2' && self::HasAlreadyCertificateType($user['username'], self::removeSubdomain($domain->vh_name_vc), true)) {
						$html	= sprintf('<strong class="text-warning">Exists as Wildcard</strong><br /><i class="text-muted">*.%s</i>', self::removeSubdomain($domain->vh_name_vc));
					} else if(self::IsWildcardRequestExists($domain->vh_name_vc)) {
						$html	= sprintf('<strong class="text-warning">Pending Wildcard</strong>', $domain->vh_name_vc);
					} else {
						// Database: check if the domain already has an Wildcard request
						$html	= sprintf('<button class="button-loader btn btn-success" type="submit" id="create" name="create" value="%s">' . ui_language::translate('Create') . '</button>', $domain->vh_name_vc);
					}
				}
				
				if($list) {
					$nameserver_domain = $domain->vh_name_vc;
					
					if($domain->vh_type_in === '2') {
						$nameserver_domain = self::removeSubdomain($domain->vh_name_vc);
					}
					
					$domains[]	= [
						'domain'		=> $domain->vh_name_vc,
						'actions'		=> $html,
						'nameservers'	=> json_encode([
							'needed'	=> [
								'ns1.' . $nameserver_domain,
								'ns2.' . $nameserver_domain
							],
							'valid'		=> self::HasSentoraDNS($nameserver_domain),
							'entries'	=> self::GetNameservers($nameserver_domain)
						])
					];
				}
			}
			
			return $domains;
		}
		
		static function removeSubdomain($domain) {
			$reparted	= explode('.', $domain);
			array_shift($reparted);
			return implode('.', $reparted);
		}
		
		static function getWildcardDomainList() {
			global $zdbh, $controller;
			
			self::init();
			
			$user		= ctrl_users::GetUserDetail();
			$domains	= [];
			$statement	= $zdbh->prepare('SELECT * FROM `x_vhosts` WHERE `vh_acc_fk`=:user AND `vh_deleted_ts` IS NULL ORDER BY `vh_name_vc` ASC');
			$statement->execute([
				'user'	=> $user['userid']
			]);
			
			foreach($statement->fetchAll(PDO::FETCH_OBJ) AS $domain) {
				$html		= '';
				$status		= '';
				$list		= false;
				$time		= self::$letsencrypt->getTime($user['username'], sprintf('*.%s', $domain->vh_name_vc));
				
				if(!self::HasAlreadyCertificateType($user['username'], $domain->vh_name_vc, true)) {
					/* Do Nothing */
				} else {
					$status = '<strong class="text-success">' . ui_language::translate('Enabled') . '</strong><br />' . ($time <= 0.00 ? '<strong class="text-warning">' . ui_language::translate('EXPIRED since') .  '</strong>' : ui_language::translate('Valid until')) . ': ' . date(ctrl_options::GetSystemOption('Sentora_df'), $time);
					$list = true;
					$html .= sprintf('<button class="button-loader btn btn-warning" type="submit" id="button" name="renew" value="%s">' . ui_language::translate('Renew') . '</button>', $domain->vh_name_vc);
					$html .= ' ';
					$html .= sprintf('<button class="button-loader btn btn-danger" type="submit" id="button" name="revoke" value="%s">' . ui_language::translate('Revoke') . '</button>', $domain->vh_name_vc);
				}
				
				if($list) {
					$domains[]	= [
						'domain'	=> $domain->vh_name_vc,
						'actions'	=> $html,
						'status'	=> $status
					];
				}
			}
		
			return $domains;
		}
		
		static function HasAlreadyCertificateType($username, $domain, $wildcard = false) {
			return file_exists(sprintf('%s%s/letsencrypt/%s%s.fullchain', ctrl_options::GetSystemOption('hosted_dir'), $username, ($wildcard ? '*.' : ''), $domain));
		}
		
		static function getSingleDomainList() {
			global $zdbh, $controller;
			
			self::init();
			
			$user		= ctrl_users::GetUserDetail();
			$domains	= [];
			$statement	= $zdbh->prepare('SELECT * FROM `x_vhosts` WHERE `vh_acc_fk`=:user AND `vh_deleted_ts` IS NULL ORDER BY `vh_name_vc` ASC');
			$statement->execute([
				'user'	=> $user['userid']
			]);
			
			foreach($statement->fetchAll(PDO::FETCH_OBJ) AS $domain) {
				$html		= '';
				$status		= '';
				$list		= false;
				$time		= self::$letsencrypt->getTime($user['username'], $domain->vh_name_vc);
				
				if(!self::HasAlreadyCertificateType($user['username'], $domain->vh_name_vc)) {
					/* Do Nothing */
				} else {
					$status = '<strong class="text-success">' . ui_language::translate('Enabled') . '</strong><br />' . ($time <= 0.00 ? '<strong class="text-warning">' . ui_language::translate('EXPIRED since') .  '</strong>' : ui_language::translate('Valid until')) . ': ' . date(ctrl_options::GetSystemOption('Sentora_df'), $time);
					$list = true;
					$html .= sprintf('<button class="button-loader btn btn-warning" type="submit" id="button" name="renew" value="%s">' . ui_language::translate('Renew') . '</button>', $domain->vh_name_vc);
					$html .= ' ';
					$html .= sprintf('<button class="button-loader btn btn-danger" type="submit" id="button" name="revoke" value="%s">' . ui_language::translate('Revoke') . '</button>', $domain->vh_name_vc);
				}
				
				if($list) {
					$domains[]	= [
						'domain'	=> $domain->vh_name_vc,
						'actions'	=> $html,
						'status'	=> $status
					];
				}
			}
		
			return $domains;
		}
		
		static function getSSLEnabled() {
			self::init();
			
			return in_array('mod_ssl', apache_get_modules());
		}
		
		static function getAdmin() {
			self::init();
			
			$user = ctrl_users::GetUserDetail();
			
			return ($user['usergroup'] == 'Administrators');
		}
		
		static function doUpdateSettings() {
			global $zdbh, $controller;
			
			if(!self::getAdmin()) {
				self::$result = 'PERMISSION_DENIED';
				return;
			}
			
			self::init();
			runtime_csfr::Protect();
		
			$form = $controller->GetAllControllerRequests('FORM');
			
			if(isset($form['action']) && !empty($form['action'])) {
				switch($form['action']) {
					case 'save':
						/* Subdomain Validations */
						if(isset($form['domain_validation']) && !empty($form['domain_validation'])) {
							$type = null;
							
							switch($form['domain_validation']) {
								case 'fetch':
									$type = 'fetch';
								break;
								case 'database':
									$type = 'database';								
								break;
							}
							
							if(!empty($type)) {
								$zdbh->prepare('UPDATE `x_settings` SET `so_value_tx`=:value WHERE `so_name_vc`=\'letsencrypt_domain_validation\'')->execute([
									'value'	=> $type
								]);
							}
						}
						
						if(isset($form['list_cache']) && !empty($form['list_cache'])) {
							$zdbh->prepare('UPDATE `x_settings` SET `so_value_tx`=:value WHERE `so_name_vc`=\'letsencrypt_tld_list_cache\'')->execute([
								'value'	=> 'true'
							]);
						} else {
							$zdbh->prepare('UPDATE `x_settings` SET `so_value_tx`=:value WHERE `so_name_vc`=\'letsencrypt_tld_list_cache\'')->execute([
								'value'	=> 'false'
							]);
						}
						
						/* Permissions */
						if(isset($form['permission_single']) && !empty($form['permission_single'])) {
							$zdbh->prepare('UPDATE `x_settings` SET `so_value_tx`=:value WHERE `so_name_vc`=\'letsencrypt_permission_single\'')->execute([
								'value'	=> 'true'
							]);
						} else {
							$zdbh->prepare('UPDATE `x_settings` SET `so_value_tx`=:value WHERE `so_name_vc`=\'letsencrypt_permission_single\'')->execute([
								'value'	=> 'false'
							]);
						}
						
						if(isset($form['permission_wildcard']) && !empty($form['permission_wildcard'])) {
							$zdbh->prepare('UPDATE `x_settings` SET `so_value_tx`=:value WHERE `so_name_vc`=\'letsencrypt_permission_wildcard\'')->execute([
								'value'	=> 'true'
							]);
						} else {
							$zdbh->prepare('UPDATE `x_settings` SET `so_value_tx`=:value WHERE `so_name_vc`=\'letsencrypt_permission_wildcard\'')->execute([
								'value'	=> 'false'
							]);
						}
						
						if(isset($form['permission_wildcard_subdomains']) && !empty($form['permission_wildcard_subdomains'])) {
							$zdbh->prepare('UPDATE `x_settings` SET `so_value_tx`=:value WHERE `so_name_vc`=\'letsencrypt_permission_wildcard_subdomains\'')->execute([
								'value'	=> 'true'
							]);
						} else {
							$zdbh->prepare('UPDATE `x_settings` SET `so_value_tx`=:value WHERE `so_name_vc`=\'letsencrypt_permission_wildcard_subdomains\'')->execute([
								'value'	=> 'false'
							]);
						}
						
						self::$result = 'SETTINGS_SAVED';
					break;
					default:
						/* Do Nothing */
					break;
				}
			}
		}
		
		static function doUpdate() {
			global $controller;
			
			self::init();
			//runtime_csfr::Protect();
		
			$form		= $controller->GetAllControllerRequests('FORM');
			$tab		= 'single';
			
			if(isset($form['tab']) && !empty($form['tab'])) {
				$tab	= $form['tab'];
			}
			
			switch($tab) {
				case 'single':
					if(isset($form['create']) && !empty($form['create'])) {
						self::WriteVHost($form['create'], self::CreateRequest($form['create']));
					} else if(isset($form['revoke']) && !empty($form['revoke'])) {
						self::WriteVHost($form['revoke'], self::RevokeRequest($form['revoke']));
					} else if(isset($form['renew']) && !empty($form['renew'])) {
						self::WriteVHost($form['renew'], self::RenewRequest($form['renew']));
					}
				break;
				case 'wildcard':
					if(isset($form['create']) && !empty($form['create'])) {
						self::CreateWildcardRequest($form['create']);
					} else if(isset($form['revoke']) && !empty($form['revoke'])) {
						$state = self::RevokeWildcardRequest($form['revoke']);
						
						if($state) {
							self::WriteWildcardVHost($form['revoke']);
						}
						
					} else if(isset($form['renew']) && !empty($form['renew'])) {
						$state = self::RenewWildcardRequest($form['renew']);
						
						if($state) {
							self::WriteWildcardVHost($form['renew']);
						}
					}
				break;
			}
		}
		
		static function IsSubdomain($domain) {
			global $zdbh;
			
			$statement	= $zdbh->prepare('SELECT `vh_type_in` FROM `x_vhosts` WHERE `vh_name_vc`=:domain LIMIT 1');
			$statement->execute([
				'domain'	=> $domain
			]);
			
			$result = $statement->fetch(PDO::FETCH_OBJ);
			
			if(!isset($result) || empty($result) || !isset($result->vh_type_in) || empty($result->vh_type_in)) {
				return false;
			}
			
			if($result->vh_type_in === '2') {
				return true;
			}
			
			return false;
		}
		
		static function CreateRequest($domain) {
			self::init();
			
			$user			= ctrl_users::GetUserDetail();
			$exists			= file_exists(sprintf('%s%s/letsencrypt/%s.fullchain', ctrl_options::GetSystemOption('hosted_dir'), $user['username'], $domain));
			
			if($exists) {
				self::$result = 'ALREADY_EXISTS';
				return false;
			}
			
			$register = self::$letsencrypt->register($user['username'], $user['email']);
			
			if(is_bool($register)) {
				if(!$register) {
					self::$result = 'CREATED_ACCOUNT_ERROR';
					return false;
				}
			} else if(!empty($register)) {
				self::$result = $register;
				return false;
			}
			
			$result = self::$letsencrypt->createCertificate($domain, self::IsSubdomain($domain));
			
			if(is_bool($result)) {
				if($result) {
					self::$result = 'CREATED';
					return true;
				} else {
					self::$result = 'CREATED_FAILED';
					return false;
				}
			}
			
			self::$result = $result;
			return false;
		}
		
		static function RenewRequest($domain) {
			self::init();
			
			$user			= ctrl_users::GetUserDetail();
			$exists			= file_exists(sprintf('%s%s/letsencrypt/%s.fullchain', ctrl_options::GetSystemOption('hosted_dir'), $user['username'], $domain));
			
			if(!$exists) {
				self::$result = 'RENEWED_NOT_EXISTS';
				return false;
			}
			
			$register = self::$letsencrypt->register($user['username'], $user['email']);
			
			if(is_bool($register)) {
				if(!$register) {
					self::$result = 'CREATED_ACCOUNT_ERROR';
					return false;
				}
			} else if(!empty($register)) {
				self::$result = $register;
				return false;
			}
			
			$result = self::$letsencrypt->renewCertificate($user['username'], $domain, self::IsSubdomain($domain));
			
			if(is_bool($result)) {
				if($result) {
					self::$result = 'RENEWED';
					return true;
				} else {
					self::$result = 'RENEWED_FAILED';
					return false;
				}
			}
			
			self::$result = $result;
			return false;
		}
		
		static function RevokeRequest($domain) {
			self::init();
			
			$user			= ctrl_users::GetUserDetail();
			$file			= sprintf('%s%s/letsencrypt/%s.fullchain', ctrl_options::GetSystemOption('hosted_dir'), $user['username'], $domain);
			$exists			= file_exists($file);
			
			if(!$exists) {
				self::$result = 'REVOKED_NOT_EXISTS';
				return false;
			}
			
			$register = self::$letsencrypt->register($user['username'], $user['email']);
			
			if(is_bool($register)) {
				if(!$register) {
					self::$result = 'CREATED_ACCOUNT_ERROR';
					return false;
				}
			} else if(!empty($register)) {
				self::$result = $register;
				return false;
			}
			
			$result = self::$letsencrypt->revokeCertificate($user['username'], $domain);
			
			if(is_bool($result)) {
				if($result) {
					self::$result = 'REVOKED';
					@unlink($file);
					return false;
				} else {
					self::$result = 'REVOKE_FAILED';
					return false;
				}
			}
			
			self::$result = $result;
			return false;
		}
		
		static function CreateWildcardRequest($domain) {
			global $zdbh;
			self::init();
			
			$user			= ctrl_users::GetUserDetail();
			$exists			= file_exists(sprintf('%s%s/letsencrypt/*.%s.fullchain', ctrl_options::GetSystemOption('hosted_dir'), $user['username'], $domain));
			
			if($exists) {
				self::$result = 'WILDCARD_ALREADY_EXISTS';
				return false;
			}
			
			if(self::IsWildcardRequestExists($domain)) {
				self::$result = 'WILDCARD_ALREADY_REQUESTED';
				return false;
			}
			
			
			if(!self::HasSentoraDNS($domain)) {
				self::$result = ui_language::translate(sprintf('You can\'t create a wildcard certificate for this domain. Please set the Nameserver to <strong>%s</strong>!', implode(', ', [
					'ns1.' . $domain,
					'ns2.' . $domain
				])));
				return false;
			}
			
			$keys	= [];
			$names	= [];
			$data	= [
				'le_id_pk'			=> NULL,
				'le_username'		=> $user['username'],
				'le_domain'			=> $domain,
				'le_time_created'	=> date('Y-m-d H:i:s', time()),
				'le_time_finished'	=> NULL
			];
			
			foreach(array_keys($data) AS $key) {
				$keys[]		= sprintf('`%s`', $key);
				$names[]	= sprintf(':%s', $key);
			}
			
			if(empty($keys) || count($keys) === 0) {
				self::$result = 'WILDCARD_CREATED_FAILED';
				return false;
			}
			
			$zdbh->prepare('INSERT INTO `x_letsencrypt` (' . implode(', ', $keys) . ') VALUES (' . implode(', ', $names) . ')')->execute($data);
			
			self::$result = 'WILDCARD_CREATED';
			return true;
		}
		
		static function IsWildcardRequestExists($domain) {
			global $zdbh;
			
			$user		= ctrl_users::GetUserDetail();
			$statement	= $zdbh->prepare('SELECT `le_id_pk` FROM `x_letsencrypt` WHERE `le_domain`=:domain AND `le_time_finished` IS NULL');
			$statement->execute([
				'domain'	=> $domain
			]);
			
			return ($statement->rowCount() > 0);
		}
		
		static function GetNameservers($domain) {
			$nameservers	= [];
			$dns			= @dns_get_record($domain, DNS_NS);
			
			/*if(!$dns) {
				if(sys_versions::ShowOSPlatformVersion() !== 'Windows') {
					$result = shell_exec('dig NS +trace ' . $domain);
					$lines	= explode("\n", $result);
					$dns	= [];
					
					foreach($lines AS $line) {
						preg_match('/^(?P<host>.*)\.\s(?P<ttl>[0-9]+)\s(?P<class>IN)\s(?P<type>NS)\s(?P<target>.*)\.$/Uis', $line, $matches);
				
						if(!empty($matches)) {
							$dns[] = [
								'type'		=> $matches['type'],
								'ttl'		=> $matches['ttl'],
								'class'		=> $matches['class'],
								'type'		=> $matches['type'],
								'target'	=> $matches['target']
							];
						}
					}
				}
			}*/
			
			if(!empty($dns)) {
				foreach($dns AS $entry) {
					if($entry['type'] === 'NS') {
						$nameservers[] = $entry['target'];
					}
				}
			}
			
			return $nameservers;
		}
		
		static function HasSentoraDNS($domain) {
			$nameservers	= self::GetNameservers($domain);
			
			// @ToDo check DNS
			return (in_array('ns1.' . $domain, $nameservers) && in_array('ns2.' . $domain, $nameservers));
		}
		
		static function RenewWildcardRequest($domain) {
			#print "Wildcard Renew...";
			#exit();
		}
		
		static function RevokeWildcardRequest($domain) {
			#print "Wildcard Renew...";
			#exit();
		}
		
		static function UpdateApache() {
			global $zdbh;
			
			$zdbh->prepare('UPDATE `x_settings` SET `so_value_tx`=\'true\' WHERE `so_name_vc`=\'apache_changed\'')->execute();
		}
		
		static function WriteVHost($domain, $create = true) {
			global $zdbh;
			
			$user		= ctrl_users::GetUserDetail();
			
			if(sys_versions::ShowOSPlatformVersion() !== 'Windows')
				{
				$template	= ($create ? str_replace([
					'$PATH',
					'$USER',
					'$DOMAIN'
				], [
					ctrl_options::GetSystemOption('hosted_dir'),
					$user['username'],
					$domain
				], file_get_contents(dirname(__FILE__, 2) . '/vhost.template')) : NULL);
				}
			else
				{
						$template	= ($create ? str_replace([
						'$PATH',
						'$USER',
						'$DOMAIN'
					], [
						ctrl_options::GetSystemOption('hosted_dir'),
						$user['username'],
						$domain
					], file_get_contents('C:/Sentora/panel/modules/letsencrypt/vhost.template')) : NULL);
				 }
			
			
			$zdbh->prepare('UPDATE `x_vhosts` SET `vh_custom_tx`=:template, `vh_custom_port_in`=:port, `vh_portforward_in`=:forward WHERE `vh_name_vc`=:domain')->execute([
				'domain'	=> $domain,
				'port'		=> ($create ? 443 : NULL),
				'forward'	=> ($create ? 1 : NULL),
				'template'	=> $template
			]);
			
			self::UpdateApache();
		}
		
		static function WriteWildcardVHost($domain) {
			
			#print "Wildcard VHOST...";
			#exit();
		}
		
		static function isTab($name, $default = false, $admin = false) {
			global $controller;
			
			$tab = self::getCurrentTab();
			
			if($admin && !self::getAdmin()) {
				return $default;
			}
			
			if(empty($tab)) {
				return $default;
			}
			
			if($tab !== $name) {
				return false;
			}
			
			return true;
		}
		
		static function getCurrentTab() {
			global $controller;
			
			$get	= $controller->GetAllControllerRequests('URL');
			$post	= $controller->GetAllControllerRequests('FORM');
			
			if(isset($post['tab']) && !empty($post['tab'])) {
				return $post['tab'];
			}
			
			if((!isset($get) || empty($get)) || (!isset($post) || empty($post))) {
				return '';
			}
			
			if(!isset($get['tab']) || empty($get['tab']) || (is_bool($get['tab']) && !$get['tab'])) {
				return '';
			}
			
			return $get['tab'];
		}
		
		static function getIsSingleTab() {
			return self::isTab('single', true);
		}
		
		static function getIsWildcardTab() {
			return self::isTab('wildcard');
		}
		
		static function getIsSettingsTab() {
			return self::isTab('settings', false, true);	
		}
		
		static function getResult() {
			switch(self::$result) {
				case 'CREATED':
					return ui_sysmessage::shout(ui_language::translate('The SSL certificate has been created.'), 'alert-success');
				break;
				case 'WILDCARD_CREATED':
					return ui_sysmessage::shout(ui_language::translate('The wildcard certificate has been requested. It can take up to 24 hours for the wildcard certificate to be delivered.'), 'alert-success');
				break;
				case 'WILDCARD_ALREADY_EXISTS':
					return ui_sysmessage::shout(ui_language::translate('The wildcard certificate already exists.'), 'notice');
				break;
				case 'WILDCARD_ALREADY_REQUESTED':
					return ui_sysmessage::shout(ui_language::translate('The wildcard certificate has already been requested.'), 'notice');
				break;
				case 'ALREADY_EXISTS':
					return ui_sysmessage::shout(ui_language::translate('The SSL certificate already exists.'), 'notice');
				break;
				case 'REVOKED_NOT_EXISTS':
					return ui_sysmessage::shout(ui_language::translate('You can\'t revoke the certificate as it doesn\'t exist.'), 'alert-error');
				break;
				case 'CREATED_ACCOUNT_ERROR':
					return ui_sysmessage::shout(ui_language::translate('Problem with Let\'s Encrypt registration.'), 'alert-error');
				break;
				case 'CREATED_FAILED':
					return ui_sysmessage::shout(ui_language::translate('Error retrieving the Let\'s Encrypt certificate.'), 'alert-error');
				break;
				case 'WILDCARD_CREATED_FAILED':
					return ui_sysmessage::shout(ui_language::translate('Error retrieving the Let\'s Encrypt wildcard certificate.'), 'alert-error');
				break;
				case 'REVOKED':
					return ui_sysmessage::shout(ui_language::translate('The SSL certificate has been revoked.'), 'alert-success');
				break;
				case 'REVOKE_FAILED':
					return ui_sysmessage::shout(ui_language::translate('The SSL certificate can\'t be revoked. There was an internal error.'), 'alert-error');
				break;
				case 'RENEWED_NOT_EXISTS':
					return ui_sysmessage::shout(ui_language::translate('You can\'t renew the certificate as it doesn\'t exist.'), 'alert-error');
				break;
				case 'RENEWED':
					return ui_sysmessage::shout(ui_language::translate('The certificate was renewed successfully.'), 'alert-success');
				break;
				case 'RENEWED_FAILED':
					return ui_sysmessage::shout(ui_language::translate('The certificate can\'t be renewed.'), 'alert-error');
				break;
				case 'SETTINGS_SAVED':
					return ui_sysmessage::shout(ui_language::translate('The settings have been saved.'), 'alert-success');
				break;
				case 'PERMISSION_DENIED':
					return ui_sysmessage::shout(ui_language::translate('You do not have permission to perform this action!'), 'alert-error');
				break;
				default:
					if(!empty(self::$result)) {
						return ui_sysmessage::shout(self::$result, 'alert-error');
					}
				break;
			}
			
			return;
		}
	}
?>
