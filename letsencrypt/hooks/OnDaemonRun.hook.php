<?php
	require_once(dirname(dirname(__FILE__)) . '/code/LetsEncrypt.php');
	
	class Cronjob {
		private $letsencrypt = null;
		public function __construct() {
			$this->output('START Let\'s Encrypt Config Hook.', $pre_break = true);
			$this->letsencrypt = new LetsEncrypt(ctrl_options::GetSystemOption('hosted_dir'));
			
			if(ui_module::CheckModuleEnabled('Let\'s Encrypt')) {
				$this->output('Renewing certificates...', $indent = 1);
				$this->renewCerificates();
				
				$this->output('Check Wildcard Requests...', $indent = 1);
				$this->requestWildcards();
				
				$this->output('Check TLD List cache...', $indent = 1);
				$this->checkTLDCache();
				
				$this->reloadingApache();
			} else {
				$this->output('Let\'s Encrypt module is Disabled.', $indent = 1);
			}
			
			$this->output('END Let\'s Encrypt Config Hook.');
		}
		
		private function requestWildcards() {
			global $zdbh;
			
			$this->output('> Wildcard Certificates are currently not supported.', $indent = 2);
			
			/*
			$statement	= $zdbh->prepare('SELECT * FROM `x_letsencrypt` WHERE `le_time_finished` IS NULL ORDER BY `le_time_created` DESC');
			$statement->execute();
			
			if($statement->rowCount() > 0) {
				foreach($statement->fetchAll(PDO::FETCH_OBJ) AS $domain) {
					$this->output('Requesting Wildcard certificate for ' . $domain->le_domain, $indent = 2);
				}
			}*/
		}
		
		private function checkTLDCache() {
			$tld = $this->letsencrypt->getTLD();
			
			$this->output('> fetch TLD List from ' . $tld->getURL(), $indent = 2);
			$this->output('> local cache file time: ' . date('m/d/Y - H:i:s', $tld->getCachedTime()), $indent = 2);
			$this->output('> is cache expired? ' . ($tld->isCacheExpired() ? 'YES' : 'No'), $indent = 2);
			$this->output('> has the online list changes? ' . ($tld->hasChanges() ? 'YES' : 'No'), $indent = 2);
			
			if($tld->isCacheExpired() && $tld->hasChanges() || $tld->hasChanges()) {
				$this->output('> fetch new version...', $indent = 2);
				$tld->renew();
			}
			
			$this->output('> Finished.', $indent = 2);
		}
		
		private function hasAlreadyCertificateType($username, $domain, $wildcard = false) {
			return file_exists(sprintf('%s%s/letsencrypt/%s%s.fullchain', ctrl_options::GetSystemOption('hosted_dir'), $username, ($wildcard ? '*.' : ''), $domain));
		}
		
		private function renewCerificates() {
			global $zdbh;
			
			$statement	= $zdbh->prepare('SELECT `x_vhosts`.`vh_name_vc`, `x_vhosts`.`vh_type_in`, `x_accounts`.`ac_user_vc`, `x_accounts`.`ac_email_vc` FROM `x_vhosts`, `x_accounts` WHERE `x_vhosts`.`vh_enabled_in`=1 AND `x_vhosts`.`vh_deleted_ts` IS NULL AND `x_vhosts`.`vh_acc_fk`=`x_accounts`.`ac_id_pk`');
			$statement->execute();
			
			if($statement->rowCount() > 0) {
				foreach($statement->fetchAll(PDO::FETCH_OBJ) AS $domain) {
					if($domain->vh_type_in === '2' && $this->hasAlreadyCertificateType($domain->ac_user_vc, $domain->vh_name_vc, true)) {
						$this->output('Skipping Subdomain with Wildcard certificate for ' . $domain->vh_name_vc, $indent = 2);
					} else if($this->hasAlreadyCertificateType($domain->ac_user_vc, $domain->vh_name_vc, true)) {
						$this->output('Skipping Wildcard certificate for ' . $domain->vh_name_vc, $indent = 2);
					} else {
						$this->output('Checking certificate for ' . $domain->vh_name_vc, $indent = 2);
						
						if($this->hasAlreadyCertificateType($domain->ac_user_vc, $domain->vh_name_vc)) {
							$time = $this->letsencrypt->getTime($domain->ac_user_vc, $domain->vh_name_vc);
							$days = $this->letsencrypt->getRemainingDays($domain->ac_user_vc, $domain->vh_name_vc);
							
							$this->output('Valid until: ' . date('m/d/Y - H:i:s', $time), $indent = 3);
							$this->output('In Days: ' . ((int) $days), $indent = 3);
							
							if($days <= 30) {
								$this->output('Certificate will be runs out, renewing,...', $indent = 3);
								
								$register = $this->letsencrypt->register($domain->ac_user_vc, $domain->ac_email_vc);
								
								if(is_bool($register)) {
									if(!$register) {
										$this->output('Error: can\'t create or use the Account with email ' . $domain->ac_email_vc . ' from user ' . $domain->ac_user_vc);
									}
								} else if(!empty($register)) {
									$this->output('Error: ' . $register);
								}
								
								$result = $this->letsencrypt->renewCertificate($domain->ac_user_vc, $domain->vh_name_vc, ($domain->vh_type_in === '2'));
								
								if(is_bool($result)) {
									if($result) {
										$time = $this->letsencrypt->getTime($domain->ac_user_vc, $domain->vh_name_vc);
										$days = $this->letsencrypt->getRemainingDays($domain->ac_user_vc, $domain->vh_name_vc);
										
										$this->output('Certificate was renewed. It\'s now valid until: ' . date('m/d/Y - H:i:s', $time) . ' (' . ((int) $days) . ' days)');
									} else {
										$this->output('Error: Can\' renewing certificate');
									}
								} else {
									$this->output('Error: ' . $result);
								}
							}
						}
					}
				}
			}		
		}
		
		private function reloadingApache() {
			$result = 0;

			if(sys_versions::ShowOSPlatformVersion() == 'Windows') {
				system(ctrl_options::GetSystemOption('httpd_exe') . ' ' . ctrl_options::GetSystemOption('apache_restart'), $result);
			} else {
				$result = ctrl_system::systemCommand(ctrl_options::GetSystemOption('zsudo'), [
					'service',
					ctrl_options::GetSystemOption('apache_sn'),
					ctrl_options::GetSystemOption('apache_restart')
				]);
			}

			$this->output('Apache reload: ' . ((0 === $result) ? 'suceeded' : 'failed'), $indent = 1);
		}
		
		public function output($message = '', $indent = 0, $break = true, $pre_break = false) {
			if($pre_break) {
				print fs_filehandler::NewLine();
			}
			
			if($indent > 0) {
				for($position = 0; $position < $indent; $position++) {
					print "\t";
				}
			}
			
			print $message;
			
			if($break) {
				print fs_filehandler::NewLine();
			}
		}
	}
	
	new Cronjob();
?>
