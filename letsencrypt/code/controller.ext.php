<?php
	require_once(dirname(__FILE__, 1) . '/ACMECert.php');
	require_once(dirname(__FILE__, 1) . '/LetsEncrypt.php');
	
	class module_controller extends ctrl_module {
		static $result;
		static $letsencrypt = null;
		
		static function init() {
			if(empty(self::$letsencrypt)) {
				self::$letsencrypt	= new LetsEncrypt(ctrl_options::GetSystemOption('hosted_dir'));
			}
		}
		
		static function getDomainList() {
			global $zdbh, $controller;
			
			self::init();
			
			$user = ctrl_users::GetUserDetail();
			
			$domains	= [];
			$statement	= $zdbh->prepare('SELECT * FROM `x_vhosts` WHERE `vh_acc_fk`=:user AND `vh_deleted_ts` IS NULL ORDER BY `vh_name_vc` ASC');
			$statement->execute([
				'user'	=> $user['userid']
			]);
			
			foreach($statement->fetchAll(PDO::FETCH_OBJ) AS $domain) {
				$exists		= file_exists(sprintf('%s%s/letsencrypt/%s.fullchain', ctrl_options::GetSystemOption('hosted_dir'), $user['username'], $domain->vh_name_vc));
				$html		= '';
				$time		= self::$letsencrypt->getTime($user['username'], $domain->vh_name_vc);
				
				if($exists) {
					$html .= sprintf('<button class="button-loader btn btn-danger" type="submit" id="button" name="revoke" value="%s">' . ui_language::translate('Revoke') . '</button>', $domain->vh_name_vc);
				} else {
					$html  = sprintf('<button class="button-loader btn btn-success" type="submit" id="button" name="create" value="%s">' . ui_language::translate('Create') . '</button>', $domain->vh_name_vc);
				}
				
				$domains[]	= [
					'domain'	=> $domain->vh_name_vc,
					'actions'	=> $html,
					'status'	=> ($exists ? '<strong class="text-success">' . ui_language::translate('Enabled') . '</strong><br />' . ui_language::translate('Valid until') . ': ' . date(ctrl_options::GetSystemOption('Sentora_df'), $time) : '<strong class="text-danger">' . ui_language::translate('Disabled') . '</strong>')
				];
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
		
		static function doUpdate() {
			global $zdbh, $controller;
			
			self::init();
			runtime_csfr::Protect();
		
			$form = $controller->GetAllControllerRequests('FORM');
			
			if(isset($form['create']) && !empty($form['create'])) {
				$response = self::CreateRequest($form['create']);
				self::WriteVHost($form['create'], $response);
			} else if(isset($form['revoke']) && !empty($form['revoke'])) {
				$response = self::RevokeRequest($form['revoke']);
				self::WriteVHost($form['revoke'], $response);
			}
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
			
			$result = self::$letsencrypt->createCertificate($domain);
			
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
		
		static function RevokeRequest($domain) {
			self::init();
			
			$user			= ctrl_users::GetUserDetail();
			$file			= sprintf('%s%s/letsencrypt/%s.fullchain', ctrl_options::GetSystemOption('hosted_dir'), $user['username'], $domain);
			$exists			= file_exists($file);
			
			if(!$exists) {
				self::$result = 'NOT_EXISTS';
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
		
		static function UpdateApache() {
			global $zdbh;
			
			$zdbh->prepare('UPDATE `x_settings` SET `so_value_tx`=\'true\' WHERE `so_name_vc`=\'apache_changed\'')->execute();
		}
		
		static function WriteVHost($domain, $create = true) {
			global $zdbh;
			
			$user		= ctrl_users::GetUserDetail();
			$template	= ($create ? str_replace([
				'$PATH',
				'$USER',
				'$DOMAIN'
			], [
				ctrl_options::GetSystemOption('hosted_dir'),
				$user['username'],
				$domain
			], file_get_contents(dirname(__FILE__, 2) . '/vhost.template')) : NULL);
			
			
			$statement	= $zdbh->prepare('UPDATE `x_vhosts` SET `vh_custom_tx`=:template, `vh_custom_port_in`=:port, `vh_portforward_in`=:forward WHERE `vh_name_vc`=:domain');
			$statement->execute([
				'domain'	=> $domain,
				'port'		=> ($create ? 443 : NULL),
				'forward'	=> ($create ? 1 : NULL),
				'template'	=> $template
			]);
			
			self::UpdateApache();
		}
		
		static function getResult() {
			switch(self::$result) {
				case 'CREATED':
					return ui_sysmessage::shout(ui_language::translate('The SSL certificat has been created.'));
				break;
				case 'ALREADY_EXISTS':
					return ui_sysmessage::shout(ui_language::translate('The SSL certificat is all ready exists.'));
				break;
				case 'NOT_EXISTS':
					return ui_sysmessage::shout(ui_language::translate('You can\'t revoke the Certificate, it doesnt exists.'));
				break;
				case 'CREATED_ACCOUNT_ERROR':
					return ui_sysmessage::shout(ui_language::translate('Problem with Let\'s Encrypt registration.'));
				break;
				case 'CREATED_FAILED':
					return ui_sysmessage::shout(ui_language::translate('Error by retrieving the Let\'s Encrypt certificate.'));
				break;
				case 'REVOKED':
					return ui_sysmessage::shout(ui_language::translate('The SSL certificat has been revoked.'));
				break;
				case 'REVOKE_FAILED':
					return ui_sysmessage::shout(ui_language::translate('The SSL certificat can\'t revoke: internal Error.'));
				break;
				default:
					if(!empty(self::$result)) {
						return ui_sysmessage::shout(self::$result);
					}
				break;
			}
			
			return;
		}
	}
?>