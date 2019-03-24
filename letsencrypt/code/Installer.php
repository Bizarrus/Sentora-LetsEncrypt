<?php
	require_once('cnf/db.php');
	require_once('dryden/db/driver.class.php');
	require_once('dryden/debug/logger.class.php');
	require_once('dryden/runtime/dataobject.class.php');
	require_once('dryden/sys/versions.class.php');
	require_once('dryden/ctrl/options.class.php');
	require_once('dryden/ctrl/auth.class.php');
	require_once('dryden/ctrl/users.class.php');
	require_once('dryden/fs/director.class.php');
	require_once('dryden/fs/filehandler.class.php');
	require_once('inc/dbc.inc.php');

	class Installer {
		public function settingsExists($name) {
			$result	= ctrl_options::GetSystemOption($name);
			
			if(is_bool($result) && !$result) {
				return false;
			}
			
			return true;
		}
		
		public function removeSettings($name) {
			global $zdbh;
			
			$zdbh->prepare('DELETE FROM `x_settings` WHERE `so_name_vc`=:name LIMIT 1')->execute([
				'name'	=> $name
			]);
		}
		
		public function addSettings($data) {
			global $zdbh;
			
			if(empty($data) || count($data) === 0) {
				return;
			}
			
			$keys	= [];
			$names	= [];
			
			foreach(array_keys($data) AS $key) {
				$keys[]		= sprintf('`%s`', $key);
				$names[]	= sprintf(':%s', $key);
			}


			if(empty($keys) || count($keys) === 0) {
				return;
			}
			
			$zdbh->prepare('INSERT INTO `x_settings` (' . implode(', ', $keys) . ') VALUES (' . implode(', ', $names) . ')')->execute($data);
		}
		
		public function removeTable($table) {
			global $zdbh;
			
			$zdbh->prepare('DROP TABLE IF EXISTS `' . $table . '`')->execute();
		}
		
		public function addTable($table, $definitions) {
			global $zdbh;
			
			$sql	= [];
			$id		= null;
			
			foreach($definitions AS $name => $type) {
				switch($type) {
					case 'ID':
						$id		= $name;
						$sql[]	= sprintf('`%s` int(11) NOT NULL AUTO_INCREMENT', $name);
					break;
					case 'STRING':
						$sql[] = sprintf('`%s` varchar(255) DEFAULT NULL', $name);
					break;
					case 'DATETIME':
						$sql[] = sprintf('`%s` datetime DEFAULT NULL', $name);
					break;
				}
			}
			
			if(!empty($id)) {
				$sql[] = sprintf('PRIMARY KEY (`%s`)', $id);
			}
			
			$zdbh->prepare('CREATE TABLE IF NOT EXISTS `' . $table . '` (' . implode(', ', $sql) . ') ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8')->execute();
		}
	}
?>