<?php
	global $zdbh;
	
	$deleted = [];
	
	if($numrows = $zdbh->query('SELECT COUNT(*) FROM `x_vhosts` WHERE `vh_deleted_ts` IS NOT NULL')) {
		if($numrows->fetchColumn() <> 0) {
			$sql = $zdbh->prepare('SELECT * FROM `x_vhosts` WHERE `vh_deleted_ts` IS NOT NULL');
			$sql->execute();
			
			while($vhost = $sql->fetch()) {
				$deleted[] = $vhost['vh_id_pk'];
			}
		}
	}
	
	foreach($deleted AS $domain) {
		// Delete all files from $domain
	}
	
	// Reloading Apache
?>