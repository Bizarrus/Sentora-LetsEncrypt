# ![Icon](https://raw.githubusercontent.com/Bizarrus/Sentora-LetsEncrypt/master/letsencrypt/assets/icon.png) Let's Encrypt for Sentora
Add Let's Encrypt certificates to your domain

## 📑 Available Functions
- [x] 🔑 Automated register with client E-Mail
- [x] ✳️ Request new SSL Certificates
- [x] 🚫 Revoke SSL Certificates
- [x] 🔄 Renew SSL Certificates
- [x] ✴️ Wildcard Certificates

## 🔨 Installation
```bash
zppy repo add sentcrypt.tk
zppy update

zppy install letsencrypt
```

## 📐Screenshots
![Screenshot](https://raw.githubusercontent.com/Bizarrus/Sentora-LetsEncrypt/master/screenshots/preview.png)

## 📚 Changelog
> **23.03.2019** (Version `1.0.4`)
> - ✔️ Fix **open_basedir** restrictions on PHP's require
> - ✔️ Adding some admin settings
> - ✔️ Create installation/deinstallation/update process
> - ✔️ Check TLD by public TLD list or only via database
> - ✔️ Create Caching (1 week) for public TLD list (see admin settings)
> - ✔️ Create cronjob on Sentora Daemon
> - ✔️ Remove all necessary certificate files on revoke
> - ✔️ If cert is available, change the displayed text of outdated certs
> - ✔️ Adding renewing button on list
> - ✔️ Adding renewing process
> - ✔️ UI: Beautify
> - ✔️ UI: Fix some breaking points
> - ✔️ UI: adding Tabs for normal certificates and wildcard certificates
> - ✔️ UI: change alerts depends on their state (error, info, success,...)
> - ✔️ Fix VHost template with chain file for a valid SSL configuration
> - 💥 **EXPERIMENTAL:** Create Wildcard support
> - ✔️ Check Nameserver on DNS for wildcard domains
> - ✔️ Permissions: enable/disable wildcards or single-domains
> 
> 💥 **Informations**
> 
> > The `Wildcard`feature is currently not fully implemented and it's marked as an **EXPERIMENTAL FEATURE**!
> > The problem is, that the cronjob must currently running up to the deployment process of DNS entries. The Wildcard-Features are currently not usable, by default.
> >
> > Following **ToDo**s are currently under development:
> > - If wildcard revoked, delete all VHost settings on subdomains
> > - Cronjob: If wildcard created, add VHost settings on subdomains
