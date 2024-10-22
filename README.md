![LOGO](https://github.com/SKUDONET/skdlb/assets/139971696/3389c323-5543-44a0-9768-79fa6497ed95)

# [SKUDONET Open Source Load Balancer and Open Source WAF](https://www.skudonet.com)
This is the repository of **SKUDONET Open Source Load Balancer and Open Source WAF** Community Edition (**Zen Load Balancer** CE next generation) and it'll guide you to install a development and testing instance of load balancer.

## Repository Contents
In this repository you'll find the source code usually placed into the folder `/usr/local/skudonet/` with the following structure:
- **app/**: Applications, binaries and libraries that SKUDONET Load Balancer requires.
- **bin/**: Additional application binaries directory. 
- **backups/**: Default folder where the configuration backups will be placed.
- **config/**: Default folder where the load balancing services, health checks, IPDS WAF and network configuration files will be placed.
- **etc/**: Some system files to configure SKUDONET Load Balancer services.
- **lib/**: Folder where Skudonet funcionality library is located.
- **share/**: Folder for templates and other data.
- **www/**: Backend API source files of SKUDONET Load Balancer.
- *other*: License and this readme information.
And `/usr/share/perl5/Skudonet` with the entire Skudonet backend core.

## SKUDONET Load Balancer Installation

Currently, there is only available package for Debian Bookworm, the installation is not supported out of this operating system.

There are two options to deploy a SKUDONET load balancer: The first is deploying the SKUDONET CE ISO, and the other is deploying a Debian Bookworm image and installing Skudonet with its dependencies.

### ISO

SKUDONET CE ISO is a Debian Bookworm template with Skudonet already installed. It can be got from the following link, clicking on the "Download ISO image" button.

https://www.skudonet.com/products/community/

![UEFI](https://github.com/user-attachments/assets/7de1949f-3fd9-4313-86d0-793b94300f3f)

### Installation on Debian Bookworm

If you prefer install skudonet yourself, you should get a Debian ISO installable from [debian.org](https://www.debian.org/distrib/). This installation process has been only tested with the 64 bits version.

Please, take into account these **requirements** before installing the load balancer:

1. You'll need at least 1,5 GB of storage.

2. Install a fresh and basic Debian Bookworm (64 bits) system with *openssh* and the basic system tools package recommended during the distribution installation.

3. Configure the load balancer with a static IP address. SKUDONET Load Balancer doesn't support DHCP yet.

4. Configure the *apt* repositories in order to be able to install some dependencies.


This git repository only contains the source code, the installable packages based in this code are updated in our Skudonet APT repos, you can use them configuring your Debian Bookworm system as follows: 

```
root@skudonetlb#> echo "deb http://repo.skudonet.com/ce/v7 bookworm main" >> /etc/apt/sources.list.d/skudonet.list
root@skudonetlb#> wget -O - http://repo.skudonet.com/ce/skudonet.com.gpg.key | apt-key add -
```
Now, update the local APT database
```
root@skudonetlb#> apt-get update
```
And finally, install the Skudonet CE
```
root@skudonetlb#> apt-get install skudonet
```

### Install the OWASP CoreRuleSet Rules in SKUDONET Community version

1. Go to a directory to download the OWASP CoreRuleSet
```
root@skudonetlb#> cd /opt
```

2. Download the latest OWASP CoreRuleSet
```
root@skudonetlb#> wget https://github.com/coreruleset/coreruleset/archive/refs/heads/main.zip
```

3. Decompress the OWASP CoreRuleSet file
```
root@skudonetlb#> unzip main.zip
```

4. Copy all the Rulesets and data to SKUDONET IPDS WAF Rulesets config directory
```
root@skudonetlb#> cp coreruleset-main/rules/* /usr/local/skudonet/config/ipds/waf/sets/
```

5. Copy the setup example file to SKUDONET IPDS WAF Rulesets config directory
  It is mandatory to setup tx.crs_setup_version
```
root@skudonetlb#> grep -v "^SecDefaultAction" coreruleset-main/crs-setup.conf.example > /usr/local/skudonet/config/ipds/waf/sets/REQUEST-90-CONFIGURATION.conf
```

Now the SKUDONET Opensource Load Balancer has all the OWASP Rulesets and them can be applied to the HTTP/S Farms. 

## Updates

Please use the Skudonet APT repo in order to check if updates are available. 

## Troubleshooting

The Perl errors are logging to /var/log/cherokee-error.log file.
The Web GUI access logs are logging to /var/log/cherokee-access.log file.
All the software logs ( farm logs, WAF logs, SKUDONET logs ) go to /var/log/syslog file.
Config files are saved in the directory /usr/local/skudonet/config.
SKUDONET WAF Rulesets are saved in the directory /usr/local/skudonet/config/ipds/waf/sets.

## How to Contribute
You can contribute with the evolution of the SKUDONET Load Balancer in a wide variety of ways:

- **Creating content**: Documentation in the [GitHub project wiki](https://github.com/skudonet/skdlb/wiki), doc translations, documenting source code, etc.
- **Help** to other users through the mailing lists.
- **Reporting** and **Resolving Bugs** from the [GitHub project Issues](https://github.com/skudonet/skdlb/issues).
- **Development** of new features.

### Reporting Bugs
Please use the [GitHub project Issues](https://github.com/skudonet/skdlb/issues) to report any issue or bug with the software. Try to describe the problem and a way to reproduce it. It'll be useful to attach the service and network configurations as well as system and services logs.

### Development & Resolving Bugs
In order to commit any change, as new features, bug fix or improvement, just perform a `git clone` of the repository, `git add` when all the changes has been made and `git commit` when you're ready to send the change.

During the submit, please ensure that every change is associated to a *logical change* in order to be easily identified every change.

In the commit description please use the following format:
```
[CATEGORY] CHANGE_SHORT_DESCRIPTION

OPTIONAL_LONGER_DESCRIPTION

SIGNED_OFFS

MODIFIED_FILES
```

Where:
- `CATEGORY` is either: **Bugfix** for resolving bugs or issues, **Improvement** for enhancements of already implemented features or **New Feature** for new developments that provides a new feature not implemented before.
- `CHANGE_SHORT_DESCRIPTION` is a brief description related with the change applied and allows to identify easily such modification. If it's related to a bug included in the Issues section it's recommended to include the identification reference for such bug.
- `OPTIONAL_LONGER_DESCRIPTION` is an optional longer description to explain details about the change applied.
- `SIGNED_OFFS` is the `Signed-off-by` entry where the username followed by the email can be placed.
- `MODIFIED_FILES` are the list of files that hace been modified, created or deleted with the commit.

Usually, executing `git commit -a -s` will create the fields described above.

Finally, just execute a `git push` and request a pull of your changes. In addition, you can use `git format-patch` to create your patches and send them through the official distribution list.

### Screenshots

![skd7_dashboard](https://github.com/user-attachments/assets/f10ef46c-1b38-46e0-8b14-3ce297052184)
![skd7_farms](https://github.com/user-attachments/assets/745edd31-30c6-4d3f-9122-b908d10aed2f)
![skd7_letsencrypt](https://github.com/user-attachments/assets/fdd58736-c8a5-4296-80c9-9c9ab5d949da)
![skd7_services](https://github.com/user-attachments/assets/d0c5f4f3-428d-4cd5-afb7-65542183f530)
![skd7_dhcp](https://github.com/user-attachments/assets/dbf599a3-62e5-406f-822f-100daf34f2b0)
![skd7_wafedit](https://github.com/user-attachments/assets/68cea9f0-25d1-4447-9bc6-eeb40de50d4b)
![skd7_waffarm](https://github.com/user-attachments/assets/d4f60d11-6a76-4429-b1ef-c43db866732e)

### Creating & Updating Documentation or Translations
In the official [GitHub wiki](https://github.com/skudonet/skdlb/wiki) there is available a list of pages and it's translations. Please clone the wiki, apply your changes and request a pull in order to be applied.

### Helping another Users
The official distribution list could be accessed through the [skudonet-ce-users google group](https://groups.google.com/a/skudonet.com/group/skudonet-ce-users/).

To post in this group, send email to [skudonet-ce-users@skudonet.com](mailto:skudonet-ce-users@skudonet.com).

But **you need to request a join** first into the group by sending an email to [skudonet-ce-users+subscribe@skudonet.com](mailto:skudonet-ce-users+subscribe@skudonet.com).

To unsubscribe from this group, send email to skudonet-ce-users+unsubscribe@skudonet.com

For more options, visit https://groups.google.com/a/skudonet.com/d/optout


## [www.skudonet.com](https://www.skudonet.com)
