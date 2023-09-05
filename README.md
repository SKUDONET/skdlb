![LOGO](https://github.com/SKUDONET/skdlb/assets/139971696/49c9cb23-e2ab-4bd6-93ca-a1efe29fe240)

# [SKUDONET Load Balancer](https://www.skudonet.com)
This is the repository of **SKUDONET Load Balancer** Community Edition (**Zen Load Balancer** CE next generation) and it'll guide you to install a development and testing instance of load balancer.

## Repository Contents
In this repository you'll find the source code usually placed into the folder `/usr/local/skudonet/` with the following structure:
- **app/**: Applications, binaries and libraries that SKUDONET Load Balancer requires.
- **bin/**: Additional application binaries directory. 
- **backups/**: Default folder where the configuration backups will be placed.
- **config/**: Default folder where the load balancing services, health checks and network configuration files will be placed.
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

![UEFI](https://github.com/SKUDONET/skdlb/assets/139971696/657c34f4-df8b-40c1-aa26-9fb1e1bdc490)

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

## Updates

Please use the Skudonet APT repo in order to check if updates are available. 


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

![skd7_dashboard](https://github.com/SKUDONET/skdlb/assets/139971696/21cab240-f404-422b-86e0-9b982bc91e7f)
![skd7_farms](https://github.com/SKUDONET/skdlb/assets/139971696/5bb18d4d-be4c-4602-b02f-cb8fe0b3ad3e)
![skd7_letsencrypt](https://github.com/SKUDONET/skdlb/assets/139971696/55e86ec5-6b94-4f39-86f6-d110f11976ad)
![skd7_services](https://github.com/SKUDONET/skdlb/assets/139971696/888abde7-5f39-4207-b60e-04f6787e434e)

### Creating & Updating Documentation or Translations
In the official [GitHub wiki](https://github.com/skudonet/skdlb/wiki) there is available a list of pages and it's translations. Please clone the wiki, apply your changes and request a pull in order to be applied.

### Helping another Users
The official distribution list could be accessed through the [skudonet-ce-users google group](https://groups.google.com/a/skudonet.com/group/skudonet-ce-users/).

To post in this group, send email to [skudonet-ce-users@skudonet.com](mailto:skudonet-ce-users@skudonet.com).

But **you need to request a join** first into the group by sending an email to [skudonet-ce-users+subscribe@skudonet.com](mailto:skudonet-ce-users+subscribe@skudonet.com).

To unsubscribe from this group, send email to skudonet-ce-users+unsubscribe@skudonet.com

For more options, visit https://groups.google.com/a/skudonet.com/d/optout


## [www.skudonet.com](https://www.skudonet.com)
