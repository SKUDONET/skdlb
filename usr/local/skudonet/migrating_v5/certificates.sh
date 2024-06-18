#!/bin/bash

# Migrate certificates files to new directory
mv /usr/local/skudonet/config/{*.pem,*.csr,*.key} /usr/local/skudonet/config/certificates/ 2>/dev/null

# Migrate certificate of farm config file
for i in $(find /usr/local/skudonet/config/ -name "*_proxy.cfg" -o -name "*_pound.cfg");
do
	if grep 'Cert \"\/usr\/local\/skudonet\/config\/\w.*\.pem' $i | grep -qv certificates; then
		echo "Migrating certificate directory of config file"
		sed -i -e 's/Cert \"\/usr\/local\/skudonet\/config/Cert \"\/usr\/local\/skudonet\/config\/certificates/' $i
	fi
done

# Migrate http server certificate
http_conf="/usr/local/skudonet/app/cherokee/etc/cherokee/cherokee.conf"

grep -E "/usr/local/skudonet/config/[^\/]+.pem" $http_conf
if [ $? -eq 0 ]; then
	echo "Migrating certificate of http server"
	perl -E '
use strict;
use Tie::File;
tie my @fh, "Tie::File", "/usr/local/skudonet/app/cherokee/etc/cherokee/cherokee.conf";
foreach my $line (@fh)
{
	if ($line =~ m"/usr/local/skudonet/config/[^/]+\.(pem|csr|key)" )
	{

		unless( $line =~ s"/usr/local/skudonet/config"/usr/local/skudonet/config/certificates"m)
		{
			say "Error modifying: >$line<";
		}
		say "migrated $line";
	}
}
close @fh;
	'
fi

