#!/usr/bin/perl
###############################################################################
#
#    Skudonet Software License
#    This file is part of the Skudonet Load Balancer software package.
#
#    Copyright (C) 2014-today SKUDONET SL, Sevilla (Spain)
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
###############################################################################

use strict;

my $q = getCGI();

if ( $ENV{ PATH_INFO } =~ qr{^/ids$} )
{
	require Skudonet::API40::Ids;

	#  GET /rbac/users
	GET qr{^/ids$} => \&list_ids;
}

# Certificates
my $cert_re     = &getValidFormat( 'certificate' );
my $cert_pem_re = &getValidFormat( 'cert_pem' );
my $le_cert_re  = &getValidFormat( 'le_certificate_name' );

# LetsencryptZ
if ( $q->path_info =~ qr{^/certificates/letsencryptz} )
{
	require Skudonet::API40::LetsencryptZ;

	#  GET List LetsencryptZ certificates
	GET qr{^/certificates/letsencryptz$} => \&get_le_certificates;

	#  GET LetsencryptZ config
	GET qr{^/certificates/letsencryptz/config$} => \&get_le_conf;

	#  GET LetsencryptZ certificate
	GET qr{^/certificates/letsencryptz/($le_cert_re)$} => \&get_le_certificate;

	#  Create LetsencryptZ certificates
	POST qr{^/certificates/letsencryptz$} => \&create_le_certificate;

	#  LetsencryptZ certificates actions
	POST qr{^/certificates/letsencryptz/($le_cert_re)/actions$} =>
	  \&actions_le_certificate;

	#  DELETE LetsencryptZ certificate
	DELETE qr{^/certificates/letsencryptz/($le_cert_re)$} =>
	  \&delete_le_certificate;

	#  Modify LetsencryptZ config
	PUT qr{^/certificates/letsencryptz/config$} => \&modify_le_conf;

	#  Modify LetsencryptZ certificates
	PUT qr{^/certificates/letsencryptz/($le_cert_re)$} => \&modify_le_certificate;

}

# SSL certificates
if ( $q->path_info =~ qr{^/certificates} )
{
	require Skudonet::API40::Certificate;
	my $cert_name_re    = &getValidFormat( 'certificate_name' );
	my $cert_csr_key_re = &getValidFormat( 'cert_csr_key' );

	#  GET List SSL certificates
	GET qr{^/certificates$} => \&certificates;

	#  GET SSL certificate information
	GET qr{^/certificates/($cert_re)/info$}, \&get_certificate_info;

	#  Download SSL certificate
	GET qr{^/certificates/($cert_re)$}         => \&download_certificate;
	GET qr{^/certificates/($cert_csr_key_re)$} => \&download_certificate;

	#  GET CSR Key information
	GET qr{^/certificates/($cert_csr_key_re)/info$}, \&get_csr_key_info;

	#  Create CSR certificates
	POST qr{^/certificates$} => \&create_csr;

	#  POST certificates
	POST qr{^/certificates/pem$} => \&create_certificate;

	if ( $q->path_info !~ qr{^/certificates/letsencryptz-wildcard$} )
	{
		#  POST certificates
		POST qr{^/certificates/($cert_name_re)$} => \&upload_certificate;
	}

	#  DELETE certificate
	DELETE qr{^/certificates/($cert_re)$} => \&delete_certificate;

}

# Farms
my $farm_re    = &getValidFormat( 'farm_name' );
my $service_re = &getValidFormat( 'service' );
my $be_re      = &getValidFormat( 'backend' );
my $fg_name_re = &getValidFormat( 'fg_name' );

if ( $q->path_info =~ qr{^/farms/$farm_re/certificates} )
{
	require Skudonet::API40::Certificate;

	POST qr{^/farms/($farm_re)/certificates$} => \&add_farm_certificate;

	DELETE qr{^/farms/($farm_re)/certificates/($cert_pem_re)$} =>
	  \&delete_farm_certificate;
}

# Farmguardian
if (    $q->path_info =~ qr{^/monitoring/fg}
	 or $q->path_info =~ qr{^/farms/$farm_re(?:/services/$service_re)?/fg} )
{
	require Skudonet::API40::Farm::Guardian;

	POST qr{^/farms/($farm_re)(?:/services/($service_re))?/fg$} =>
	  \&add_farmguardian_farm;
	DELETE qr{^/farms/($farm_re)(?:/services/($service_re))?/fg/($fg_name_re)$} =>
	  \&rem_farmguardian_farm;

	GET qr{^/monitoring/fg$}                  => \&list_farmguardian;
	POST qr{^/monitoring/fg$}                 => \&create_farmguardian;
	GET qr{^/monitoring/fg/($fg_name_re)$}    => \&get_farmguardian;
	PUT qr{^/monitoring/fg/($fg_name_re)$}    => \&modify_farmguardian;
	DELETE qr{^/monitoring/fg/($fg_name_re)$} => \&delete_farmguardian;
}

if ( $q->path_info =~ qr{^/farms/$farm_re/actions} )
{
	require Skudonet::API40::Farm::Action;

	PUT qr{^/farms/($farm_re)/actions$} => \&farm_actions;
}

if ( $q->path_info =~ qr{^/farms/$farm_re.*/backends/$be_re/maintenance} )
{
	require Skudonet::API40::Farm::Action;

	PUT qr{^/farms/($farm_re)/services/($service_re)/backends/($be_re)/maintenance$}
	  => \&service_backend_maintenance;    #  (HTTP only)

	PUT qr{^/farms/($farm_re)/backends/($be_re)/maintenance$} =>
	  \&backend_maintenance;               #  (L4xNAT only)
}

if ( $q->path_info =~ qr{^/farms/$farm_re(?:/services/$service_re)?/backends} )
{
	require Skudonet::API40::Farm::Backend;

	GET qr{^/farms/($farm_re)/backends$} => \&backends;

	POST qr{^/farms/($farm_re)/backends$} => \&new_farm_backend;

	PUT qr{^/farms/($farm_re)/backends/($be_re)$} => \&modify_backends;

	DELETE qr{^/farms/($farm_re)/backends/($be_re)$} => \&delete_backend;

	GET qr{^/farms/($farm_re)/services/($service_re)/backends$} =>
	  \&service_backends;

	POST qr{^/farms/($farm_re)/services/($service_re)/backends$} =>
	  \&new_service_backend;

	PUT qr{^/farms/($farm_re)/services/($service_re)/backends/($be_re)$} =>
	  \&modify_service_backends;

	DELETE qr{^/farms/($farm_re)/services/($service_re)/backends/($be_re)$} =>
	  \&delete_service_backend;
}

if ( $q->path_info =~ qr{^/farms/$farm_re/services} )
{
	require Skudonet::API40::Farm::Service;

	POST qr{^/farms/($farm_re)/services$}                 => \&new_farm_service;
	GET qr{^/farms/($farm_re)/services/($service_re)$}    => \&farm_services;
	PUT qr{^/farms/($farm_re)/services/($service_re)$}    => \&modify_services;
	DELETE qr{^/farms/($farm_re)/services/($service_re)$} => \&delete_service;
}

if ( $q->path_info =~ qr{^/farms} )
{
	if ( $ENV{ REQUEST_METHOD } eq 'GET' )
	{
		require Skudonet::API40::Farm::Get;

		##### /farms
		GET qr{^/farms$} => \&farms;

		##### /farms/modules/MODULE
		GET qr{^/farms/modules/summary$} => \&farms_module_summary;
		GET qr{^/farms/modules/lslb$}    => \&farms_lslb;
		GET qr{^/farms/modules/dslb$}    => \&farms_dslb;

		##### /farms/FARM/summary
		GET qr{^/farms/($farm_re)/summary$} => \&farms_name_summary;

		##### /farms/FARM
		GET qr{^/farms/($farm_re)$} => \&farms_name;

		##### /farms/FARM/status
		GET qr{^/farms/($farm_re)/status$} => \&farms_name_status;
	}

	if ( $ENV{ REQUEST_METHOD } eq 'POST' )
	{
		require Skudonet::API40::Farm::Post;
		##### /farms
		POST qr{^/farms$} => \&new_farm;
	}

	if ( $ENV{ REQUEST_METHOD } eq 'PUT' )
	{
		require Skudonet::API40::Farm::Put;

		##### /farms/FARM
		PUT qr{^/farms/($farm_re)$} => \&modify_farm;
	}

	if ( $ENV{ REQUEST_METHOD } eq 'DELETE' )
	{
		require Skudonet::API40::Farm::Delete;

		##### /farms/FARM
		DELETE qr{^/farms/($farm_re)$} => \&delete_farm;
	}
}

# Network Interfaces
my $nic_re  = &getValidFormat( 'nic_interface' );
my $vlan_re = &getValidFormat( 'vlan_interface' );

if ( $q->path_info =~ qr{^/interfaces/nic} )
{
	require Skudonet::API40::Interface::NIC;

	GET qr{^/interfaces/nic$}                    => \&get_nic_list;
	GET qr{^/interfaces/nic/($nic_re)$}          => \&get_nic;
	PUT qr{^/interfaces/nic/($nic_re)$}          => \&modify_interface_nic;
	DELETE qr{^/interfaces/nic/($nic_re)$}       => \&delete_interface_nic;
	POST qr{^/interfaces/nic/($nic_re)/actions$} => \&actions_interface_nic;
}

if ( $q->path_info =~ qr{^/interfaces/vlan} )
{
	require Skudonet::API40::Interface::VLAN;

	GET qr{^/interfaces/vlan$}                     => \&get_vlan_list;
	POST qr{^/interfaces/vlan$}                    => \&new_vlan;
	GET qr{^/interfaces/vlan/($vlan_re)$}          => \&get_vlan;
	PUT qr{^/interfaces/vlan/($vlan_re)$}          => \&modify_interface_vlan;
	DELETE qr{^/interfaces/vlan/($vlan_re)$}       => \&delete_interface_vlan;
	POST qr{^/interfaces/vlan/($vlan_re)/actions$} => \&actions_interface_vlan;
}

if ( $q->path_info =~ qr{^/interfaces/virtual} )
{
	require Skudonet::API40::Interface::Virtual;

	GET qr{^/interfaces/virtual$}  => \&get_virtual_list;
	POST qr{^/interfaces/virtual$} => \&new_vini;

	my $virtual_re = &getValidFormat( 'virt_interface' );

	GET qr{^/interfaces/virtual/($virtual_re)$}    => \&get_virtual;
	PUT qr{^/interfaces/virtual/($virtual_re)$}    => \&modify_interface_virtual;
	DELETE qr{^/interfaces/virtual/($virtual_re)$} => \&delete_interface_virtual;
	POST qr{^/interfaces/virtual/($virtual_re)/actions$} =>
	  \&actions_interface_virtual;
}

if ( $q->path_info =~ qr{^/interfaces/gateway(?:/ipv([46]))?$} )
{
	require Skudonet::API40::Interface::Gateway;

	GET qr{^/interfaces/gateway(?:/ipv([46]))?$}    => \&get_gateway;
	PUT qr{^/interfaces/gateway(?:/ipv([46]))?$}    => \&modify_gateway;
	DELETE qr{^/interfaces/gateway(?:/ipv([46]))?$} => \&delete_gateway;
}

if ( $q->path_info =~ qr{^/interfaces$} )
{
	require Skudonet::API40::Interface::Generic;

	GET qr{^/interfaces$} => \&get_interfaces;
}

# Statistics
if ( $q->path_info =~ qr{^/stats} )
{
	require Skudonet::API40::Stats;

	# System stats
	GET qr{^/stats$}                => \&stats;
	GET qr{^/stats/system/network$} => \&stats_network;

	# Farm stats
	GET qr{^/stats/farms$}                     => \&all_farms_stats;
	GET qr{^/stats/farms/($farm_re)$}          => \&farm_stats;
	GET qr{^/stats/farms/($farm_re)/backends$} => \&farm_stats;

	# Fixed: make 'service' or 'services' valid requests for compatibility
	# with previous bug.
	GET qr{^/stats/farms/($farm_re)/services?/($service_re)/backends$} =>
	  \&farm_stats;
}

# Graphs
if ( $q->path_info =~ qr{^/graphs} )
{
	require Skudonet::API40::Graph;

	my $frequency_re = &getValidFormat( 'graphs_frequency' );
	my $system_id_re = &getValidFormat( 'graphs_system_id' );
	my $rrd_re       = &getValidFormat( 'rrd_time' );

	#  GET possible graphs
	GET qr{^/graphs$} => \&list_possible_graphs;

	##### /graphs/system
	#  GET all possible system graphs
	GET qr{^/graphs/system$} => \&list_sys_graphs;

	#  GET system graphs
	GET qr{^/graphs/system/($system_id_re)$} => \&get_sys_graphs;

	#  GET frequency system graphs
	GET qr{^/graphs/system/($system_id_re)/($frequency_re)$} =>
	  \&get_sys_graphs_freq;

	#  GET the interval of a system graph
	GET qr{^/graphs/system/($system_id_re)/custom/start/($rrd_re)/end/($rrd_re)$} =>
	  \&get_sys_graphs_interval;

	##### /graphs/system/disk

	# $disk_re includes 'root' at the beginning
	my $disk_re = &getValidFormat( 'mount_point' );

	GET qr{^/graphs/system/disk$} => \&list_disks_graphs;

	#  GET the interval of a disk graph
	GET qr{^/graphs/system/disk/($disk_re)/custom/start/($rrd_re)/end/($rrd_re)$} =>
	  \&get_disk_graphs_interval;

	# keep before next request
	GET qr{^/graphs/system/disk/($disk_re)/($frequency_re)$} =>
	  \&get_disk_graphs_freq;

	GET qr{^/graphs/system/disk/($disk_re)$} => \&get_disk_graphs;

	##### /graphs/interfaces

	#  GET all possible interfaces graphs
	GET qr{^/graphs/interfaces$} => \&list_iface_graphs;

	#  GET interfaces graphs
	GET qr{^/graphs/interfaces/($nic_re|$vlan_re)$} => \&get_iface_graphs;

	#  GET frequency interfaces graphs
	GET qr{^/graphs/interfaces/($nic_re|$vlan_re)/($frequency_re)$} =>
	  \&get_iface_graphs_frec;

	#  GET the interval of an interface graph
	GET
	  qr{^/graphs/interfaces/($nic_re|$vlan_re)/custom/start/($rrd_re)/end/($rrd_re)$}
	  => \&get_iface_graphs_interval;

	##### /graphs/farms

	#  GET all posible farm graphs
	GET qr{^/graphs/farms$} => \&list_farm_graphs;

	#  GET farm graphs
	GET qr{^/graphs/farms/($farm_re)$} => \&get_farm_graphs;

	#  GET frequency farm graphs
	GET qr{^/graphs/farms/($farm_re)/($frequency_re)$} => \&get_farm_graphs_frec;

	#  GET the interval of a farm graph
	GET qr{^/graphs/farms/($farm_re)/custom/start/($rrd_re)/end/($rrd_re)$} =>
	  \&get_farm_graphs_interval;
}

# System
if ( $q->path_info =~ qr{^/system/dns} )
{
	require Skudonet::API40::System::Service::DNS;

	GET qr{^/system/dns$}  => \&get_dns;
	POST qr{^/system/dns$} => \&set_dns;
}

if ( $q->path_info =~ qr{^/system/snmp} )
{
	require Skudonet::API40::System::Service::SNMP;

	GET qr{^/system/snmp$}  => \&get_snmp;
	POST qr{^/system/snmp$} => \&set_snmp;
}

if ( $q->path_info =~ qr{^/system/ntp} )
{
	require Skudonet::API40::System::Service::NTP;

	GET qr{^/system/ntp$}  => \&get_ntp;
	POST qr{^/system/ntp$} => \&set_ntp;
}

if ( $q->path_info =~ qr{^/system/users} )
{
	require Skudonet::API40::System::User;

	GET qr{^/system/users$}  => \&get_system_user;    #  GET users
	POST qr{^/system/users$} => \&set_system_user;    #  POST users
}

if ( $q->path_info =~ qr{^/system/log} )
{
	require Skudonet::API40::System::Log;

	GET qr{^/system/logs$} => \&get_logs;

	my $logs_re = &getValidFormat( 'log' );
	GET qr{^/system/logs/($logs_re)$} => \&download_logs;

	GET qr{^/system/logs/($logs_re)/lines/(\d+)$} => \&show_logs;

}

if ( $q->path_info =~ qr{^/system/backup} )
{
	require Skudonet::API40::System::Backup;

	GET qr{^/system/backup$}  => \&get_backup;       #  GET list backups
	POST qr{^/system/backup$} => \&create_backup;    #  POST create backups

	my $backup_re = &getValidFormat( 'backup' );
	GET qr{^/system/backup/($backup_re)$} =>
	  \&download_backup;                             #  GET download backups
	PUT qr{^/system/backup/($backup_re)$} => \&upload_backup; #  PUT  upload backups
	DELETE qr{^/system/backup/($backup_re)$} => \&del_backup; #  DELETE  backups
	POST qr{^/system/backup/($backup_re)/actions$} =>
	  \&apply_backup;                                         #  POST  apply backups
}

if ( $q->path_info =~
	 qr{^/system/(?:version|info|license|supportsave|language|packages)} )
{
	require Skudonet::API40::System::Info;

	GET qr{^/system/version$}     => \&get_version;
	GET qr{^/system/info$}        => \&get_system_info;
	GET qr{^/system/supportsave$} => \&get_supportsave;

	my $license_re = &getValidFormat( 'license_format' );
	GET qr{^/system/license/($license_re)$} => \&get_license;

	GET qr{^/system/language$}  => \&get_language;
	POST qr{^/system/language$} => \&set_language;

	GET qr{^/system/packages$} => \&get_packages_info;
}

if ( $q->path_info =~ qr{/ciphers$} )
{
	require Skudonet::API40::Certificate;

	GET qr{^/ciphers$} => \&ciphers_available;
}

if ( $ENV{ PATH_INFO } =~
	qr{^/farms/$farm_re/(?:replacerequestheader|replaceresponseheader)/(\d+)/actions$}
  )
{
	require Skudonet::API40::Farm::HTTP;

	POST qr{^/farms/($farm_re)/replacerequestheader/(\d+)/actions$} =>
	  \&move_replacerequestheader;
	POST qr{^/farms/($farm_re)/replaceresponseheader/(\d+)/actions$} =>
	  \&move_replaceresponseheader;
}

if ( $ENV{ PATH_INFO } =~
	qr{^/farms/$farm_re/(?:addheader|headremove|addresponseheader|removeresponseheader|replacerequestheader|replaceresponseheader)(:?/\d+)?$}
  )
{
	require Skudonet::API40::Farm::HTTP;

	POST qr{^/farms/($farm_re)/addheader$}          => \&add_addheader;
	PUT qr{^/farms/($farm_re)/addheader/(\d+)$}     => \&modify_addheader;
	DELETE qr{^/farms/($farm_re)/addheader/(\d+)$}  => \&del_addheader;
	POST qr{^/farms/($farm_re)/headremove$}         => \&add_headremove;
	PUT qr{^/farms/($farm_re)/headremove/(\d+)$}    => \&modify_headremove;
	DELETE qr{^/farms/($farm_re)/headremove/(\d+)$} => \&del_headremove;

	POST qr{^/farms/($farm_re)/addresponseheader$} => \&add_addResponseheader;
	PUT qr{^/farms/($farm_re)/addresponseheader/(\d+)$} =>
	  \&modify_addResponseheader;
	DELETE qr{^/farms/($farm_re)/addresponseheader/(\d+)$} =>
	  \&del_addResponseheader;
	POST qr{^/farms/($farm_re)/removeresponseheader$} => \&add_removeResponseheader;
	PUT qr{^/farms/($farm_re)/removeresponseheader/(\d+)$} =>
	  \&modify_removeResponseheader;
	DELETE qr{^/farms/($farm_re)/removeresponseheader/(\d+)$} =>
	  \&del_removeResponseHeader;

	POST qr{^/farms/($farm_re)/replacerequestheader$} => \&add_replaceRequestHeader;
	PUT qr{^/farms/($farm_re)/replacerequestheader/(\d+)$} =>
	  \&modify_replaceRequestHeader;
	DELETE qr{^/farms/($farm_re)/replacerequestheader/(\d+)$} =>
	  \&del_replaceRequestHeader;
	POST qr{^/farms/($farm_re)/replaceresponseheader$} =>
	  \&add_replaceResponseHeader;
	PUT qr{^/farms/($farm_re)/replaceresponseheader/(\d+)$} =>
	  \&modify_replaceResponseHeader;
	DELETE qr{^/farms/($farm_re)/replaceresponseheader/(\d+)$} =>
	  \&del_replaceResponseHeader;
}

if ( $ENV{ PATH_INFO } =~ qr{^/ipds} )
{
	require Skudonet::API40::IPDS::Generic;
	GET qr{^/ipds$} => \&get_ipds_rules_list;
}
if ( $ENV{ PATH_INFO } =~ qr{^/ipds/waf} )
{
	my $file     = &getValidFormat( 'waf_file' );
	my $file_ext = &getValidFormat( 'waf_file_ext' );
	require Skudonet::API40::IPDS::WAF::Files;

	GET qr{^/ipds/waf/files$}            => \&list_waf_file;
	GET qr{^/ipds/waf/files/($file)$}    => \&get_waf_file;
	PUT qr{^/ipds/waf/files/($file)$}    => \&create_waf_file;
	POST qr{^/ipds/waf/files/(.+)$}      => \&upload_waf_file;
	DELETE qr{^/ipds/waf/files/($file)$} => \&delete_waf_file;

	my $set_name = &getValidFormat( 'waf_set_name' );
	require Skudonet::API40::IPDS::WAF::Sets;

	GET qr{^/ipds/waf$}                      => \&list_waf_sets;
	GET qr{^/ipds/waf/($set_name)$}          => \&get_waf_set;
	PUT qr{^/ipds/waf/($set_name)$}          => \&modify_waf_set;
	POST qr{^/ipds/waf/($set_name)/actions$} => \&actions_waf;

}

if ( $ENV{ PATH_INFO } =~ qr{^/farms/$farm_re/ipds/waf} )
{
	my $set_name = &getValidFormat( 'waf_set_name' );
	require Skudonet::API40::IPDS::WAF::Sets;

	POST qr{^/farms/($farm_re)/ipds/waf$}               => \&add_farm_waf_set;
	DELETE qr{^/farms/($farm_re)/ipds/waf/($set_name)$} => \&remove_farm_waf_set;
	POST qr{^/farms/($farm_re)/ipds/waf/($set_name)/actions$} =>
	  \&move_farm_waf_set;
}

##### Load modules dynamically #######################################
my $routes_path = &getGlobalConfiguration( 'zlibdir' ) . '/API40/Routes';
opendir ( my $dir, $routes_path );
foreach my $file ( readdir $dir )
{
	next if $file !~ /\w\.pm$/;

	my $module = "$routes_path/$file";

	unless ( eval { require $module; } )
	{
		&zenlog( $@, "error", "SYSTEM" );
		die $@;
	}
}

1;
