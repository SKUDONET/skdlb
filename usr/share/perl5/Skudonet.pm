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

use Skudonet::Core;
use Skudonet::Log;
use Skudonet::Config;
use Skudonet::Validate;
use Skudonet::Debug;
use Skudonet::Netfilter;
use Skudonet::Net::Interface;
use Skudonet::FarmGuardian;
use Skudonet::Backup;
use Skudonet::RRD;
use Skudonet::SNMP;
use Skudonet::Stats;
use Skudonet::SystemInfo;
use Skudonet::System;
use Skudonet::Zapi;

require Skudonet::CGI if defined $ENV{ GATEWAY_INTERFACE };

1;
