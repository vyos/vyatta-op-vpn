<?xml version="1.0"?>
<!DOCTYPE stylesheet [
<!ENTITY newln "&#10;">
]>

<!-- /*
      *  Copyright 2007, Vyatta, Inc.
      *
      *  GNU General Public License
      *
      *  This program is free software; you can redistribute it and/or modify
      *  it under the terms of the GNU General Public License, version 2,
      *  as published by the Free Software Foundation.
      *
      *  This program is distributed in the hope that it will be useful,
      *  but WITHOUT ANY WARRANTY; without even the implied warranty of
      *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
      *  GNU General Public License for more details.
      *
      *  You should have received a copy of the GNU General Public License
      *  along with this program; if not, write to the Free Software
      *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
      *  02110-1301 USA
      *
      * Module: show_vpn_ipsec_status.xsl 
      *
      * Author: Mike Horn, Marat Nepomnyashy
      * Date: 2007
      *
      */ -->

<!--XSL template for formatting the "show ipsec status" command output-->

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:variable name="pad2" select="'  '"/>
<xsl:variable name="pad2_len" select="string-length($pad2)"/>
<xsl:variable name="pad8" select="'        '"/>
<xsl:variable name="pad8_len" select="string-length($pad8)"/>
<xsl:template match="/">
<xsl:variable name="pluto_pid" select="opcommand/format/pluto_pid" />
<xsl:choose>
<xsl:when test="string($pluto_pid)">
IPSec Process Running  PID: <xsl:value-of select="$pluto_pid" /><xsl:text>&newln;</xsl:text><xsl:text>&newln;</xsl:text>
<xsl:value-of select="//opcommand/format/setup_status_tunnels" /> Active IPsec Tunnels<xsl:text>&newln;</xsl:text>
IPsec Interfaces:
<xsl:for-each select="opcommand/format/auto_status_interface">
<xsl:value-of select="$pad2"/>
<xsl:value-of select="iface"/><xsl:value-of select="substring($pad8,1,$pad8_len - string-length(iface))"/>(<xsl:value-of select="address"/>)
</xsl:for-each>
</xsl:when>
<xsl:otherwise>
IPSec Process NOT Running
</xsl:otherwise>
</xsl:choose>
</xsl:template>
</xsl:stylesheet>

