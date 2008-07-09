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
      * Module: show_ike_secrets.xsl 
      *
      * Author: Mike Horn, Marat Nepomnyashy
      * Date: 2007
      *
      */ -->

<!--XSL template for formatting the "show ike secrets" command output-->

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:variable name="pad16" select="'                '"/>
<xsl:variable name="pad16_len" select="string-length($pad16)"/>

<xsl:template match="/">
<xsl:text>&newln;</xsl:text>
<xsl:text>Local           Peer            Secret</xsl:text>
<xsl:text>&newln;</xsl:text>
<xsl:text>--------        -------         ------</xsl:text>
<xsl:text>&newln;</xsl:text>
<xsl:for-each select="opcommand/format/secret">

    <xsl:variable name="t_sip" select="substring(sip,1,15)"/>
    <xsl:variable name="t_dip" select="substring(dip,1,15)"/>
    <xsl:variable name="t_key" select="substring(key,2,string-length(key)-2)"/>

    <xsl:value-of select="$t_sip"/>
    <xsl:value-of select="substring($pad16,1,$pad16_len - string-length($t_sip))"/>
    <xsl:value-of select="$t_dip"/>
    <xsl:value-of select="substring($pad16,1,$pad16_len - string-length($t_dip))"/>
    <xsl:value-of select="$t_key"/>
    <xsl:text>&newln;</xsl:text>

</xsl:for-each>
</xsl:template>

</xsl:stylesheet>
