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
      * Module: show_ipsec_sa_statistics.xsl 
      *
      * Author: Mike Horn, Marat Nepomnyashy
      * Date: 2007
      *
      */ -->

<!--XSL template for formatting the "show ipsec sa statistics" command output-->

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:variable name="pad4" select="'    '"/>
<xsl:variable name="pad4_len" select="string-length($pad4)"/>
<xsl:variable name="pad16" select="'                '"/>
<xsl:variable name="pad16_len" select="string-length($pad16)"/>
<xsl:variable name="pad19" select="'                   '"/>
<xsl:variable name="pad19_len" select="string-length($pad19)"/>

<xsl:template match="/">
<xsl:text>&newln;</xsl:text>
<xsl:text>Peer            Dir SRC Network        DST Network        Bytes</xsl:text>
<xsl:text>&newln;</xsl:text>
<xsl:text>-------         --- -----------        -----------        -----</xsl:text>
<xsl:text>&newln;</xsl:text>
<xsl:for-each select="opcommand/format/peer/setkey">
  <xsl:value-of select="../peer_ip"/>
  <xsl:value-of select="substring($pad16,1,$pad16_len - string-length(../peer_ip))"/>
  <xsl:value-of select="dir"/>
  <xsl:value-of select="substring($pad4,1,$pad4_len - string-length(dir))"/>
  <xsl:value-of select="left"/>
  <xsl:value-of select="substring($pad19,1,$pad19_len - string-length(left))"/>
  <xsl:value-of select="right"/>
  <xsl:value-of select="substring($pad19,1,$pad19_len - string-length(right))"/>
  <xsl:value-of select="bytes"/>
  <xsl:text>&newln;</xsl:text>
</xsl:for-each>
</xsl:template>
</xsl:stylesheet>
