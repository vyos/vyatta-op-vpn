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
      * Module: show_ike_sa.xsl 
      *
      * Author: Mike Horn, Marat Nepomnyashy
      * Date: 2007
      *
      */ -->

<!--XSL template for formatting the "show ike sa" command output-->

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:param name="nat"/>
<xsl:param name="peer"/>

<xsl:variable name="pad7" select="'       '"/>
<xsl:variable name="pad7_len" select="string-length($pad7)"/>
<xsl:variable name="pad9" select="'         '"/>
<xsl:variable name="pad9_len" select="string-length($pad9)"/>
<xsl:variable name="pad10" select="'          '"/>
<xsl:variable name="pad10_len" select="string-length($pad10)"/>
<xsl:variable name="pad16" select="'                '"/>
<xsl:variable name="pad16_len" select="string-length($pad16)"/>

<xsl:template match="/">
  <xsl:text>&newln;</xsl:text>
  <xsl:text>Local           Peer            State     Encrypt   Hash     NAT-T A-Time L-Time</xsl:text>
  <xsl:text>&newln;</xsl:text>
  <xsl:text>--------        -------         -----     -------   ----     ----- ------ ------</xsl:text>
  <xsl:text>&newln;</xsl:text>
  <xsl:for-each select="opcommand/format/peer">
    <xsl:choose>
      <xsl:when test="string-length($peer) > 0">
        <xsl:if test="$peer=peer_ip">
          <xsl:call-template name="show_ike_sa">
            <xsl:with-param name="row" select="." />
          </xsl:call-template>
        </xsl:if>
      </xsl:when>
      <xsl:when test="string-length($nat) > 0">
        <xsl:if test="$nat = nat_traversal">
          <xsl:call-template name="show_ike_sa">
            <xsl:with-param name="row" select="." />
          </xsl:call-template>
        </xsl:if>
      </xsl:when>
      <xsl:otherwise>
        <xsl:call-template name="show_ike_sa">
          <xsl:with-param name="row" select="." />
        </xsl:call-template>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:for-each>
</xsl:template>

  <xsl:template name="show_ike_sa">
    <xsl:param name="row" />
    <xsl:variable name="t_right_ip" select="substring(right_ip,1,15)"/>
    <xsl:variable name="t_peer_ip" select="substring(peer_ip,1,15)"/>
    <xsl:variable name="t_ike_state" select="substring(ike_state,1,9)"/>
    <xsl:variable name="t_ike_encrypt" select="substring(ike_encrypt,1,9)"/>
    <xsl:variable name="t_ike_hash" select="substring(ike_hash,1,8)"/>
    <xsl:variable name="t_ike_activetime" select="substring(ike_activetime,1,6)"/>
    <xsl:variable name="t_ike_lifetime" select="substring(ike_lifetime,1,6)"/>

    <xsl:value-of select="$t_right_ip"/>
    <xsl:value-of select="substring($pad16,1,$pad16_len - string-length($t_right_ip))"/>
    <xsl:value-of select="$t_peer_ip"/>
    <xsl:value-of select="substring($pad16,1,$pad16_len - string-length($t_peer_ip))"/>
    <xsl:value-of select="$t_ike_state"/>
    <xsl:value-of select="substring($pad10,1,$pad10_len - string-length($t_ike_state))"/>
    <xsl:value-of select="$t_ike_encrypt"/>
    <xsl:value-of select="substring($pad10,1,$pad10_len - string-length($t_ike_encrypt))"/>
    <xsl:value-of select="$t_ike_hash"/>
    <xsl:value-of select="substring($pad9,1,$pad9_len - string-length($t_ike_hash))"/>
    <xsl:if test="nat_traversal='enabled'"><xsl:text>Yes   </xsl:text></xsl:if>
    <xsl:if test="nat_traversal='disabled'"><xsl:text>No    </xsl:text></xsl:if>
    <xsl:value-of select="$t_ike_activetime"/>
    <xsl:value-of select="substring($pad7,1,$pad7_len - string-length($t_ike_activetime))"/>
    <xsl:value-of select="$t_ike_lifetime"/>
    <xsl:value-of select="substring($pad7,1,$pad7_len - string-length($t_ike_lifetime))"/>
    <xsl:text>&newln;</xsl:text>
  </xsl:template>
</xsl:stylesheet>
