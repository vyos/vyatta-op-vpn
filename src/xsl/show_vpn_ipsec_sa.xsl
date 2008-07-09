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
      * Module: show_vpn_ipsec_sa.xsl 
      *
      * Author: Mike Horn, Marat Nepomnyashy
      * Date: 2007
      *
      */ -->

<!--XSL template for formatting the output of a number of "show vpn ipsec sa" commands-->

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:param name="conn"/>
<xsl:param name="detail"/>
<xsl:param name="nat"/>
<xsl:param name="peer"/>

<xsl:variable name="pad4" select="'    '"/>
<xsl:variable name="pad4_len" select="string-length($pad4)"/>
<xsl:variable name="pad5" select="'     '"/>
<xsl:variable name="pad5_len" select="string-length($pad5)"/>
<xsl:variable name="pad6" select="'      '"/>
<xsl:variable name="pad6_len" select="string-length($pad6)"/>
<xsl:variable name="pad7" select="'       '"/>
<xsl:variable name="pad7_len" select="string-length($pad7)"/>
<xsl:variable name="pad8" select="'        '"/>
<xsl:variable name="pad8_len" select="string-length($pad8)"/>
<xsl:variable name="pad9" select="'         '"/>
<xsl:variable name="pad9_len" select="string-length($pad9)"/>
<xsl:variable name="pad11" select="'           '"/>
<xsl:variable name="pad11_len" select="string-length($pad11)"/>
<xsl:variable name="pad16" select="'                '"/>
<xsl:variable name="pad16_len" select="string-length($pad16)"/>

<xsl:template match="/">
<xsl:text>&newln;</xsl:text>

<xsl:if test="$detail != 'y'">
  <xsl:text>Peer            Tunnel# Dir SPI      Encrypt    Hash       NAT-T A-Time L-Time</xsl:text>
  <xsl:text>&newln;</xsl:text>
  <xsl:text>-------         ------- --- ---      -------    ----       ----- ------ ------</xsl:text>
  <xsl:text>&newln;</xsl:text>
</xsl:if>

<xsl:for-each select="opcommand/format/peer/setkey">
  <xsl:choose>
    <xsl:when test="string-length($conn) > 0">
      <xsl:if test="$conn = conn_name">
        <xsl:call-template name="show_ipsec_sa">
          <xsl:with-param name="row" select="." />
        </xsl:call-template>
      </xsl:if>
    </xsl:when>
    <xsl:when test="string-length($nat) > 0">
      <xsl:if test="$nat = ../nat_traversal">
        <xsl:call-template name="show_ipsec_sa">
          <xsl:with-param name="row" select="." />
        </xsl:call-template>
      </xsl:if>
    </xsl:when>
    <xsl:when test="string-length($peer) > 0">
      <xsl:if test="$peer=../peer_ip">
        <xsl:call-template name="show_ipsec_sa">
          <xsl:with-param name="row" select="." />
        </xsl:call-template>
      </xsl:if>
    </xsl:when>
    <xsl:otherwise>
      <xsl:call-template name="show_ipsec_sa">
        <xsl:with-param name="row" select="." />
      </xsl:call-template>
    </xsl:otherwise>
  </xsl:choose>
</xsl:for-each>
</xsl:template>

  <xsl:template name="show_ipsec_sa">
    <xsl:param name="row" />
    <xsl:choose>
      <xsl:when test="$detail = 'y'">
        <xsl:if test="position() > 1">
          <xsl:text>---------</xsl:text><xsl:text>&newln;</xsl:text>
          <xsl:text>&newln;</xsl:text>
	</xsl:if>
        <xsl:text>Conn Name:            </xsl:text><xsl:value-of select="conn_name"/><xsl:text>&newln;</xsl:text>
	<xsl:text>State:                </xsl:text><xsl:value-of select="../ike_state"/><xsl:text>&newln;</xsl:text>
        <xsl:text>Peer:                 </xsl:text><xsl:value-of select="../peer_ip"/><xsl:text>&newln;</xsl:text>
        <xsl:text>Direction:            </xsl:text><xsl:value-of select="dir"/><xsl:text>&newln;</xsl:text>
        <!--<xsl:text>Outbound interface: !!</xsl:text>  <xsl:text>&newln;</xsl:text>-->
        <xsl:text>Source Net:           </xsl:text><xsl:value-of select="left"/><xsl:text>&newln;</xsl:text>
        <xsl:text>Dest Net:             </xsl:text><xsl:value-of select="right"/><xsl:text>&newln;</xsl:text>
        <xsl:text>SPI:                  </xsl:text><xsl:value-of select="spi"/><xsl:text>&newln;</xsl:text>
        <xsl:text>Encryption:           </xsl:text><xsl:value-of select="esp_encrypt"/><xsl:text>&newln;</xsl:text>
        <xsl:text>Hash:                 </xsl:text><xsl:value-of select="esp_hash"/><xsl:text>&newln;</xsl:text>
        <xsl:text>PFS Group:            </xsl:text><xsl:value-of select="pfs_group"/><xsl:text>&newln;</xsl:text>
        <xsl:text>DH Group:             </xsl:text><xsl:value-of select="../ike_dh"/><xsl:text>&newln;</xsl:text>
        <xsl:text>NAT Traversal:        </xsl:text><xsl:if test="../nat_traversal='enabled'"><xsl:text>Yes</xsl:text></xsl:if><xsl:if test="../nat_traversal='disabled'"><xsl:text>No</xsl:text></xsl:if><xsl:text>&newln;</xsl:text>
        <xsl:text>NAT Source Port:      </xsl:text><xsl:value-of select="../nat_src_port"/><xsl:text>&newln;</xsl:text>
        <xsl:text>NAT Dest Port:        </xsl:text><xsl:value-of select="../nat_dst_port"/><xsl:text>&newln;</xsl:text>
        <!--<xsl:text>Packets: !!           </xsl:text>  <xsl:text>&newln;</xsl:text>-->
        <xsl:text>Bytes:                </xsl:text><xsl:value-of select="bytes"/><xsl:text>&newln;</xsl:text>
        <xsl:text>Active time (s):      </xsl:text><xsl:value-of select="active_time"/><xsl:text>&newln;</xsl:text>
        <xsl:text>Lifetime (s):         </xsl:text><xsl:value-of select="keylife"/><xsl:text>&newln;</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:variable name="t_peer_ip" select="substring(../peer_ip,1,15)"/>
        <xsl:variable name="t_tunnel" select="substring(tunnel,1,8)"/>
        <xsl:variable name="t_dir" select="substring(dir,1,3)"/>
        <xsl:variable name="t_spi" select="substring(spi,1,8)"/>
        <xsl:variable name="t_esp_encrypt" select="substring(esp_encrypt,1,10)"/>
        <xsl:variable name="t_esp_hash" select="substring(esp_hash,1,10)"/>
        <xsl:variable name="t_active_time" select="substring(active_time,1,6)"/>
        <xsl:variable name="t_keylife" select="substring(keylife,1,6)"/>

        <xsl:value-of select="$t_peer_ip"/>
        <xsl:value-of select="substring($pad16,1,$pad16_len - string-length($t_peer_ip))"/>
        <xsl:value-of select="$t_tunnel"/>
        <xsl:value-of select="substring($pad8,1,$pad8_len - string-length($t_tunnel))"/>
        <xsl:value-of select="$t_dir"/>
        <xsl:value-of select="substring($pad4,1,$pad4_len - string-length($t_dir))"/>
        <xsl:value-of select="$t_spi"/>
        <xsl:value-of select="substring($pad9,1,$pad9_len - string-length($t_spi))"/>
        <xsl:value-of select="$t_esp_encrypt"/>
        <xsl:value-of select="substring($pad11,1,$pad11_len - string-length($t_esp_encrypt))"/>
        <xsl:value-of select="$t_esp_hash"/>
        <xsl:value-of select="substring($pad11,1,$pad11_len - string-length($t_esp_hash))"/>
	<xsl:if test="../nat_traversal='enabled'"><xsl:text>Yes   </xsl:text></xsl:if>
	<xsl:if test="../nat_traversal='disabled'"><xsl:text>No    </xsl:text></xsl:if>
        <xsl:value-of select="$t_active_time"/>
        <xsl:value-of select="substring($pad7,1,$pad7_len - string-length($t_active_time))"/>
        <xsl:value-of select="$t_keylife"/>
        <xsl:text>&newln;</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>
</xsl:stylesheet>

