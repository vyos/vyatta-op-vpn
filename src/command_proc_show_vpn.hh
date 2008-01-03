/**
 *    Module: command_proc_show_vpn.hh
 *
 *    Author: Michael Larson
 *    Date: 2006
 *    Description:
 *
 *    This program is free software; you can redistribute it and/or modify 
 *    it under the terms of the GNU General Public License as published 
 *    by the Free Software Foundation; either version 2 of the License, 
 *    or (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be  useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 *    02110-1301 USA
 *
 *    Copyright 2006, Vyatta, Inc.
 */
#ifndef __COMMAND_PROC_SHOW_VPN_HH__
#define __COMMAND_PROC_SHOW_VPN_HH__

#include <sstream>
#include <string>
#include <map>
#include "command_proc_base.hh"

#define XSLDIR          "/opt/vyatta/share/xsl"


using namespace std;

class Dir
{
public:
  Dir() : _session_id("n/a"),_bytes(0),_active_time(0) {}

public:
  string _session_id; //same as tunnel_id
  int _bytes;
  int _active_time;
};

class AllTunnels;
class Peer;
class PeerTunnels;

class Tunnel 
{
public:
  ~Tunnel();
  Tunnel(AllTunnels & all_tunnels, Peer & peer) : _esp_encrypt("n/a"),_esp_hash("n/a"),_esp_state("down"),_keylife(0), _all_tunnels(all_tunnels), _peer(peer) {}

public:

  Dir    _in;
  Dir    _out;

  string _tunnel_name;
  string _tunnel_number;
  string _esp_encrypt;
  string _esp_hash;
  string _pfs_group;

  string _esp_state;

  int    _keylife;
  string _left_net;
  string _right_net;

  Peer & getPeer();
private:
  AllTunnels &  _all_tunnels;
  Peer &        _peer;
};

class Tunnels {
public:
  ~Tunnels();

  const map<string, Tunnel*> & getConstTunnelsMap() const;

  map<string, Tunnel*> & getTunnelsMap();
  void add(const string & strTunnelName, Tunnel * p_tunnel);
  void unlink(const Tunnel * p_tunnel);

protected:
  Tunnels();

private:
  map<string, Tunnel*> _tunnels;

};

class AllTunnels : public Tunnels {

};

class PeerTunnels : public Tunnels {

};

class Peer
{
friend Tunnel::~Tunnel();

public:
  Peer() : _ike_seconds_lifetime(0), _ike_seconds_lifetime_left(0), _ike_encrypt("n/a"),_ike_hash("n/a"), _ike_state("down"), _nat_trav(false), _nat_src_port(0), _nat_dst_port(0) {}

  int _ike_seconds_lifetime;
  int _ike_seconds_lifetime_left;

  string _ike_encrypt;
  string _ike_hash;
  string _ike_dh;
  string _ike_state;

  string _left_ip;
  string _right_ip;

  bool   _nat_trav;
  int    _nat_src_port;
  int    _nat_dst_port;

  const PeerTunnels & getConstPeerTunnels() const;

  PeerTunnels & getPeerTunnels();
protected:
  PeerTunnels  _peer_tunnels;
};

class CommandProcShowVPN : public CommandProcBase
{
public:
//  typedef std::map<std::string, Tunnel> Coll;
//  typedef std::map<std::string, Tunnel>::iterator Iter;

public:
  CommandProcShowVPN();
  ~CommandProcShowVPN();

  static std::string
  name() {return "showvpntable";}

  /**
   *
   **/ 
  bool
  is_valid() {return true;}

  /**
   *
   **/
  std::string
  process(const std::string &cmd, bool debug, std::string &reason);

private:
  /**
   *
   **/
  void 
  convert_to_xml_secrets(const std::string &line, bool debug);

  /**
   *
   **/
  void 
  convert_to_xml_pluto_pid(const std::string &line, bool debug);

  /**
   *
   **/
  void 
  convert_to_xml_setkey_d(bool debug);

  /**
   *
   **/
  void 
  convert_to_xml_setkey_dp(const std::string &line, bool debug, string &net1, string &net2);

  /**
   *
   **/
  void 
  convert_to_xml_setup_status(const std::string &line, bool debug);

  /**
   *
   **/
  void 
  convert_to_xml_auto_status(const std::string &line, bool debug);

  /**
   *
   **/
  void
  process_conf(bool debug);

  /**
   *
   **/
  void
  update_tunnel(const string &tunnel, const string &right, const string &left, const string &rightnet, const string &leftnet, const string &lifetime, bool debug);

protected:
  ostringstream        _xml_out;
  list<Peer*>          _peers;
  AllTunnels           _all_tunnels;

  string               _interface_conf_line;
  vector<std::string>  _pad;

private:
};

#endif //__COMMAND_PROC_SHOW_VPN_H__
