/**
 *    Module: command_proc_show_vpn.cc
 *
 *    Author(s): Michael Larson, Marat Nepomnyashy
 *    Date: 2008
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
 *    Copyright 2008, Vyatta, Inc.
 */

#include <stdio.h>
#include <iostream>
#include <list>
#include <string>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
//#include "config.h"
#include "rl_str_proc.hh"
//#include <librl_common/rl_interface.hh>
#include "command_proc_show_vpn.hh"
#include "xsl_processor.hh"

using namespace std;

int main(int argc, char ** argv) {

	//Build out string request based on the number of argcs.
	string request;
	bool debug = false;
	for (int i = 1; i < argc; ++i) {
		if (strcmp((const char *)argv[i], "--debug") == 0) {
			debug = true;
		} else {
			request += string(argv[i]) + string(" ");
		}
	}
	if (debug) {
		cout << "request: " << request << endl;
	}


	CommandProcShowVPN proc;

	// process command and create xml output
	string reason;
	string xml_out = proc.process(request, debug, reason);
	if (debug) {
		cout << "output xml:" << endl << xml_out << endl;
	}

	if (xml_out.empty() == true) {
		cout << reason << endl;
		exit(0);
	}

	bool catch_param_name = false;
	bool catch_param_val = false;
	string param_name;
	string param_val;
	list<pair<string,string> > listParams;
	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--pname") == 0) {
			catch_param_name = true;
			catch_param_val = false;
			param_name = "";
			param_val = "";
		} else if (strcmp(argv[i], "--pval") == 0) {
			catch_param_name = false;
			catch_param_val = true;
			param_val = "";
		} else {
			if (catch_param_name) {
				param_name = argv[i];
				catch_param_name = false;
			}
			if (catch_param_val) {
				param_val = argv[i];
				catch_param_val = false;
			}
		}
		if (param_name.length() > 0 && param_val.length() > 0) {
			listParams.push_back(pair<string,string>(param_name, param_val));
			param_name = "";
			param_val = "";
		}
	}


	XSLProcessor xsl_processor(debug);

	cout << xsl_processor.transform(xml_out, proc.xsl(), listParams) << endl;
}



/**
 *
 **/
CommandProcShowVPN::CommandProcShowVPN() : CommandProcBase()
{
  string str;
  for (int i = 0; i < 8; ++i) {
    _pad.push_back(str);
    str += "0";
  }
}

/**
 *
 **/
CommandProcShowVPN::~CommandProcShowVPN()
{
  list<Peer*>::iterator i = _peers.begin();
  const list<Peer*>::const_iterator iEnd = _peers.end();
  while (i != iEnd) {
    delete *i;
    *i = NULL;
    i++;
  }
}

/**
 *
 **/
std::string
CommandProcShowVPN::process(const string &cmd, bool debug, string &reason)
{
  UNUSED(reason);
  char buf[2048];
  string ipsec_cmd;
  FILE *f;
  StrProc proc_str(cmd, " ");

  _xsl = XSLDIR "/" + proc_str.get(0);


  _xml_out << "<opcommand name='vpn'><format type='row'>";



//  ipsec eroute
//  ipsec spi
//  ipsec spigrp
//  ipsec spi status
//  ipsec setup --status
//  ipsec statusall
 
  ipsec_cmd = "cat /etc/ipsec.secrets";
  f = popen(ipsec_cmd.c_str(), "r");
  if (f) {
    while(fgets(buf, 2047, f) != NULL) { 
      string line(buf);
      convert_to_xml_secrets(line, debug);
    } 
    if (pclose(f) != 0) {
      return string("");
    }
  }

  ipsec_cmd = "cat /var/run/pluto.pid 2>/dev/null";
  f = popen(ipsec_cmd.c_str(), "r");
  if (f) {
    while(fgets(buf, 2047, f) != NULL) { 
      string line(buf);
      convert_to_xml_pluto_pid(line, debug);
    } 
    if (pclose(f) != 0) {
      reason = "VPN is not running";
      return string("");
    }
  }

  process_conf(debug);

  ipsec_cmd = "ipsec statusall";
  f = popen(ipsec_cmd.c_str(), "r");
  if (f) {
    while(fgets(buf, 2047, f) != NULL) { 
      string line(buf);
      convert_to_xml_auto_status(line, debug);
    } 
    if (pclose(f) != 0) {
      return string("");
    }
  }

  convert_to_xml_setkey_d(debug);

  std::list<Peer*>::const_iterator i = _peers.begin();
  const std::list<Peer*>::const_iterator iEnd = _peers.end();
  while (i != iEnd) {
    const Peer * p_peer = *i;
    if (p_peer != NULL) {
      _xml_out << "<peer>";
      _xml_out << "<left_ip>" << p_peer->_left_ip << "</left_ip>";
      _xml_out << "<right_ip>" << p_peer->_right_ip << "</right_ip>";
      _xml_out << "<peer_ip>" << p_peer->_left_ip << "</peer_ip>";
      _xml_out << "<ike_encrypt>" << p_peer->_ike_encrypt << "</ike_encrypt>";
      _xml_out << "<ike_hash>" << p_peer->_ike_hash << "</ike_hash>";
      _xml_out << "<ike_dh>" << p_peer->_ike_dh << "</ike_dh>";
      _xml_out << "<ike_activetime>" << ((p_peer->_ike_state == "up") ? (p_peer->_ike_seconds_lifetime - p_peer->_ike_seconds_lifetime_left) : 0) << "</ike_activetime>";
      _xml_out << "<ike_lifetime>" << p_peer->_ike_seconds_lifetime << "</ike_lifetime>";
      _xml_out << "<ike_state>" << p_peer->_ike_state << "</ike_state>";
      _xml_out << "<nat_traversal>" << (p_peer->_nat_trav ? "enabled" : "disabled") << "</nat_traversal>";
      if (p_peer->_nat_trav) {
        _xml_out << "<nat_src_port>" << p_peer->_nat_src_port << "</nat_src_port>";
        _xml_out << "<nat_dst_port>" << p_peer->_nat_dst_port << "</nat_dst_port>";
      } else {
        _xml_out << "<nat_src_port>n/a</nat_src_port>";
        _xml_out << "<nat_dst_port>n/a</nat_dst_port>";
      }

      std::map<std::string, Tunnel*>::const_iterator iter = p_peer->getConstPeerTunnels().getConstTunnelsMap().begin();
      const std::map<std::string, Tunnel*>::const_iterator iterEnd = p_peer->getConstPeerTunnels().getConstTunnelsMap().end();
      while (iter != iterEnd) {
        Tunnel * p_tunnel = iter->second;
	if (p_tunnel != NULL) {
          //first do the in direction
          _xml_out << "<setkey>";
          _xml_out << "<conn_name>" << iter->first << "</conn_name>";
          _xml_out << "<tunnel>" << p_tunnel->_tunnel_number << "</tunnel>";
          _xml_out << "<dir>in</dir>";
          _xml_out << "<spi>" << p_tunnel->_in._session_id << "</spi>";
          _xml_out << "<esp_encrypt>" << p_tunnel->_esp_encrypt << "</esp_encrypt>";
          _xml_out << "<esp_hash>" << p_tunnel->_esp_hash << "</esp_hash>";
          _xml_out << "<pfs_group>" << p_tunnel->_pfs_group << "</pfs_group>";
          _xml_out << "<active_time>" << p_tunnel->_in._active_time << "</active_time>";
          _xml_out << "<bytes>" << p_tunnel->_in._bytes << "</bytes>";
          _xml_out << "<keylife>" << p_tunnel->_keylife << "</keylife>";
          _xml_out << "<left>" << p_tunnel->_left_net << "</left>";
          _xml_out << "<right>" << p_tunnel->_right_net << "</right>";
          _xml_out << "<esp_state>" << p_tunnel->_esp_state << "</esp_state>";
          _xml_out << "</setkey>";

          //now do the out direction
          _xml_out << "<setkey>";
          _xml_out << "<conn_name>" << iter->first << "</conn_name>";
          _xml_out << "<tunnel>" << p_tunnel->_tunnel_number << "</tunnel>";
          _xml_out << "<dir>out</dir>";
          _xml_out << "<spi>" << p_tunnel->_out._session_id << "</spi>";
          _xml_out << "<esp_encrypt>" << p_tunnel->_esp_encrypt << "</esp_encrypt>";
          _xml_out << "<esp_hash>" << p_tunnel->_esp_hash << "</esp_hash>";
          _xml_out << "<pfs_group>" << p_tunnel->_pfs_group << "</pfs_group>";
          _xml_out << "<active_time>" << p_tunnel->_out._active_time << "</active_time>";
          _xml_out << "<bytes>" << p_tunnel->_out._bytes << "</bytes>";
          _xml_out << "<keylife>" << p_tunnel->_keylife << "</keylife>";
          _xml_out << "<left>" << p_tunnel->_right_net << "</left>";
          _xml_out << "<right>" << p_tunnel->_left_net << "</right>";
          _xml_out << "<esp_state>" << p_tunnel->_esp_state << "</esp_state>";
          _xml_out << "</setkey>";
        }
        ++iter;
      }
    }
    _xml_out << "</peer>";
    ++i;
  }

  if (_xml_out.tellp() > 0) {
    _xml_out << "</format></opcommand>";
  }
  return _xml_out.str();
}

/**
 *
 >ipsec eroute
[root@localhost etc]# ipsec eroute
/usr/libexec/ipsec/eroute: NETKEY does not support eroute table.

 **/
void 
CommandProcShowVPN::convert_to_xml_secrets(const string &line, bool debug)
{
  if (debug) {
    cout << "processing: convert_to_xml_secrets" << endl;
  }
  StrProc proc_str(line, " ");
  if (proc_str.size() > 0) {
    _xml_out << "<secret>";
    _xml_out << "<sip>" << proc_str.get(0) << "</sip>";
    _xml_out << "<dip>" << proc_str.get(1) << "</dip>";
    _xml_out << "<key>" << proc_str.get(4) << "</key>";
    _xml_out << "</secret>";
    }
  /*
  if (line.find("Media type") != string::npos) {
      _xml_out += "<csudsu_type>" + proc_str.get(2) + "</csudsu_type>";
  }
  */
  return;
}

/**
 *
mercury:~# cat /var/run/pluto.pid
3688
 **/
void 
CommandProcShowVPN::convert_to_xml_pluto_pid(const string &line, bool debug)
{
  if (debug) {
    cout << "processing: convert_to_xml_secrets" << endl;
  }
  StrProc proc_str(line, " ");
  if (proc_str.size() > 0) {
    _xml_out << "<pluto_pid>" << proc_str.get(0) << "</pluto_pid>";
  }
  return;
}

/**
 *
mercury:~# setkey -D
10.3.0.198 10.1.0.54
        esp mode=tunnel spi=1222935307(0x48e4830b) reqid=16385(0x00004001)
        E: 3des-cbc  9a562c3f 6a2a9209 02fd7390 524c987e 38491354 1ffe8d44
        A: hmac-md5  b35fd32c 387f2b05 7262373f bc1769bb
        seq=0x00000000 replay=32 flags=0x00000000 state=mature
        created: Jan  5 15:34:55 2007   current: Jan  5 15:42:47 2007
        diff: 472(s)    hard: 0(s)      soft: 0(s)
        last:                           hard: 0(s)      soft: 0(s)
        current: 0(bytes)       hard: 0(bytes)  soft: 0(bytes)
        allocated: 0    hard: 0 soft: 0
        sadb_seq=1 pid=9770 refcnt=0
10.1.0.54 10.3.0.198
        esp mode=tunnel spi=2194861623(0x82d2ee37) reqid=16385(0x00004001)
        E: 3des-cbc  ba1cad93 b0b901d3 5b645165 0719fad2 6ab60ec1 a7c6c593
        A: hmac-md5  0fa8adc6 9f90012f c3a37145 be698b61
        seq=0x00000000 replay=32 flags=0x00000000 state=mature
        created: Jan  5 15:34:55 2007   current: Jan  5 15:42:47 2007
        diff: 472(s)    hard: 0(s)      soft: 0(s)
        last:                           hard: 0(s)      soft: 0(s)
        current: 0(bytes)       hard: 0(bytes)  soft: 0(bytes)
        allocated: 0    hard: 0 soft: 0
        sadb_seq=0 pid=9770 refcnt=0

 **/
void 
CommandProcShowVPN::convert_to_xml_setkey_d(bool debug)
{
  if (debug) {
    cout << "processing: convert_to_xml_setkey_d: " << endl;
  }

  string left_addr, right_addr, dir;
  string spi, sessionid, encryption, key_hash;
  string active_time, bytes;
  int nat_src_port = 0, nat_dst_port = 0;
  bool in_flag = true;

//  std::map<std::string, Tunnel>::const_iterator iter = _coll.end();
//  std::list<Peer>::const_iterator iter = _peers.begin();

  Tunnel * p_tunnel = NULL;

  string cmd = "setkey -D";
  char buf[2048];
  FILE *f = popen(cmd.c_str(), "r");
  if (f) {
    while(fgets(buf, 2047, f) != NULL) { 
      string line(buf);

      if (line.length() > 0 && isdigit(line[0])) {
        StrProc ips(line, " ");
        string src = ips.get(0);
        string::size_type src_o = src.find('[');
	string::size_type src_c = src.find(']');
	if (src_o != string::npos && src_c != string::npos) {
          nat_src_port = atoi(src.substr(src_o + 1, src_c - src_o - 1).c_str());
        } else {
//          nat_src_port.clear();
        }
        string dst = ips.get(1);
        string::size_type dst_o = dst.find('[');
	string::size_type dst_c = dst.find(']');
	if (dst_o != string::npos && dst_c != string::npos) {
          nat_dst_port = atoi(dst.substr(dst_o + 1, dst_c - dst_o - 1).c_str());
        } else {
//          nat_dst_port.clear();
        }
      }

      StrProc proc_str(line, " ");
      if (line.find("spi=") != string::npos) {
	string tmp = proc_str.get(2);
	int pos = tmp.find("(");
	spi = tmp.substr(pos+3,tmp.length()-pos-4);
	
	//now find the entry that corresponds with this spi
        std::list<Peer*>::iterator iPeer = _peers.begin();
        const std::list<Peer*>::const_iterator iPeerEnd = _peers.end();

        while (iPeer != iPeerEnd) {
          Peer * p_peer = *iPeer;
	  if (p_peer != NULL) {
            std::map<std::string, Tunnel*>::iterator iPeerTunnel = p_peer->getPeerTunnels().getTunnelsMap().begin();
            const std::map<std::string, Tunnel*>::const_iterator iPeerTunnelEnd = p_peer->getPeerTunnels().getTunnelsMap().end();

	    Tunnel * p_tunnelHere = NULL;
            while (iPeerTunnel != iPeerTunnelEnd) {
              p_tunnelHere = iPeerTunnel->second;
              if (p_tunnelHere != NULL) {
                if (debug) {
                  cout << "comparing spis: " << spi << ", " << p_tunnelHere->_in._session_id << ", " << p_tunnelHere->_out._session_id << endl;
                }

                if (spi == p_tunnelHere->_in._session_id) {
                  in_flag = true;
                  if (debug) {
                    cout << "found match with spis for in" << endl;
                  }
                  break;
                } else if (spi == p_tunnelHere->_out._session_id) {
                  in_flag = false;
                  if (debug) {
                    cout << "found match with spis for out" << endl;
                  }
                  break;
                }
              }
              ++iPeerTunnel;
            }

            if (iPeerTunnel == iPeerTunnelEnd) {
              p_tunnel = NULL;
            } else {
              p_tunnel = p_tunnelHere;
              if (proc_str.get(0) == "esp-udp") {
                p_peer->_nat_trav = true;
                p_peer->_nat_src_port = nat_src_port;
                p_peer->_nat_dst_port = nat_dst_port;
              } else {
                p_peer->_nat_trav = false;
              }
              break;
            }
          }
          ++iPeer;
        }
      }
      /*      else if (line.find("state=") != string::npos) {
	if (iter != _coll.end()) {
	  string trans_state;
	  string state = proc_str.get(3);
	  if (state.find("mature") != string::npos) {
	    trans_state = "up";
	  }
	  else if (state.find("larval") != string::npos) {
	    trans_state = "init";
	  }
	  else {
	    trans_state = "down";
	  }
	  
	  if (in_flag == true) {
	    iter->second._in._state = trans_state;
	  }
	  else {
	    iter->second._out._state = trans_state;
	  }
	}
      }
      */
      else if (p_tunnel != NULL && line.find("diff:") != string::npos) {
        if (in_flag == true) {
          p_tunnel->_in._active_time = atoi(proc_str.get(1).c_str());
        } else {
          p_tunnel->_out._active_time = atoi(proc_str.get(1).c_str());
        }
      } else if (p_tunnel != NULL && (proc_str.get(0).find("current:") != string::npos)) {
        if (in_flag == true) {
          p_tunnel->_in._bytes = atoi(proc_str.get(1).c_str());
        } else {
          p_tunnel->_out._bytes = atoi(proc_str.get(1).c_str());
        }
        //now complete the transaction here
        p_tunnel = NULL;
      }
    }
    if (pclose(f) != 0) {
      return;
    }
  }
}

/**
 *
 *
sample from conf file:

conn peer-10.6.0.22-tunnel-1
        left=10.6.0.2
        right=10.6.0.22
        type=tunnel
        authby=secret
        leftsubnet=10.1.0.0/24
        rightsubnet=10.7.0.16/28
        ike=aes256-md5-modp1536
        esp=aes256-md5
        auto=start

 *
 **/
void 
CommandProcShowVPN::process_conf(bool debug)
{
  if (debug) {
    cout << "processing: process_conf" << endl;
  }

  string cmd("cat /etc/ipsec.conf");
  char buf[2048];
  FILE *f = popen(cmd.c_str(), "r");
  if (f) {
    string src, dst;
    string rightnet, leftnet, tunnel, tunnel_num;

    while(fgets(buf, 2047, f) != NULL) { 
      string line(buf);
      int pos = line.find("=");
      if (line.find("conn peer-") != string::npos) {
	StrProc proc_str(line, " ");
	tunnel = proc_str.get(1);
        string::size_type dash = tunnel.find_last_of('-');
        if (dash != string::npos) tunnel_num = tunnel.substr(dash + 1);
	src = "";
	dst = "";
      }
      else if (line.find("left=") != string::npos) {
	src=line.substr(pos+1,line.length()-pos-2);
	if (src == "%any") {
	  src = "0.0.0.0";
	}
      }
      else if (line.find("leftid=") != string::npos) {
	src = line.substr(pos + 1, line.length() - pos - 2);
      }
      else if (line.find("right=") != string::npos) {
	dst=line.substr(pos+1,line.length()-pos-2);
	if (dst == "%any") {
	  dst = "0.0.0.0";
	}
      }
      else if (line.find("rightid=") != string::npos) {
	dst = line.substr(pos + 1, line.length() - pos - 2);
      }
      else if (line.find("rightsubnet=") != string::npos) {
	rightnet=line.substr(pos+1,line.length()-pos-2);
      }
      else if (line.find("leftsubnet=") != string::npos) {
	leftnet=line.substr(pos+1,line.length()-pos-2);
      }
      else if (line.find("interfaces") != string::npos) {
	_interface_conf_line = line;
      }
      else if (line.find("auto=start") != string::npos || line.find("auto=add") != string::npos) {
        Peer * p_peer = NULL;
        std::list<Peer*>::iterator i = _peers.begin();
        const std::list<Peer*>::const_iterator iEnd = _peers.end();
        while (i != iEnd) {
          Peer * p_peerCheck = *i;
	  if (p_peerCheck != NULL && p_peerCheck->_right_ip == src && p_peerCheck->_left_ip == dst) {
            p_peer = p_peerCheck;
            break;
          }
          ++i;
        }
        if (p_peer == NULL) {
          p_peer = new Peer();
          _peers.push_back(p_peer);
          p_peer->_right_ip = src;
          p_peer->_left_ip = dst;
        }

	Tunnel * p_tunnel = new Tunnel(_all_tunnels, *p_peer);
        p_tunnel->_tunnel_name = tunnel;
        p_tunnel->_tunnel_number = tunnel_num;
	p_tunnel->_right_net = rightnet;
	p_tunnel->_left_net = leftnet;
	p_peer->getPeerTunnels().add(tunnel, p_tunnel);
	_all_tunnels.add(tunnel, p_tunnel);
      }
    }
    pclose(f);
  }
  return;
}

/**
 *
 *
 **/
void 
CommandProcShowVPN::convert_to_xml_auto_status(const string &line, bool debug)
{
  if (debug) {
    cout << "processing: convert_to_xml_auto_status" << endl;
  }
  StrProc proc_str(line, " ");

  if (line.find("000 interface") != string::npos) {
    string tmp = proc_str.get(2);
    string::size_type pos = tmp.find("/");
    if (pos != string::npos) {
      string interface = tmp.substr(0,pos);
      if (_interface_conf_line.find(interface) != string::npos) {
	_xml_out << "<auto_status_interface>";
	_xml_out << "<iface>" << interface << "</iface>";
	_xml_out << "<address>" << proc_str.get(3) << "</address>";
	_xml_out << "</auto_status_interface>";
      }
    }
  }

  string strToken1 = proc_str.get(1);
  string strToken2 = proc_str.get(2);

  string strTunnelName;
  if ((strToken1.find("\"peer-") == 0) && (strToken1[strToken1.length() - 1] == ':')) {
    string::size_type iEnd = strToken1.find("\"", 1);
    if (iEnd != string::npos) {
      strTunnelName = strToken1.substr(1, iEnd-1);
    }
  } else if ((strToken1.length() > 2 && strToken1[0] == '#' && strToken1[strToken1.length() - 1] == ':') && ((strToken2.find("\"peer-") == 0))) {
    string::size_type iEnd = strToken2.find("\"", 1);
    if (iEnd != string::npos) {    
      strTunnelName = strToken2.substr(1, iEnd-1);
    }
  }

  if (strTunnelName.length() == 0) return;

  string::size_type iPeer = strTunnelName.find("peer-");
  string::size_type iTunnel = strTunnelName.find("-tunnel-");
  if (iPeer == string::npos || iPeer != 0 || iTunnel == string::npos) return;
  string strPeerIP = strTunnelName.substr(5, iTunnel - 5);

  Tunnel * p_tunnel = _all_tunnels.getTunnelsMap()[strTunnelName];
  
  if (p_tunnel == NULL) return;

  //now retrieve ike and esp encryption and hash
  if (line.find(" proposal: ") != string::npos) { //look up encryption/hash
    //strip out the tunnel

    //  000 "peer-10.6.0.57-tunnel-1":   IKE algorithm newest: 3DES_CBC_192-MD5-MODP1536
    //  000 "peer-10.6.0.57-tunnel-1":   ESP algorithm newest: AES_128-HMAC_SHA1; pfsgroup=<Phase1>

    //  need to parse lifetime from setup output
    //  000 "peer-10.6.0.57-tunnel-50":   ike_life: 3600s; ipsec_life: 28800s; rekey_margin: 540s; rekey_fuzz: 100%; keyingtries: 00

    string eh = proc_str.get(4);

    StrProc tmp(eh, "/");

    //allowed e values: aes128, aes256, 3des
    //allowed h values: md5, sha1, sha2_256, sha2_384, sha2_512
    //allowed m values: MOD1024, MODP1536
    string e = tmp.get(0);
    string h = tmp.get(1);
    string m = tmp.get(2);
    if (e.find("128") != string::npos) {
      e = "aes128";
    } else if (e.find("256") != string::npos) {
      e = "aes256";
    } else if (e.find("3DES") != string::npos) {
      e = "3des";
    }

    if (h.find("MD5") != string::npos) {
      h = "md5";
    } else if (h.find("SHA1") != string::npos) {
      h = "sha1";
    } else if (h.find("_256") != string::npos) {
      h = "sha2_256";
    } else if (h.find("_384") != string::npos) {
      h = "sha2_384";
    } else if (h.find("_512") != string::npos) {
      h = "sha2_512";
    }
    
    if (m.find("1024") != string::npos) {
    	m = "2";
    } else if (m.find("1536") != string::npos) {
    	m = "5";
    } else if (m.find("Phase1") != string::npos) {
    	m = "Phase1";
    } else {
	m = "Disabled";
    }

    //assign encryption and hash
    if (proc_str.get(2) == "IKE") {
      p_tunnel->getPeer()._ike_encrypt = e;
      p_tunnel->getPeer()._ike_hash = h;
      p_tunnel->getPeer()._ike_dh = m;
    } else { //ESP
      p_tunnel->_esp_encrypt = e;
      p_tunnel->_esp_hash = h;
      p_tunnel->_pfs_group = m;
    }
    
  } else if (line.find("ike_life:") != string::npos) {
    p_tunnel->getPeer()._ike_seconds_lifetime = atoi(proc_str.get(3).substr(0,proc_str.get(3).length()-1).c_str());
    p_tunnel->_keylife = atoi(proc_str.get(5).c_str());
  } else if (line.find("STATE_") != string::npos) { //for state now...
    if (p_tunnel->getPeer()._ike_state == "down") p_tunnel->getPeer()._ike_state = "init";
    if (p_tunnel->_esp_state == "down") p_tunnel->_esp_state = "init";

    {
      string strIKEEI("ISAKMP SA established); EVENT_SA_EXPIRE in ");
      string::size_type iIKEEI = line.find(strIKEEI);
      if (iIKEEI != string::npos) {
        string strIKEExpireIn = line.substr(iIKEEI, line.length() - iIKEEI);
        string strSecondsStart = strIKEExpireIn.substr(strIKEEI.length(), strIKEExpireIn.length() - strIKEEI.length());
        string::size_type iSecondsEnd = strSecondsStart.find("s; ");
        if (iSecondsEnd != string::npos) {
          string strSeconds = strSecondsStart.substr(0, iSecondsEnd);
	  int ike_seconds_lifetime_left = atoi(strSeconds.c_str());
	  if (ike_seconds_lifetime_left > 0) {
            p_tunnel->getPeer()._ike_seconds_lifetime_left = ike_seconds_lifetime_left;
	    p_tunnel->getPeer()._ike_state = "up";
	  }
        }
      }
    }
    {
      string strIKERI("ISAKMP SA established); EVENT_SA_REPLACE in ");
      string::size_type iIKERI = line.find(strIKERI);
      if (iIKERI != string::npos) {
        string strIKEReplaceIn = line.substr(iIKERI, line.length() - iIKERI);
        string strSecondsStart = strIKEReplaceIn.substr(strIKERI.length(), strIKEReplaceIn.length() - strIKERI.length());
        string::size_type iSecondsEnd = strSecondsStart.find("s; ");
        if (iSecondsEnd != string::npos) {
          string strSeconds = strSecondsStart.substr(0, iSecondsEnd);
	  int ike_seconds_lifetime_left = atoi(strSeconds.c_str());
	  if (ike_seconds_lifetime_left > 0) {
            p_tunnel->getPeer()._ike_seconds_lifetime_left = ike_seconds_lifetime_left;
	    p_tunnel->getPeer()._ike_state = "up";
	  }
        }
      }
    }


    if (line.find("IPsec SA established); EVENT_SA_REPLACE") != string::npos) p_tunnel->_esp_state = "up";
  } else if (line.find("esp.") != string::npos) { //look up tunnel id
    //strip out the tunnel
    
    //  000 #2: "peer-10.6.0.57-tunnel-1" esp.d54ce9b0@10.6.0.57 esp.225ad1e@10.6.0.55 tun.0@10.6.0.57 tun.0@10.6.0.55
    
    if (debug) {
      cout << "ipsec statusall: found esp: " << line << ", " << strTunnelName << endl;
    }
    
    StrProc ps(line, "@");
    string id = ps.get(0);
    int start = id.rfind(".");
    id = id.substr(start+1, id.length()-start-1);
    id = _pad[8 - id.length()] + id;
    p_tunnel->_in._session_id = id;

    id = ps.get(1);
    start = id.rfind(".");
    id = id.substr(start+1, id.length()-start-1);
    id = _pad[8 - id.length()] + id;
    p_tunnel->_out._session_id = id;

  }
}

const PeerTunnels & Peer::getConstPeerTunnels() const {
  return _peer_tunnels;
}

PeerTunnels & Peer::getPeerTunnels() {
  return _peer_tunnels;
}

Tunnel::~Tunnel() {
  _all_tunnels.unlink(this);
  _peer._peer_tunnels.unlink(this);
}
Peer & Tunnel::getPeer() {
  return _peer;
}
Tunnels::~Tunnels() {
  map<string, Tunnel*>::iterator i = _tunnels.begin();
  const map<string, Tunnel*>::const_iterator iEnd = _tunnels.end();
  while (i != iEnd) {
    Tunnel * p_tunnel = i->second;
    if (p_tunnel != NULL) {
      i->second = NULL;
      delete p_tunnel;
    }
    i++;
  }
}
Tunnels::Tunnels() {
}
const map<string, Tunnel*> & Tunnels::getConstTunnelsMap() const {
  return _tunnels;
}
map<string, Tunnel*> & Tunnels::getTunnelsMap() {
  return _tunnels;
}
void Tunnels::add(const string & strTunnelName, Tunnel * p_tunnel) {
  _tunnels[strTunnelName] = p_tunnel;
}
void Tunnels::unlink(const Tunnel * p_tunnel) {
  if (p_tunnel != NULL) _tunnels[p_tunnel->_tunnel_name] = NULL;
}
