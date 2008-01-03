/**
 *    Module: command_proc_base.hh
 *
 *    Author: Michael Larson
 *    Date: 2005
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
#ifndef __COMMAND_PROC_BASE_HH__
#define __COMMAND_PROC_BASE_HH__

#include <assert.h>
#include <vector>
#include <list>
#include <string>

#define UNUSED(var)             assert(sizeof(var) != 0)


/**
 * Derive from this class when you want to create a new unformatted to xml processing implementation.
 *
 **/
class CommandProcBase
{
public:
  typedef std::vector<std::string> StringColl;
  typedef std::vector<std::string>::iterator StringIter;

public:
  CommandProcBase() {;}
  virtual ~CommandProcBase() {;}

  /**
   *
   **/
  virtual std::string
  process(const std::string &cmd, bool debug, std::string &reason) = 0;

  /**
   *
   **/
  static std::string
  name() {return std::string("");}

  /**
   *
   **/
  virtual bool
  is_valid() = 0;

  /**
   *
   **/
  virtual std::string
  xsl() {return _xsl;}

protected: //method
  std::list<std::string>
  tokenize(const std::string &line);

protected:
  std::string _xsl;
};

#endif
