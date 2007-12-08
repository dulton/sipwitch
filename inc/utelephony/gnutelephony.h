// Copyright (C) 2006-2007 David Sugar, Tycho Softworks.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Top level include directory for GNU Telephony.
 * This is a master include file that will be used when producing
 * new GNU Telephony services.  It includes all generic library headers
 * from both GNU Telephony and UCommon.
 * @file gnutelephony/gnutelephony.h
 */

#ifndef	_GNUTELEPHONY_GNUTELEPHONY_H_
#define	_GNUTELEPHONY_GNUTELEPHONY_H_

#include <ucommon/ucommon.h>
#include <gnutelephony/mapped.h>
#include <gnutelephony/service.h>
#include <gnutelephony/process.h>
#include <gnutelephony/digest.h>

#endif

/**
 * @short GNU Telephony common library and API services.
 * GNU Telephony is a package of libraries which may be used together to
 * build telephony services for current and next generation telephone
 * networks.  The core GNU Telephony libraries are offered as a C++
 * framework which are distributed as part of UCommon and GNU SIP Witch.  
 * Other packages, such as GNU Bayonne 3, will add things like the Bayonne 
 * scripting engines and auxillory classes to further extend the GNU 
 * Telephony core API as well as introducing new services.
 * @author David Sugar <dyfet@gnutelephony.org>
 * @license GNU GPL Version 3 or later.
 * @mainpage GNU Telephony
 */

/** 
 * Common namespace for all GNU Telephony objects. 
 * We are using the UCommon namespace for GNU Telephony objects.  This  
 * namespace may be changed from ucc to gnu when we merge UCommon with  
 * GNU Common C++.  In any case, it is controlled by macros in the UCommon 
 * package, and so any changes will be hidden from user applications so long  
 * as the namespace macros (UCOMMON_NAMESPACE, NAMESPACE_UCOMMON,  
 * END_NAMESPACE) are used in place of direct namespace declarations. 
 * @namespace ucc 
 */


