# (C) Copyright 2004 Nuxeo SARL <http://nuxeo.com>
# Author: Florent Guillaume <fg@nuxeo.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
# $Id$
"""
Patch for GRUF

Patch to add a GRUF-specific method.
"""

from AccessControl import ClassSecurityInfo
from Globals import InitializeClass

from Products.CPSUserFolder.CPSUserFolder import CPSUserFolder


security = ClassSecurityInfo()

security.declarePublic('getLocalRolesForDisplay')
def getLocalRolesForDisplay(self, object):
    """Used by Plone's local roles display.

    Returns a tuple (massagedUsername, roles, userType, actualUserName).
    """
    result = []
    prefix = 'group_'
    for username, roles in object.get_local_roles():
        massagedUsername = username
        userType = 'user'
        result.append((massagedUsername, roles, userType, username))
##     for groupname, roles in object.get_local_group_roles():
##         massagedGroupname = groupname
##         userType = 'group'
##         result.append((massagedGroupname, roles, userType, group))
    return tuple(result)

CPSUserFolder.getLocalRolesForDisplay = getLocalRolesForDisplay
CPSUserFolder.security = security
InitializeClass(CPSUserFolder)
