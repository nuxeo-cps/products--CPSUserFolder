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
CPSUserFolder

A user folder based on CPSDirectory and CPSSchemas.
"""

from Globals import InitializeClass
from AccessControl import ClassSecurityInfo

from AccessControl.User import UserFolder


class CPSUserFolder(UserFolder):
    """CPS User Folder

    User folder whose configuration is based on directories.
    """

    meta_type = 'CPSUserFolder'
    title = 'CPS User Folder'

    security = ClassSecurityInfo()

    def __init__(self):
        UserFolder.__init__(self)

InitializeClass(CPSUserFolder)


def addCPSUserFolder(container, id=None, REQUEST=None):
    """Add a CPS User Folder"""
    container = container.this() # For FactoryDispatcher.
    f = CPSUserFolder()
    container._setObject('acl_users', f)
    container.__allow_groups__ = f
    if REQUEST is not None:
        REQUEST.RESPONSE.redirect(container.absolute_url()+'/manage_main')
