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

from Testing import ZopeTestCase
from Products.CPSDefault.tests import CPSTestCase
from Products.CPSUserFolder.CPSUserFolder \
    import CPSUserFolder, addCPSUserFolder

ZopeTestCase.installProduct('CPSSchemas')
ZopeTestCase.installProduct('CPSDirectory')
ZopeTestCase.installProduct('CPSUserFolder')

def _doAddUser(self, *args):
    pass
CPSUserFolder._doAddUser = _doAddUser

class CPSUserFolderInstaller(CPSTestCase.CPSInstaller):
    def addPortal(self, id):
        # CPS Default Site
        CPSTestCase.CPSInstaller.addPortal(self, id)
        portal = getattr(self.app, id)

        portal.manage_delObjects(ids=['acl_users'])
        addCPSUserFolder(portal)

# FIXME: not working yet
#CPSTestCase.setupPortal(PortalInstaller=CPSUserFolderInstaller)

CPSTestCase.setupPortal()

class CPSUserFolderTestCase(CPSTestCase.CPSTestCase):
    pass

