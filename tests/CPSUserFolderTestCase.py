# (C) Copyright 2004 Nuxeo SARL <http://nuxeo.com>
# Author: Florent Guillaume <fg@nuxeo.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the1
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
# $Id$

from zExceptions.unauthorized import Unauthorized

from Testing import ZopeTestCase
from Products.ExternalMethod.ExternalMethod import ExternalMethod

from Products.CPSDefault.tests import CPSTestCase

ZopeTestCase.installProduct('CPSUserFolder')

from Products.CPSUserFolder.CPSUserFolder import CPSUserFolder
from Products.CPSUserFolder.CPSUserFolder import addCPSUserFolder

## XXX
## Patch on CPSDirectory.BaseDirectory to allow the creation of
## use within the tests

from Products.CPSDirectory.BaseDirectory import BaseDirectory

def checkCreateEntryAllowed(self, id=None, entry=None):
    return 1

def checkEditEntryAllowed(self, id=None, entry=None):
    return 1


BaseDirectory.checkCreateEntryAllowed = checkCreateEntryAllowed
BaseDirectory.checkEditEntryAllowed = checkEditEntryAllowed

## //
## EOF

class CPSUserFolderTestCase(CPSTestCase.CPSTestCase):
    pass
    ##def _setupUser(self):
    ##    '''Creates the default user.'''
    ##    try:
    ##        CPSTestCase.CPSTestCase._setupUser(self)
    ##    except Unauthorized:
    ##        pass

class CPSUserFolderInstaller(CPSTestCase.CPSInstaller):

    def addPortal(self, id):
        # CPS Default Site
        CPSTestCase.CPSInstaller.addPortal(self, id)
        portal = getattr(self.app, id)

        # add a CPSUserFolder
        portal.manage_delObjects(ids=['acl_users'])
        _properties =  {
            'users_dir' : 'members',
            'users_login_field' : 'id',
            'users_password_field' : 'password', 
            'users_roles_field' :'roles', 
            'users_groups_field' :'groups' ,
            'groups_dir' : 'groups',
            'cache_timeout' : 300 
            }
        addCPSUserFolder(portal, **_properties)

        # Delete the std Members directory since it's not compatible
        # with the CPSUserFolder
        dtool = portal.portal_directories
        dtool.manage_delObjects(['members'])

        _properties = {
            'schema' : 'members',
            'schema_search' : 'members_search',
            'layout' : 'members',
            'layout_search' : 'members_search',
            'id_field' : 'id',
            'title_field' : 'fullname',
            'search_substring_fields' : [],
            }
        
        dtool.manage_addCPSDirectory('members', 'CPS ZODB Directory',
                                     **_properties)

        # Add a Manager
        users_dir = dtool.members
        manager_entry = {'id':'manager',
                         'password':'secret',
                         'roles' : ['Manager', 'Member'],
                         }
        users_dir.createEntry(manager_entry)

CPSTestCase.setupPortal(PortalInstaller=CPSUserFolderInstaller)
