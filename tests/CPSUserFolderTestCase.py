# (C) Copyright 2005 Nuxeo SARL <http://nuxeo.com>
# Author: Julien Anguenot <ja@nuxeo.com>
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
## it's a problem for the first user that we wanna create

from Products.CPSDirectory.BaseDirectory import BaseDirectory

def checkCreateEntryAllowed(self, id=None, entry=None):
    return 1

def checkEditEntryAllowed(self, id=None, entry=None):
    return 1


BaseDirectory.checkCreateEntryAllowed = checkCreateEntryAllowed
BaseDirectory.checkEditEntryAllowed = checkEditEntryAllowed

## //
## EOF

CPSUserFolderTestCase = CPSTestCase.CPSTestCase

class CPSUserFolderInstaller(CPSTestCase.CPSInstaller):

    #
    # XXX : perform links in between members -> roles and
    # members -> groups directory within computed fields
    # CPSUserFolder limitation for the moment.
    #

    def _getPortal(self, id):
        return getattr(self.app, id)

    def _addCPSUserFolder(self, portal):
        portal.manage_delObjects(ids=['acl_users'])
        _properties =  {
            'users_dir' : 'members',
            'users_login_field' : 'id',
            'users_password_field' : 'password', 
            'users_roles_field' :'roles', 
            'users_groups_field' :'groups' ,
            'groups_dir' : 'groups',
            'groups_members_field': 'members',
            'roles_members_field': 'members',
            'cache_timeout' : 300 
            }
        addCPSUserFolder(portal, **_properties)

    def _setupMembersDirectory(self, portal):

        #
        # Delete the std Members directory since it's not compatible
        # with the CPSUserFolder
        #

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
        assert('members' in dtool.objectIds())

    def _setupGroupsDirectory(self, portal):

        #
        # Delete the std Groups directory since it's not compatible
        # with the CPSUserFolder
        #

        dtool = portal.portal_directories
        dtool.manage_delObjects(['groups'])

        _properties = {
            'schema' : 'groups',
            'schema_search' : 'groups_search',
            'layout' : 'groups',
            'layout_search' : 'groups_search',
            'id_field' : 'group',
            'title_field' : 'group',
            'search_substring_fields' : [],
            }
        
        dtool.manage_addCPSDirectory('groups', 'CPS ZODB Directory',
                                     **_properties)
        assert('groups' in dtool.objectIds())

    def _setupRolesDirectory(self, portal):

        #
        # Delete the std Roles directory since it's not compatible
        # with the CPSUserFolder
        #

        dtool = portal.portal_directories
        dtool.manage_delObjects(['roles'])

        _properties = {
            'schema' : 'roles',
            'schema_search' : 'roles_search',
            'layout' : 'roles',
            'layout_search' : 'roles_search',
            'id_field' : 'role',
            'title_field' : 'role',
            'search_substring_fields' : [],
            }
        
        dtool.manage_addCPSDirectory('roles', 'CPS ZODB Directory',
                                     **_properties)
        assert('roles' in dtool.objectIds())

        roles_dir = dtool.roles

        default_entries = ({'role' : 'Member', 'members' : ()},
                           {'role' : 'Manager', 'members' : ()},
                           )
        for each in default_entries:
            roles_dir.createEntry(each)

    ################################################################
    ################################################################
    
    def addPortal(self, id):
        # CPS Default Site
        CPSTestCase.CPSInstaller.addPortal(self, id)
        portal = self._getPortal(id)

        # add a CPSUserFolder
        self._addCPSUserFolder(portal)

        # setup Members directory
        self._setupMembersDirectory(portal)

        # setup Groups directory
        self._setupGroupsDirectory(portal)

        # setup Roles directory
        self._setupRolesDirectory(portal)
        
CPSTestCase.setupPortal(PortalInstaller=CPSUserFolderInstaller)
