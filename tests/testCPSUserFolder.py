# (C) Copyright 2004-2005 Nuxeo SARL <http://nuxeo.com>
# Authors: Florent Guillaume <fg@nuxeo.com>
#          Julien Anguenot <ja@nuxeo.com>
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

import os, sys
from copy import deepcopy

import unittest

from Interface import Interface
from Interface.Verify import verifyClass
from OFS.Folder import Folder as OFS_Folder

from Products.CPSUserFolder.TimeoutCache import resetAllCaches

from Products.CPSUserFolder.CPSUserFolder import CPSUserFolder
from Products.CPSUserFolder.CPSUserFolder import CPSUser



class Folder(OFS_Folder):
    def __init__(self, id):
        self._setId(id)
        OFS_Folder.__init__(self)

_marker = object()
class FakeDirectory(Folder):
    def __init__(self, id, id_field, blank):
        Folder.__init__(self, id)
        self.id_field = id_field
        self.blank = blank
        self.entries = {}
    def getEntry(self, id, default=_marker):
        res = self.entries.get(id, default)
        if res is _marker: raise KeyError(id)
        return res
    _getEntry = getEntry
    def createEntry(self, entry):
        new = deepcopy(self.blank)
        new.update(entry)
        self.entries[entry[self.id_field]] = new
    def editEntry(self, entry):
        self.entries[entry[self.id_field]].update(entry)
    def deleteEntry(self, id):
        del self.entries[id]
    def hasEntry(self, id):
        return self.entries.has_key(id)
    def listEntryIds(self):
        return self.entries.keys()


def sorted(l):
    l = list(l)
    l.sort()
    return l


# TODO: fix AccessControl.IUserFolder instead
class IStandardUserFolder(Interface):
    def getUser(name): pass
    def getUsers(): pass
    def getUserNames(): pass


class TestCPSUser(unittest.TestCase):

    def makeUser(self):
        id = 'someuser'
        roles = ['SomeRole']
        groups = ['somegroup']
        entry = {'givenName': 'James', 'sn': 'Bond',
                 'list': ['a', 'b']}
        password = 'secret'
        user = CPSUser(id, password, roles, groups, entry)
        return user

    def makeFolders(self):
        self.root = Folder('root')
        self.root.fold = Folder('fold')
        self.root.fold.ob = Folder('ob')
        return self.root

    def test_basic(self):
        user = self.makeUser()
        self.assertEquals(user.getId(), 'someuser')
        self.assertEquals(user.getUserName(), 'someuser')
        self.assertEquals(user._getPassword(), 'secret')
        self.assertEquals(sorted(user.getRoles()),
                          ['Anonymous', 'Authenticated', 'SomeRole'])
        self.assertEquals(user.getDomains(), [])
        self.assertEquals(user.getGroups(), ('somegroup',))
        self.assertEquals(sorted(user.getComputedGroups()),
                          ['role:Anonymous', 'role:Authenticated',
                           'somegroup'])

    def test_getProperty(self):
        user = self.makeUser()
        self.assertEquals(user.getProperty('sn'), 'Bond')
        self.assertEquals(user.getProperty('blob', 'arf'), 'arf')
        self.assertRaises(KeyError, user.getProperty, ('blob',))
        self.assertEquals(user.getProperty('list'), ['a', 'b'])
        # make sure lists are not shared
        l1 = user.getProperty('list')
        l2 = user.getProperty('list')
        self.assert_(l1 is not l2)

    def test_getRolesInContext(self):
        user = self.makeUser()
        root = self.makeFolders()
        fold = root.fold
        ob = fold.ob

        base = ['Anonymous', 'Authenticated', 'SomeRole']
        self.assertEquals(sorted(user.getRolesInContext(root)), base)
        self.assertEquals(sorted(user.getRolesInContext(fold)), base)
        self.assertEquals(sorted(user.getRolesInContext(ob)), base)

        fold.manage_setLocalRoles('someuser', ['Daddy'])
        self.assertEquals(sorted(user.getRolesInContext(root)), base)
        self.assertEquals(sorted(user.getRolesInContext(fold)),
                          ['Anonymous', 'Authenticated', 'Daddy', 'SomeRole'])
        self.assertEquals(sorted(user.getRolesInContext(ob)),
                          ['Anonymous', 'Authenticated', 'Daddy', 'SomeRole'])

        fold.manage_setLocalGroupRoles('somegroup', ['Chief'])
        self.assertEquals(sorted(user.getRolesInContext(root)), base)
        self.assertEquals(sorted(user.getRolesInContext(fold)),
                          ['Anonymous', 'Authenticated', 'Chief', 'Daddy',
                           'SomeRole'])
        self.assertEquals(sorted(user.getRolesInContext(ob)),
                          ['Anonymous', 'Authenticated', 'Chief', 'Daddy',
                           'SomeRole'])

    def test_getRolesInContext_blocking(self):
        user = self.makeUser()
        root = self.makeFolders()
        fold = root.fold
        ob = fold.ob

        base = ['Anonymous', 'Authenticated', 'SomeRole']
        self.assertEquals(sorted(user.getRolesInContext(root)), base)
        self.assertEquals(sorted(user.getRolesInContext(fold)), base)
        self.assertEquals(sorted(user.getRolesInContext(ob)), base)

        # Blocking a specific role for a user (not usable from CMF)
        fold.manage_setLocalRoles('someuser', ['Daddy'])
        ob.manage_setLocalRoles('someuser', ['-Daddy'])
        self.assertEquals(sorted(user.getRolesInContext(fold)),
                          ['Anonymous', 'Authenticated', 'Daddy', 'SomeRole'])
        self.assertEquals(sorted(user.getRolesInContext(ob)), base)

        # Blocking all roles for a user (not usable from CMF)
        ob.manage_setLocalRoles('someuser', ['-'])
        self.assertEquals(sorted(user.getRolesInContext(fold)),
                          ['Anonymous', 'Authenticated', 'Daddy', 'SomeRole'])
        self.assertEquals(sorted(user.getRolesInContext(ob)), base)

        # Blocking all roles for all
        ob.manage_delLocalRoles(['someuser'])
        ob.manage_setLocalGroupRoles('role:Anonymous', ['-'])
        self.assertEquals(sorted(user.getRolesInContext(fold)),
                          ['Anonymous', 'Authenticated', 'Daddy', 'SomeRole'])
        self.assertEquals(sorted(user.getRolesInContext(ob)), base)

        # Blocking a specific role for all
        ob.manage_setLocalGroupRoles('role:Anonymous', ['-Daddy'])
        self.assertEquals(sorted(user.getRolesInContext(fold)),
                          ['Anonymous', 'Authenticated', 'Daddy', 'SomeRole'])
        self.assertEquals(sorted(user.getRolesInContext(ob)), base)


class TestCPSUserFolder(unittest.TestCase):

    def makeFolders(self):
        self.root = Folder('root')
        self.root.fold = Folder('fold')
        self.root.fold.ob = Folder('ob')
        return self.root

    def testInterface(self):
        # TODO: remove 'tentative=1' after putting __implements__ in
        # CPSUserFolder class
        verifyClass(IStandardUserFolder, CPSUserFolder, tentative=1)

    def test_mergedLocalRoles(self):
        aclu = CPSUserFolder()
        root = self.makeFolders()
        fold = root.fold
        ob = fold.ob

        self.assertEquals(aclu.mergedLocalRoles(root), {})
        self.assertEquals(aclu.mergedLocalRoles(fold), {})
        self.assertEquals(aclu.mergedLocalRoles(ob), {})

        # Basic
        fold.manage_setLocalRoles('someuser', ['Daddy'])
        self.assertEquals(aclu.mergedLocalRoles(fold),
                          {'someuser': ['Daddy']})
        self.assertEquals(aclu.mergedLocalRoles(fold, withgroups=1),
                          {'user:someuser': ['Daddy']})

        # Blocking a specific role for a user
        # (ignored by mergedLocalRoles because cannot be expressed)
        ob.manage_setLocalRoles('someuser', ['-Daddy'])
        self.assertEquals(aclu.mergedLocalRoles(ob, withgroups=1),
                          {'user:someuser': ['Daddy']})

        # Blocking all roles for a user (ignored by mergedLocalRoles)
        # (ignored by mergedLocalRoles because cannot be expressed)
        ob.manage_setLocalRoles('someuser', ['-'])
        self.assertEquals(aclu.mergedLocalRoles(ob, withgroups=1),
                          {'user:someuser': ['Daddy']})

        # Blocking all roles for all
        ob.manage_delLocalRoles(['someuser'])
        ob.manage_setLocalGroupRoles('role:Anonymous', ['-'])
        self.assertEquals(aclu.mergedLocalRoles(ob, withgroups=1),
                          {})

        # Blocking a specific role for all
        ob.manage_setLocalGroupRoles('role:Anonymous', ['-Daddy'])
        self.assertEquals(aclu.mergedLocalRoles(ob, withgroups=1),
                          {})

        # Pathological cases
        ob.manage_setLocalGroupRoles('role:Anonymous', ['', '-', 'Bar'])
        self.assertEquals(aclu.mergedLocalRoles(ob, withgroups=1),
                          {'group:role:Anonymous': ['Bar']})


    def makeWithDirs(self):
        # Make a portal, aclu, and fake directories.
        portal = self.portal = Folder('portal')
        dirtool = portal.portal_directories = Folder('portal_directories')
        dirtool.members = FakeDirectory(
            'members', 'uid', {'pw': 'secret',
                               'roles': [],
                               'groups': [],
                               'sn': None,
                               })
        dirtool.groups = FakeDirectory(
            'groups', 'group', {'members': ()})
        aclu = portal.aclu = CPSUserFolder()
        aclu.manage_changeProperties(
            users_dir='members',
            users_password_field='pw',
            users_roles_field='roles',
            users_groups_field='groups',
            )
        resetAllCaches()

    def test_userfolder_API(self):
        self.makeWithDirs()

        portal = self.portal
        aclu = portal.aclu
        mdir = portal.portal_directories.members

        # Entry bob doesn't exist yet.
        self.assertRaises(KeyError, mdir.getEntry, 'bob')
        self.assertEquals(aclu.getUserById('bob'), None)
        self.assertEquals(aclu.getUserById('bob', 'no'), 'no')
        self.assertEquals(aclu.getUser('bob'), None)
        self.assertEquals(aclu.getUserNames(), [])

        # Create a bob entry.
        aclu.userFolderAddUser('bob', 'secret', ['Member'], (), groups=['gr'])
        self.assertEquals(aclu.getUserNames(), ['bob'])
        user = aclu.getUserById('bob')
        self.assertEquals(user.getProperty('uid'), 'bob')
        self.assertEquals(user.getProperty('pw'), 'secret')
        self.assertEquals(user.getProperty('roles'), ('Member',))
        self.assertEquals(user.getProperty('groups'), ('gr',))

        # Ask the directory directly.
        entry = mdir.getEntry('bob')
        self.assertEquals(entry['uid'], 'bob')
        self.assertEquals(entry['pw'], 'secret')
        self.assertEquals(entry['roles'], ('Member',))
        self.assertEquals(entry['groups'], ('gr',))

        # Change the user entry through the user folder.
        aclu.userFolderEditUser('bob', 'secret2', ['Manager'], (),
                                groups=['hi'])
        user = aclu.getUserById('bob')
        self.assertEquals(user.getProperty('uid'), 'bob')
        self.assertEquals(user.getProperty('pw'), 'secret2')
        self.assertEquals(user.getProperty('roles'), ('Manager',))
        self.assertEquals(user.getProperty('groups'), ('hi',))

        # Ask the directory directly.
        entry = mdir.getEntry('bob')
        self.assertEquals(entry['uid'], 'bob')
        self.assertEquals(entry['pw'], 'secret2')
        self.assertEquals(entry['roles'], ('Manager',))
        self.assertEquals(entry['groups'], ('hi',))

        # Delete the user entry though the user folder.
        aclu.userFolderDelUsers(['bob'])
        self.assertRaises(KeyError, mdir.getEntry, 'bob')
        self.assertEquals(aclu.getUserById('bob'), None)

    def test_properties(self):
        self.makeWithDirs()
        aclu = self.portal.aclu
        mdir = self.portal.portal_directories.members
        entry = {'uid': 'donald',
                 'pw': 'secretduck',
                 'roles': ('Loser',),
                 'groups': ('ducks',),
                 'sn': 'Donald',
                 }
        mdir.createEntry(entry)
        user = aclu.getUserById('donald')
        self.assertEquals(user.getProperty('sn'), 'Donald')
        # Change value
        user.setProperties(sn='Duck')
        self.assertEquals(user.getProperty('sn'), 'Duck')
        e = mdir.getEntry('donald')
        self.assertEquals(e['sn'], 'Duck')
        # Re-get user from user folder, check cache was invalidated
        u = aclu.getUserById('donald')
        self.assertEquals(user.getProperty('sn'), 'Duck')

    def test_group_API(self):
        self.makeWithDirs()

        portal = self.portal
        aclu = portal.aclu
        gdir = portal.portal_directories.groups

        # Create a new group using the directory.
        entry = {'group': 'rodents', 'members': ['mickey']}
        gdir.createEntry(entry)

        # Check the availability through the user folder.
        group = aclu.getGroupById('rodents')
        self.assertEquals(group.getUsers(), ['mickey'])

        # Try to get a non existing entry.
        group = aclu.getGroupById('fake', None)
        self.assertEquals(group, None)

    def test_user_not_shared(self):
        # Ensure that two requests for the same user return a different object.
        # This will avoid them being shared between threads, which causes
        # problems for the persistent references a user holds.
        self.makeWithDirs()
        aclu = self.portal.aclu
        aclu.userFolderAddUser('bob', 'secret', ['Member'], [])
        user1 = aclu.getUserById('bob')
        user2 = aclu.getUserById('bob')
        self.assert_(user1 is not user2, "User objets are the same")

def test_suite():
    return unittest.TestSuite((
        unittest.makeSuite(TestCPSUserFolder),
        unittest.makeSuite(TestCPSUser),
        ))

if __name__ == '__main__':
    unittest.TextTestRunner().run(test_suite())
