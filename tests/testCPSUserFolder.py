# (C) Copyright 2004-2005 Nuxeo SARL <http://nuxeo.com>
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

import os, sys

import unittest

from Interface import Interface
from Interface.Verify import verifyClass
from OFS.Folder import Folder as OFS_Folder


from Products.CPSUserFolder.CPSUserFolder import CPSUserFolder
from Products.CPSUserFolder.CPSUserFolder import CPSUser



class Folder(OFS_Folder):
    def __init__(self, id):
        self._setId(id)
        OFS_Folder.__init__(self)


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
        dir = None
        aclu = None
        password = 'secret'
        user = CPSUser(id, roles, groups, entry, dir, aclu, password)
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

    #def test_setProperties(self):
    # needs fake dir and fake aclu

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


def test_suite():
    return unittest.TestSuite((
        unittest.makeSuite(TestCPSUserFolder),
        unittest.makeSuite(TestCPSUser),
        ))

if __name__ == '__main__':
    unittest.TextTestRunner().run(test_suite())
