#!/usr/bin/python
# -*- coding: iso-8859-15 -*-

# (C) Copyright 2004 Nuxeo SARL <http://nuxeo.com>
# Author: Julien Anguenot <ja@nuxeo.com>
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
""" Test the CPSUSerFolder API that relies on ther CPSDirectories
"""
import unittest
import os, sys
from Testing import ZopeTestCase

if __name__ == '__main__':
    execfile(os.path.join(sys.path[0], 'framework.py'))

from Products.CMFCore.utils import getToolByName

from Products.CPSUserFolder.TimeoutCache import resetAllCaches

import CPSUserFolderTestCase

portal_name = 'portal'

class CPSUserFolderTests(CPSUserFolderTestCase.CPSUserFolderTestCase):
    """ Test the CPSUSerFolder API that relies on the  CPSDirectories
    """

    def test_userFolderUsersAPI(self):

        # test UF users API

        resetAllCaches()

        self.login('manager')

        portal = self.getPortal()
        aclu = self.portal.acl_users
        dtool = getToolByName(portal, 'portal_directories')
        users_dir = dtool.members

        # Toto doesn't exist yet
        self.assertRaises(KeyError, users_dir.getEntry, 'toto')

        # Create a toto entry
        aclu.userFolderAddUser('toto', 'secret', ['Member',], [])

        # ask the aclu on the users_dir
        user_entry = users_dir.getEntry('toto')
        self.assertEqual(user_entry['id'], 'toto')
        self.assertEqual(user_entry['password'], 'secret')
        self.assertEqual(user_entry['roles'], ['Member'])

        # same by ask it from the aclu
        user = aclu.getUserById('toto')
        self.assertEqual(user.getProperty('id'), 'toto')
        self.assertEqual(user.getProperty('password'), 'secret')
        self.assertEqual(user.getProperty('roles'), ['Member'])

        # Change the user entry through UF
        aclu.userFolderEditUser('toto', 'secret2', ['Manager'], [])
        user_entry = users_dir.getEntry('toto')
        self.assertEqual(user_entry['id'], 'toto')
        self.assertEqual(user_entry['password'], 'secret2')
        self.assertEqual(user_entry['roles'], ['Manager'])

        # same by ask it from the aclu
        user = aclu.getUserById('toto')
        self.assertEqual(user.getProperty('id'), 'toto')
        self.assertEqual(user.getProperty('password'), 'secret2')
        self.assertEqual(user.getProperty('roles'), ['Manager'])

        # Delete the user entry though UF
        aclu.userFolderDelUsers(['toto'])
        self.assertRaises(KeyError, users_dir.getEntry, 'toto')
        self.assertRaises(KeyError, aclu.getUserById, 'toto')

        resetAllCaches()

    def test_userFolderGroupsAPI(self):

        # test UF groups API

        resetAllCaches()

        self.login('manager')

        portal = self.getPortal()
        aclu = self.portal.acl_users

        dtool = getToolByName(portal, 'portal_directories')
        users_dir = dtool.members
        groups_dir = dtool.groups

        # create a new group entry using the dir
        new_entry = {'group': 'nuxeo', 'members': ('julien',), 'subgroups': ()}
        groups_dir.createEntry(new_entry)

        # Check the availibility through the aclu
        group = aclu.getGroupById('nuxeo')
        self.assertEqual(group.getUsers(), ('julien',))

        # Try to get a non existing entry
        group = aclu.getGroupById('fake', None)
        self.assertEqual(group, None)

        resetAllCaches()
        
def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(CPSUserFolderTests))
    return suite
