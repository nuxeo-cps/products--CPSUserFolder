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

import os, sys
if __name__ == '__main__':
    execfile(os.path.join(sys.path[0], 'framework.py'))

from unittest import TestSuite, makeSuite
from Testing import ZopeTestCase
from CPSUserFolderTestCase import CPSUserFolderTestCase

ZopeTestCase.installProduct('CPSSchemas')
ZopeTestCase.installProduct('CPSDirectory')
ZopeTestCase.installProduct('CPSUserFolder')

from Interface import Interface
from Interface.Verify import verifyObject, verifyClass

#from AccessControl.IUserFolder import IStandardUserFolder
    

# TODO: fix AccessControl.IUserFolder instead
class IStandardUserFolder(Interface):
    def getUser(name): pass
    def getUsers(): pass
    def getUserNames(): pass

class TestCPSUserFolder(CPSUserFolderTestCase):
    def testInterface(self):
        from Products.CPSUserFolder.CPSUserFolder import CPSUserFolder

        # TODO: remove 'tentative=1' after putting __implements__ in
        # CPSUserFolder class
        verifyClass(IStandardUserFolder, CPSUserFolder, tentative=1)


def test_suite():
    suite = TestSuite()
    suite.addTest(makeSuite(TestCPSUserFolder))
    return suite
