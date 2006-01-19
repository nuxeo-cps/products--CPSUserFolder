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

import unittest
from Products.CPSUserFolder.CPSMemberDataTool import CPSMemberDataTool
from Products.CPSUserFolder.CPSMemberDataTool import CPSMemberData
from zope.interface.verify import verifyClass
from Products.CMFCore.interfaces import IMemberDataTool
from Products.CMFCore.interfaces import IMemberData

class TestCPSMemberDataTool(unittest.TestCase):
    def testInterfaces(self):
        verifyClass(IMemberDataTool, CPSMemberDataTool)

class TestCPSMemberData(unittest.TestCase):
    def testInterfaces(self):
        verifyClass(IMemberData, CPSMemberData)

def test_suite():
    return unittest.TestSuite((
        unittest.makeSuite(TestCPSMemberDataTool),
        unittest.makeSuite(TestCPSMemberData),
        ))

