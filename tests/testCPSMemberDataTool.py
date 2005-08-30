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
from Interface.Verify import verifyClass
from Products.CPSUserFolder.CPSMemberDataTool \
    import CPSMemberDataTool, CPSMemberData

class TestCPSMemberDataTool(unittest.TestCase):
    # FIXME: "The registerMemberData attribute was not provided."
    def XXXtestInterfaces(self):
        for interface in CPSMemberDataTool.__implements__:
            verifyClass(interface, CPSMemberDataTool)

class TestCPSMemberData(unittest.TestCase):
    def testInterfaces(self):
        for interface in (CPSMemberData.__implements__,):
            verifyClass(interface, CPSMemberData)


def test_suite():
    return unittest.TestSuite((
        unittest.makeSuite(TestCPSMemberDataTool),
        unittest.makeSuite(TestCPSMemberData),
        ))

