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

import sys
from AccessControl.Permissions import add_user_folders as AddUserFolders
from Products.CMFCore.permissions import ManagePortal

from UserFolderWithGroups import UserFolderWithGroups as UFWG
from UserFolderWithGroups import addUserFolderWithGroups

#from Products.CPSUserFolder import FakeNuxUserGroups
#sys.modules['Products.NuxUserGroups'] = FakeNuxUserGroups


import CPSUserFolder
import CPSMemberDataTool
import PatchForGruf # XXX

from Products.CPSUtil.genericsetup import tool_steps
export_step, import_step = tool_steps('acl_users', logger_id='users')

def initialize(registrar):
    registrar.registerClass(
        CPSUserFolder.CPSUserFolder,
        permission=AddUserFolders,
        constructors=(CPSUserFolder.addCPSUserFolder,),
        icon='zmi/cpsuserfolder_icon.gif')
    registrar.registerClass(
        CPSMemberDataTool.CPSMemberDataTool,
        permission=ManagePortal,
        constructors=(CPSMemberDataTool.addCPSMemberDataTool,),
        icon='zmi/tool.gif')
    registrar.registerClass(
        UFWG,
        permission=AddUserFolders,
        constructors=(addUserFolderWithGroups,),
        icon='zmi/userfolder_icon.gif')
