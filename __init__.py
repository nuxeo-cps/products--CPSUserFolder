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

from AccessControl.Permissions import add_user_folders as AddUserFolders
from Products.CMFCore.CMFCorePermissions import ManagePortal


import CPSUserFolder
import CPSMemberDataTool

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
