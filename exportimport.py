# (C) Copyright 2005 Nuxeo SAS <http://nuxeo.com>
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
"""User Folder XML Adapter.
"""

from Acquisition import aq_base
from zope.app import zapi
from zope.component import adapts
from zope.interface import implements
import Products
from Products.CMFCore.utils import getToolByName
from Products.GenericSetup.utils import exportObjects
from Products.GenericSetup.utils import importObjects
from Products.GenericSetup.utils import XMLAdapterBase
from Products.GenericSetup.utils import ObjectManagerHelpers
from Products.GenericSetup.utils import PropertyManagerHelpers
from Products.CPSUtil.PropertiesPostProcessor import (
    PostProcessingPropertyManagerHelpers)

from Products.GenericSetup.interfaces import INode
from Products.GenericSetup.interfaces import IBody
from Products.GenericSetup.interfaces import ISetupEnviron

from AccessControl.interfaces import IStandardUserFolder
from Products.CPSUserFolder.interfaces import IUserFolderWithGroups
from Products.CPSUserFolder.interfaces import ICPSUserFolder


_marker = object()

TOOL = 'acl_users'
NAME = 'users'

def exportUserFolder(context):
    """Export user folder configuration as a set of XML files.

    Does not export the users themselves.
    """
    site = context.getSite()
    if getattr(aq_base(site), TOOL, None) is None:
        logger = context.getLogger(NAME)
        logger.info("Nothing to export.")
        return
    tool = getToolByName(site, TOOL)
    exportObjects(tool, '', context)

def importUserFolder(context):
    """Import user folder configuration from XML files.
    """
    site = context.getSite()
    if getattr(aq_base(site), TOOL, None) is None:
        logger = context.getLogger(NAME)
        logger.info("Cannot import into missing acl_users.")
        return
    tool = getToolByName(site, TOOL)
    importObjects(tool, '', context)


class StandardUserFolderXMLAdapter(XMLAdapterBase, ObjectManagerHelpers):
    """XML importer and exporter for Standard User Folder.
    """

    adapts(IStandardUserFolder, ISetupEnviron)
    implements(IBody)

    _LOGGER_ID = NAME
    name = NAME

    def _exportNode(self):
        """Export the object as a DOM node.
        """
        node = self._getObjectNode('object')
        node.appendChild(self._extractUFProperties())
        self._logger.info("User folder exported.")
        return node

    def _importNode(self, node):
        """Import the object from the DOM node.
        """
        meta_type = str(node.getAttribute('meta_type'))
        if meta_type != self.context.meta_type:
            self._logger.error("Cannot import %r into %r." %
                               (meta_type, self.context.meta_type))
            return
        if self.environ.shouldPurge():
            self._purgeUFProperties()
        self._initUFProperties(node)
        self._logger.info("User folder imported.")

    node = property(_exportNode, _importNode)

    def _extractUFProperties(self):
        aclu = self.context
        fragment = self._doc.createDocumentFragment()

        child = self._doc.createElement('property')
        child.setAttribute('name', 'encrypt_passwords')
        text = self._doc.createTextNode(str(bool(aclu.encrypt_passwords)))
        child.appendChild(text)
        fragment.appendChild(child)

        child = self._doc.createElement('property')
        child.setAttribute('name', 'maxlistusers')
        text = self._doc.createTextNode(str(aclu.maxlistusers))
        child.appendChild(text)
        fragment.appendChild(child)

        return fragment

    def _purgeUFProperties(self):
        return

    def _initUFProperties(self, node):
        aclu = self.context
        for child in node.childNodes:
            if child.nodeName != 'property':
                continue
            name = child.getAttribute('name')
            value = self._getNodeText(child)
            if name == 'encrypt_passwords':
                aclu.encrypt_passwords = self._convertToBoolean(value)
            elif name == 'maxlistusers':
                aclu.maxlistusers = int(value)


class UserFolderWithGroupsXMLAdapter(StandardUserFolderXMLAdapter):
    """XML importer and exporter for User Folder With Groups.
    """
    adapts(IUserFolderWithGroups, ISetupEnviron)
    implements(IBody)


class CPSUserFolderXMLAdapter(XMLAdapterBase, ObjectManagerHelpers,
                              PostProcessingPropertyManagerHelpers):
    """XML importer and exporter for CPS User Folder.
    """

    adapts(ICPSUserFolder, ISetupEnviron)
    implements(IBody)

    _LOGGER_ID = NAME
    name = NAME

    def _exportNode(self):
        """Export the object as a DOM node.
        """
        node = self._getObjectNode('object')
        node.appendChild(self._extractProperties())
        return node

    def _importNode(self, node):
        """Import the object from the DOM node.
        """
        meta_type = str(node.getAttribute('meta_type'))
        if meta_type and meta_type != self.context.meta_type:
            self._logger.error("Cannot import %r into %r." %
                               (meta_type, self.context.meta_type))
            return
        if self.environ.shouldPurge():
            self._purgeProperties()
        self._initProperties(node)

    node = property(_exportNode, _importNode)
