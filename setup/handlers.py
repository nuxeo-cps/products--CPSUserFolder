# Copyright (c) 2005 Nuxeo SAS <http://nuxeo.com>
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
# $Id:$
"""User folder import/export for CMFSetup.
"""

import os
from Globals import package_home
from Globals import InitializeClass
from Acquisition import aq_base
from AccessControl import ClassSecurityInfo
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.CMFCore.permissions import ManagePortal
from Products.CMFCore.utils import getToolByName

from Products.CMFSetup.utils import ExportConfiguratorBase
from Products.CMFSetup.utils import ImportConfiguratorBase
from Products.CMFSetup.utils import DEFAULT, KEY

_pkgdir = package_home(globals())
_xmldir = os.path.join(_pkgdir, 'xml')


_FILENAME = 'userfolder.xml'


def exportUserFolder(context):
    """Export user folder configuration.

    Does not export the users themselves.
    """
    site = context.getSite()
    aclu = getToolByName(site, 'acl_users')

    ufconf = PropertiesUserFolderExportConfigurator(site).__of__(site)
    # XXX deal with LDAPUserFolder
    ufconf.setObject(aclu)
    uf_xml = ufconf.generateXML()
    context.writeDataFile(_FILENAME, uf_xml, 'text/xml')

    return "User Folder configuration exported."


def importUserFolder(context):
    """Import user folder configuration.
    """
    site = context.getSite()
    encoding = context.getEncoding()

    if context.shouldPurge():
        pass

    uf_text = context.readDataFile(_FILENAME)
    if uf_text is None:
        return "User Folder: nothing to import."

    ufconf = PropertiesUserFolderImportConfigurator(site, encoding)
    info = ufconf.parseXML(uf_text)
    ufconf.create(site, info)

    return "User Folder imported."

ORIGINAL_USERFOLDER_API = [
    'User Folder',
    'User Folder With Groups',
    ]

class PropertiesUserFolderExportConfigurator(ExportConfiguratorBase):
    """Export a CPS User Folder configuration.
    """
    security = ClassSecurityInfo()

    def _getExportTemplate(self):
        return PageTemplateFile('propsUserFolderExport.xml', _xmldir)

    def setObject(self, object):
        self.object = object

    security.declareProtected(ManagePortal, 'getType')
    def getType(self):
        """Get the vocabulary type."""
        return self.object.meta_type

    def reindent(self, s, indent='  '):
        lines = s.splitlines()
        lines = [l for l in lines if l.strip()]
        if lines:
            # Take indentation of first line from including template
            lines[0] = lines[0].strip()
        return ('\n'+indent).join(lines)

    security.declareProtected(ManagePortal, 'getPropertiesXML')
    def getPropertiesXML(self):
        """Return info about the properties."""
        object = self.object
        if object.meta_type in ORIGINAL_USERFOLDER_API:
            prop_infos = [{
                'id': 'encrypt_passwords',
                'value': bool(object.encrypt_passwords),
                'elements': (),
                'type': None,
                'select_variable': None,
                }, {
                'id': 'maxlistusers',
                'value': object.maxlistusers,
                'elements': (),
                'type': None,
                'select_variable': None,
                }]
        else:
            prop_infos = [self._extractProperty(object, prop_map)
                          for prop_map in object._propertyMap()]
        propsXML = self.generatePropertyNodes(prop_infos)
        propsXML = self.reindent(propsXML, '')
        return propsXML

InitializeClass(PropertiesUserFolderExportConfigurator)


class PropertiesUserFolderImportConfigurator(ImportConfiguratorBase):
    """User Folder import configurator.

    The import mapping has to be able to read all user folders
    possible, otherwise we'd have to sniff the type before parsing.
    """
    def _getImportMapping(self):
        return {
            'user-folder': {
                'type': {},
                'property': {KEY: 'properties', DEFAULT: ()},
                },
            }

    # XXX Should be a proper registry
    _products = {
        'User Folder': ('OFSP', 'manage_addUserFolder'),
        'User Folder With Groups': ('CPSUserFolder',
                                    'addUserFolderWithGroups'),
        'CPS User Folder': ('CPSUserFolder', 'addCPSUserFolder'),
        }

    def create(self, portal, info):
        type = info['type']
        if getattr(aq_base(portal), 'acl_users', None) is None:
            # Create it if nothing is there
            if type not in self._products:
                raise ValueError("Unsupported user folder type: %s" % type)
            product, name = self._products[type]
            factory = getattr(portal.manage_addProduct[product], name)
            factory()
        aclu = getToolByName(portal, 'acl_users')
        if aclu.meta_type != type:
            # Won't overwrite config for another type
            raise ValueError("Cannot install %r, a %r already exists" %
                             (type, aclu.meta_type))
        # Properties
        if type in ORIGINAL_USERFOLDER_API:
            kw = {}
            for prop_info in info['properties']:
                id = prop_info['id']
                value = prop_info['value']
                if id == 'encrypt_passwords':
                    value = value in ('1', 'True')
                kw[id] = value
            if kw:
                aclu.manage_setUserFolderProperties(**kw)
        else:
            for prop_info in info['properties']:
                self.initProperty(aclu, prop_info)
            if getattr(aq_base(aclu), '_postProcessProperties', None) is not None:
                aclu._postProcessProperties()
