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
"""CPS MemberData Tool

A memberdata tool designed to work in conjunction with CPS User Folder.
"""

from zLOG import LOG, DEBUG

from Acquisition import aq_base, aq_parent, aq_inner
from Globals import DTMLFile
from Globals import InitializeClass
from AccessControl import ClassSecurityInfo

from OFS.SimpleItem import SimpleItem
from Products.CMFCore.utils import getToolByName
from Products.CMFCore.utils import UniqueObject
from Products.CMFCore.CMFCorePermissions import SetOwnProperties
from Products.CMFCore.CMFCorePermissions import ManagePortal
from Products.CMFCore.ActionProviderBase import ActionProviderBase

from Products.CMFCore.interfaces.portal_memberdata import portal_memberdata as IMemberDataTool
from Products.CMFCore.interfaces.portal_memberdata import MemberData as IMemberData

from Products.CMFCore.MemberDataTool import MemberDataTool as BaseMemberDataTool


_marker = []


class CPSMemberDataTool(UniqueObject, SimpleItem, ActionProviderBase):
    """This tool wraps user objects, making them act as Member objects.
    """
    __implements__ = (IMemberDataTool, ActionProviderBase.__implements__)

    id = 'portal_memberdata'
    meta_type = 'CPS MemberData Tool'

    _actions = ()

    def __init__(self):
        pass

    security = ClassSecurityInfo()

    #
    # ZMI
    #

    manage_options = (
        ActionProviderBase.manage_options +
        ({'label': 'Overview', 'action': 'manage_overview'},) +
        SimpleItem.manage_options
        )

    security.declareProtected(ManagePortal, 'manage_overview')
    manage_overview = DTMLFile('zmi/explainMemberDataTool', globals())

    #
    #   'portal_memberdata' interface methods
    #

    security.declarePrivate('searchMemberDataContents')
    def searchMemberDataContents(self, search_param, search_term):
        """Search members.

        Delegates the search to the CPS User Folder.

        (Called by the membership tool.)
        """
        if search_param in ('username', 'id'):
            aclu = self.acl_users
            if not hasattr(aq_base(aclu), '_getUsersDirectory'):
                raise ValueError("User folder does not have a "
                                 "_getUsersDirectory")
            search_param = aclu._getUsersDirectory().id_field

        entries = self.searchForMembers(return_fields=['email'],
                                        **{search_param: search_term})

        res = [{'username': id, 'email': entry.get('email', '')}
               for id, entry in entries]

        return res

    # CPS-specific method
    security.declarePublic('searchForMembers')
    def searchForMembers(self, query={}, return_fields=None, **kw):
        """Search for members.

        Uses the CPSDirectory semantics of searchEntries.

        If return_fields is None, returns a list of ids:
          ['member1', 'member2']

        If return_fields is not None, it must be sequence of property ids. The
        method will return a list of tuples containing the member id and a
        dictionary of available properties:
          [('member1', {'email': 'foo', 'age': 75}), ('member2', {'age': 5})]

        return_fields=['*'] means to return all available properties.
        """
        # old name for return_fields
        if kw.has_key('props') and return_fields is None:
            return_fields = kw['props']
            del kw['props']

        kw.update(query)

        aclu = self.acl_users
        if not hasattr(aq_base(aclu), 'searchEntries'):
            raise ValueError("User folder does not have a searchEntries")

        return aclu.searchEntries(return_fields=return_fields, **kw)

    security.declarePrivate('wrapUser')
    def wrapUser(self, u):
        """Wrap a user to make it a member.

        (Called by the membership tool.)
        """
        m = CPSMemberData(u)
        # Return a wrapper with self as containment and
        # the user as context.
        return m.__of__(self).__of__(u)

InitializeClass(CPSMemberDataTool)


class CPSMemberData(SimpleItem):

    __implements__ = IMemberData

    security = ClassSecurityInfo()

    def __init__(self, u):
        self.user = u
        self.id = u.getId()

    security.declareProtected(SetOwnProperties, 'setProperties')
    def setProperties(self, properties=None, **kw):
        """Set the properties of the current authenticated member.

        This is a method of any member but actually sets the values
        on the authenticated member!

        Accepts a mapping or keyword arguments.
        """
        if properties is None:
            properties = kw
        mtool = getToolByName(self, 'portal_membership')
        if mtool.isAnonymousUser():
            raise ValueError("Not logged in")
        member = mtool.getAuthenticatedMember()
        member.setMemberProperties(properties)

    security.declarePrivate('setMemberProperties')
    def setMemberProperties(self, mapping):
        """Sets the properties of the member."""
        u = self.getUser()
        if not hasattr(aq_base(u), 'setProperties'):
            raise ValueError("User %s does not have a setProperties" %
                             self.getId())
        u.setProperties(**mapping)

    security.declarePublic('getProperty')
    def getProperty(self, key, default=_marker):
        u = self.getUser()
        if not hasattr(aq_base(u), 'getProperty'):
            raise ValueError("User %s does not have a getProperty" %
                             self.getId())
        if default is _marker:
            v = u.getProperty(key)
        else:
            v = u.getProperty(key, default)
        return v

    security.declarePrivate('setSecurityProfile')
    def setSecurityProfile(self, password=None, roles=None, domains=None):
        """Set the user's basic security profile"""
        raise NotImplementedError
        u = self.getUser()
        # This is really hackish.  The Zope User API needs methods
        # for performing these functions.
        if password is not None:
            u.__ = password
        if roles is not None:
            u.roles = roles
        if domains is not None:
            u.domains = domains

    security.declarePublic('getUser')
    def getUser(self):
        return aq_inner(self.user)

    security.declarePublic('getMemberId')
    def getMemberId(self):
        return self.id

    security.declarePrivate('getPassword')
    def getPassword(self):
        """Return the password of the user."""
        return self.getUser()._getPassword()

    def __str__(self):
        return self.id

    #
    # User object interface
    #

    security.declarePublic('getId')
    def getId(self):
        """Get the id of the user."""
        return self.id

    security.declarePublic('getUserName')
    def getUserName(self):
        """Get the username of the user"""
        return self.getUser().getUserName()

    security.declarePublic('getRoles')
    def getRoles(self):
        """Get the roles of the user."""
        return self.getUser().getRoles()

    security.declarePublic('getRolesInContext')
    def getRolesInContext(self, object):
        """Get the roles of the user in the context of the object."""
        return self.getUser().getRolesInContext(object)

    security.declarePublic('getDomains')
    def getDomains(self):
        """Get the domain restrictions of the user"""
        return self.getUser().getDomains()

    security.declarePublic('has_role')
    def has_role(self, roles, object=None):
        """Check if the user has a given role or roles."""
        return self.getUser().has_role(roles, object)

InitializeClass(CPSMemberData)


def addCPSMemberDataTool(container, id=None, REQUEST=None, **kw):
    """Add a CPS MemberData Tool."""
    container = container.this() # For FactoryDispatcher.
    t = CPSMemberDataTool()
    container._setObject(t.getId(), t)
    if REQUEST is not None:
        t = container._getOb(t.getId())
        REQUEST.RESPONSE.redirect(t.absolute_url()+'/manage_overview')

