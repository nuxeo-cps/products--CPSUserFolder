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
"""
CPSUserFolder

A user folder based on CPSDirectory and CPSSchemas.
"""

from zLOG import LOG, DEBUG, WARNING, ERROR

from types import StringType, ListType
import base64

import Acquisition
from Acquisition import aq_base, aq_parent, aq_inner
from Globals import InitializeClass

from AccessControl import Unauthorized
from AccessControl import ClassSecurityInfo
from AccessControl.User import BasicUser, BasicUserFolder
from AccessControl.Permissions import manage_users as ManageUsers
from AccessControl.PermissionRole import rolesForPermissionOn
from AccessControl.PermissionRole import _what_not_even_god_should_do
from AccessControl.SecurityManagement import newSecurityManager
from AccessControl.SecurityManagement import noSecurityManager

from Products.CMFCore.utils import getToolByName
from Products.CMFCore.utils import SimpleItemWithProperties
from Products.CPSSchemas.PropertiesPostProcessor import PropertiesPostProcessor

from Products.CPSDirectory.BaseDirectory import AuthenticationFailed


_marker = []
cache_key = '_cps_user_folder_cache'


def _isinstance(ob, cls):
    try:
        return isinstance(ob, cls)
    except TypeError:
        # In python 2.1 isinstance() raises TypeError
        # instead of returning 0 for ExtensionClasses.
        return 0


class CPSUserFolder(PropertiesPostProcessor, SimpleItemWithProperties,
                    BasicUserFolder):
    """CPS User Folder

    User folder whose configuration is based on directories.

    This user folder makes a difference between the login field, which
    is what is used by identification and authentication, and the id
    field, which is whatever id the user will have once it's logged in.

    However the 'username' and the 'id' are still identical.
    """
    meta_type = 'CPSUserFolder'
    id ='acl_users'
    title = 'CPS User Folder'

    isPrincipiaFolderish = 1
    isAUserFolder = 1

    security = ClassSecurityInfo()

    _propertiesBaseClass = SimpleItemWithProperties
    _properties = SimpleItemWithProperties._properties + (
        {'id': 'users_dir', 'type': 'string', 'mode': 'w',
         'label': "Users directory"},
        {'id': 'users_login_field', 'type': 'string', 'mode': 'w',
         'label': "Users directory: login field"},
        {'id': 'users_roles_field', 'type': 'string', 'mode': 'w',
         'label': "Users directory: roles field"},
        {'id': 'users_groups_field', 'type': 'string', 'mode': 'w',
         'label': "Users directory: groups field"},
        )
    users_dir = 'members'
    users_login_field = ''
    users_roles_field = 'roles'
    users_groups_field = 'groups'

    manage_options = SimpleItemWithProperties.manage_options

    def __init__(self, **kw):
        self.manage_changeProperties(**kw)

    def _setId(self, id):
        if id != self.id:
            raise ValueError("Cannot change the id of a UserFolder")

    def __len__(self):
        return 1

    def manage_beforeDelete(self, item, container):
        if item is self:
            try:
                del container.__allow_groups__
            except:
                pass

    def manage_afterAdd(self, item, container):
        if item is self:
            container.__allow_groups__ = aq_base(self)

    #
    # Internal methods
    #

    security.declarePrivate('_getUsersDirectory')
    def _getUsersDirectory(self):
        """Get the underlying users directory."""
        dtool = getToolByName(self, 'portal_directories', None)
        if dtool is None:
            # User folder has been instanciated outside a CPS site.
            return None
        try:
            dir = getattr(dtool, self.users_dir)
        except AttributeError:
            LOG('CPSUserFolder', WARNING,
                "Missing directory '%s'" % self.users_dir)
            dir = None
        return dir

    def _getUserFromCache(self, name, password):
        """Maybe get a user from the cache.

        Returns the unwrapped user or None.
        """
        request = getattr(self, 'REQUEST', None)
        if request is None:
            return None
        cache = getattr(request, cache_key, None)
        if cache is None:
            return None
        return cache.get((name, password))

    def _setUserToCache(self, name, password, user):
        """Cache a user."""
        request = getattr(self, 'REQUEST', None)
        if request is None:
            return
        if not hasattr(request, cache_key):
            setattr(request, cache_key, {})
        cache = getattr(request, cache_key)
        cache[(name, password)] = user

    def _clearUserCache(self):
        """Clear the user cache."""
        # Not really needed as we cache in request.
        request = getattr(self, 'REQUEST', None)
        if request is None:
            return
        if hasattr(request, cache_key):
            delattr(request, cache_key)

    security.declarePrivate('_buildUser')
    def _buildUser(self, id, roles, groups, entry, dir):
        """Build a user object from information."""
        return CPSUser(id, roles, groups, entry, dir)

    #
    # Public UserFolder object interface
    #

    # CPS extension
    security.declarePrivate('getUserWithAuthentication')
    def getUserWithAuthentication(self, name, password, use_login=0):
        """Get a user by its id if it is authenticated.

        If password is None, don't check authentication.
        If use_login is true, name is the user's login instead of its id.
        Returns an unwrapped user object, or None.
        """
        if not name.strip():
            # Avoid passing an empty search to some backends.
            return None

        # Check cache
        user = self._getUserFromCache(name, password)
        if user is not None:
            return user

        dir = self._getUsersDirectory()
        if dir is None:
            return None
        if password is not None and not dir.isAuthenticating():
            LOG('getUserWithAuthentication', ERROR,
                "Directory %s is not authenticating" % dir.getId())
            return None

        # Find on which field identification is done
        if use_login:
            auth_field = self.users_login_field
            if not auth_field:
                auth_field = dir.id_field
        else:
            auth_field = dir.id_field

        # Get entry authenticated
        try:
            if auth_field == dir.id_field:
                if password is not None:
                    entry = dir.getEntryAuthenticated(name, password)
                else:
                    entry = dir._getEntry(name)
            else:
                if password is not None:
                    # We'll have to refetch the entry authenticated.
                    return_fields = None
                else:
                    # We can directly fetch the entry.
                    return_fields = ['*']
                res = dir.searchEntries(return_fields=return_fields,
                                        **{auth_field: [name]})
                if not res:
                    LOG('getUserWithAuthentication', DEBUG,
                        "No result for %s=%s" % (auth_field, name))
                    return None
                if len(res) > 1:
                    LOG('getUserWithAuthentication', ERROR,
                        "Search on %s=%s returned several entries, "
                        "confusing authentication rejected"
                        % (auth_field, name))
                    return None
                if password is not None:
                    id = res[0]
                    entry = dir.getEntryAuthenticated(id, password)
                else:
                    entry = res[0]
        except AuthenticationFailed:
            return None
        except KeyError:
            return None
        except ValueError, e:
            LOG('getUserWithAuthentication', ERROR,
                "Got %s(%s) while authenticating %s" %
                (e.__class__.__name__, e, name))
            return None

        id = entry[dir.id_field]
        roles = entry[self.users_roles_field]
        groups = entry[self.users_groups_field]
        user = self._buildUser(id, roles, groups, entry, dir)

        # Set to cache
        self._setUserToCache(name, password, user)
        return user

    security.declareProtected(ManageUsers, 'getUser')
    def getUser(self, name):
        """Get a user by its username (which is also the id).

        Returns an unwrapped user object, or None.
        """
        return self.getUserWithAuthentication(name, None)

    security.declareProtected(ManageUsers, 'getUserNames')
    def getUserNames(self):
        """Return a list of usernames"""
        # This is already quite costly to implement. Who needs this?
        dir = self._getUsersDirectory()
        if dir is None:
            return []
        return dir.listEntryIds()

    security.declareProtected(ManageUsers, 'user_names')
    def user_names(self):
        return self.getUserNames()

    security.declareProtected(ManageUsers, 'getUsers')
    def getUsers(self):
        """Return a list of user objects"""
        # This is very costly to implement. Who needs this?
        raise NotImplementedError

    security.declareProtected(ManageUsers, 'getUserById')
    def getUserById(self, id, default=_marker):
        """Return the user corresponding to the given id."""
        user = self.getUser(id)
        if user is not None:
            return user
        if default is not _marker:
            return default
        raise KeyError(id)

    security.declarePrivate('_doAddUser')
    def _doAddUser(self, name, password, roles, domains, **kw):
        """Create a new user. This should be implemented by subclasses to
           do the actual adding of a user. The 'password' will be the
           original input password, unencrypted. The implementation of this
           method is responsible for performing any needed encryption."""
        raise NotImplementedError

    security.declarePrivate('_doChangeUser')
    def _doChangeUser(self, name, password, roles, domains, **kw):
        """Modify an existing user. This should be implemented by subclasses
           to make the actual changes to a user. The 'password' will be the
           original input password, unencrypted. The implementation of this
           method is responsible for performing any needed encryption."""
        raise NotImplementedError

    security.declarePrivate('_doDelUsers')
    def _doDelUsers(self, names):
        """Delete one or more users. This should be implemented by subclasses
           to do the actual deleting of users."""
        raise NotImplementedError

    security.declareProtected(ManageUsers, 'userFolderAddUser')
    def userFolderAddUser(self, name, password, roles, domains, **kw):
        """API method for creating a new user object. Note that not all
           user folder implementations support dynamic creation of user
           objects."""
        if hasattr(self, '_doAddUser'):
            return self._doAddUser(name, password, roles, domains, **kw)
        raise NotImplementedError

    security.declareProtected(ManageUsers, 'userFolderEditUser')
    def userFolderEditUser(self, name, password, roles, domains, **kw):
        """API method for changing user object attributes. Note that not
           all user folder implementations support changing of user object
           attributes."""
        if hasattr(self, '_doChangeUser'):
            return self._doChangeUser(name, password, roles, domains, **kw)
        raise NotImplementedError

    security.declareProtected(ManageUsers, 'userFolderDelUsers')
    def userFolderDelUsers(self, names):
        """API method for deleting one or more user objects. Note that not
           all user folder implementations support deletion of user objects."""
        if hasattr(self, '_doDelUsers'):
            return self._doDelUsers(names)
        raise NotImplementedError

    # CPS Public extensions

    security.declareProtected(ManageUsers, 'userFolderAddGroup')
    def userFolderAddGroup(self, groupname, **kw):
        """Create a group"""
        raise NotImplementedError

    security.declareProtected(ManageUsers, 'userFolderDelGroups')
    def userFolderDelGroups(self, groupnames):
        """Delete groups"""
        raise NotImplementedError

    security.declareProtected(ManageUsers, 'getGroupNames')
    def getGroupNames(self):
        """Return a list of group names"""
        raise NotImplementedError

    security.declareProtected(ManageUsers, 'getGroupById')
    def getGroupById(self, groupname):
        """Return the given group"""
        raise NotImplementedError

    #
    # Private UserFolder object interface
    #

##     def identify(self, auth):
##         """Identify a user.

##         (Called by validate.)

##         From 'auth' which comes from the request, identify the user.

##         Returns its username and password, or (None, None).
##         """
##         if auth and auth.lower().startswith('basic '):
##             try:
##                 name, password = (base64.decodestring(auth.split(' ')[-1])
##                                   .split(':', 1))
##             except:
##                 raise 'BadRequest', 'Invalid authentication token'
##             return name, password
##         else:
##             return None, None

    def authenticate(self, name, password, request):
        """Authenticate a user from a name and password.

        (Called by validate).

        Returns the user object, or None.
        """
        if name is None:
            return None
        emergency = self._emergency_user
        if emergency and name == emergency.getUserName():
            user = emergency
            if user.authenticate(password, request):
                return user
            else:
                return None
        else:
            return self.getUserWithAuthentication(name, password, use_login=1)

    #def authorize(self, user, accessed, container, name, value, roles):
##         """ Check if a user is authorized to access an object.
##         Returns a boolean.
##         access, container, name, value, roles will be passed to the
##         security manager for validation.
##         """
##         # Only called by validate.

    #def validate(self, request, auth='', roles=_noroles):

    # CPS Private extensions

    security.declarePublic('hasLocalRolesBlocking')
    def hasLocalRolesBlocking(self):
        """Test if local roles blocking is implemented in this user folder."""
        return 1

    def mergedLocalRoles(self, object, withgroups=0):
        """Get the merged local roles of an object.

        Returns a dictionnary.

        When called with withgroups=1, the keys are of the form user:foo and
        group:bar.
        """
        merged = {}
        object = aq_inner(object)
        while 1:
            if hasattr(object, '__ac_local_roles__'):
                dict = object.__ac_local_roles__ or {}
                if callable(dict):
                    dict = dict()
                for k, v in dict.items():
                    if withgroups:
                        k = 'user:'+k # groups
                    if merged.has_key(k):
                        merged[k] = merged[k] + v
                    else:
                        merged[k] = v
            # deal with groups
            if withgroups:
                if hasattr(object, '__ac_local_group_roles__'):
                    dict = object.__ac_local_group_roles__ or {}
                    if callable(dict):
                        dict = dict()
                    for k, v in dict.items():
                        k = 'group:'+k
                        if merged.has_key(k):
                            merged[k] = merged[k] + v
                        else:
                            merged[k] = v
            # end groups
            if hasattr(object, 'aq_parent'):
                object = aq_inner(object.aq_parent)
                continue
            if hasattr(object, 'im_self'):
                object = aq_inner(object.im_self)
                continue
            break
        return merged

    def mergedLocalRolesWithPath(self, object, withgroups=0):
        """Get the merged local roles of an object.

        Returns a dictionnary.

        When called with withgroups=1, the keys are of the form user:foo and
        group:bar.

        The path corresponding to the object where the role takes place
        is added with the role in the result. In this case of the form:
        {'user:foo': [{'url':url, 'roles':[Role0, Role1]},
                      {'url':url, 'roles':[Role1]}],..}.
        """
        utool = getToolByName(object, 'portal_url')
        merged = {}
        object = aq_inner(object)
        while 1:
            if hasattr(object, '__ac_local_roles__'):
                dict = object.__ac_local_roles__ or {}
                if callable(dict):
                    dict = dict()
                obj_url = utool.getRelativeUrl(object)
                for k, v in dict.items():
                    if withgroups:
                        k = 'user:'+k # groups
                    if merged.has_key(k):
                        merged[k].append({'url':obj_url,'roles':v})
                    else:
                        merged[k] = [{'url':obj_url,'roles':v}]
            # deal with groups
            if withgroups:
                if hasattr(object, '__ac_local_group_roles__'):
                    dict = object.__ac_local_group_roles__ or {}
                    if callable(dict):
                        dict = dict()
                    obj_url = utool.getRelativeUrl(object)
                    for k, v in dict.items():
                        k = 'group:'+k
                        if merged.has_key(k):
                            merged[k].append({'url':obj_url,'roles':v})
                        else:
                            merged[k] = [{'url':obj_url,'roles':v}]
            # end groups
            if hasattr(object, 'aq_parent'):
                object = aq_inner(object.aq_parent)
                continue
            if hasattr(object, 'im_self'):
                object = aq_inner(object.im_self)
                continue
            break
        return merged

    def _allowedRolesAndUsers(self, ob):
        """
        Return a list of roles, users and groups with View permission.
        Used by PortalCatalog to filter out items you're not allowed to see.
        """
        allowed = {}
        for r in rolesForPermissionOn('View', ob):
            allowed[r] = 1
        localroles = self.mergedLocalRoles(ob, withgroups=1) # groups
        for user_or_group, roles in localroles.items():
            for role in roles:
                if allowed.has_key(role):
                    allowed[user_or_group] = 1
        if allowed.has_key('Owner'):
            del allowed['Owner']
        return list(allowed.keys())

    def _getAllowedRolesAndUsers(self, user):
        """Get the current roles and groups a user represents."""
        res = list(user.getRoles())
        res.append('user:%s' % user.getUserName())
        if hasattr(aq_base(user), 'getComputedGroups'):
            groups = user.getComputedGroups()
        elif hasattr(aq_base(user), 'getGroups'):
            LOG('_getAllowedRolesAndUsers', DEBUG, 'no computed groups but groups for %s (%s)' % (`user`, user.aq_parent))
            groups = user.getGroups() + ('role:Anonymous',)
            if 'Authenticated' in res:
                groups = groups + ('role:Authenticated',)
        else:
            LOG('_getAllowedRolesAndUsers', DEBUG, 'no groups for %s' % `user`)
            groups = ('role:Anonymous',)
        for group in groups:
            res.append('group:%s' % group)
        return res

InitializeClass(CPSUserFolder)


def addCPSUserFolder(container, id=None, REQUEST=None, **kw):
    """Add a CPS User Folder"""
    container = container.this() # For FactoryDispatcher.
    f = CPSUserFolder(**kw)
    container._setObject('acl_users', f)
    container.__allow_groups__ = f
    if REQUEST is not None:
        f = container.acl_users
        REQUEST.RESPONSE.redirect(f.absolute_url()+'/manage_propertiesForm')


#
# User
#

class CPSUser(BasicUser):
    """User object."""

    security = ClassSecurityInfo()
    security.declareObjectPublic()

    def __init__(self, id, roles, groups, entry, dir):
        self._id = id
        self._roles = tuple(roles) + ('Anonymous', 'Authenticated')
        self._groups = tuple(groups)
        self._entry = entry
        self._dir = dir

    #
    # Basic API
    #

    security.declarePublic('getId')
    def getId(self):
        """Get the id of this user."""
        return self._id

    security.declarePublic('getUserName')
    def getUserName(self):
        """Get the username (same as the id) associated with this user."""
        return self._id

    security.declarePrivate('_getPassword')
    def _getPassword(self):
        """Get the password of the user."""
        raise NotImplementedError

    security.declarePublic('getRoles')
    def getRoles(self):
        """Get the user's roles."""
        return self._roles

    security.declarePublic('getDomains')
    def getDomains(self):
        """Get the user's domains (always empty)."""
        return []

    security.declarePublic('getGroups')
    def getGroups(self):
        """Get the user's groups."""
        return self._groups

    # CPS extension
    security.declarePublic('getComputedGroups')
    def getComputedGroups(self):
        """Get all the user's groups.

        This includes groups of groups, and special groups
        like role:Anonymous and role:Authenticated.

        Groups of groups are not implemented yet.
        """
        return self.getGroups() + ('role:Anonymous', 'role:Authenticated')
        #raise NotImplementedError

    # CPS extension
    security.declarePublic('getProperty')
    def getProperty(self, key, default=_marker):
        """Get the value of a property of the user."""
        if not self._entry.has_key(key):
            if default is not _marker:
                return default
            raise KeyError(key)
        value = self._entry[key]
        if _isinstance(value, ListType):
            value = value[:]
        return value

    #
    # Internal API
    #

    security.declarePublic('getRolesInContext')
    def getRolesInContext(self, object):
        """Get the list of roles assigned to the user.

        This includes local roles assigned in the context of
        the passed in object.

        Knows about local roles blocking (roles starting with '-').
        """
        name = self.getUserName()
        roles = self.getRoles()
        # deal with groups
        groups = self.getComputedGroups()
        # end groups
        local = {}
        stop_loop = 0
        object = aq_inner(object)
        while 1:
            # Collect all roles info
            lrd = {}
            local_roles = getattr(object, '__ac_local_roles__', None)
            if local_roles:
                if callable(local_roles):
                    local_roles = local_roles() or {}
                for r in local_roles.get(name, []):
                    if r:
                        lrd[r] = None
            local_group_roles = getattr(object, '__ac_local_group_roles__', None)
            if local_group_roles:
                if callable(local_group_roles):
                    local_group_roles = local_group_roles() or {}
                for g in groups:
                    for r in local_group_roles.get(g, []):
                        if r:
                            lrd[r] = None
            lr = lrd.keys()
            # Positive role assertions
            for r in lr:
                if r[0] != '-':
                    if not local.has_key(r):
                        local[r] = 1 # acquired role
            # Negative (blocking) role assertions
            for r in lr:
                if r[0] == '-':
                    r = r[1:]
                    if not r:
                        # role '-' blocks all acquisition
                        stop_loop = 1
                        break
                    if not local.has_key(r):
                        local[r] = 0 # blocked role
            if stop_loop:
                break
            if hasattr(object, 'aq_parent'):
                object = aq_inner(object.aq_parent)
                continue
            if hasattr(object, 'im_self'):
                object = aq_inner(object.im_self)
                continue
            break
        roles = list(roles)
        for r, v in local.items():
            if v: # only if not blocked
                roles.append(r)
        return roles

    security.declarePublic('allowed')
    def allowed(self, object, object_roles=None):
        """Check whether the user has access to object.

        The user must have one of the roles in object_roles to allow access.
        """
        if object_roles is _what_not_even_god_should_do:
            return 0

        # Short-circuit the common case of anonymous access.
        if object_roles is None or 'Anonymous' in object_roles:
            return 1

        # Provide short-cut access if object is protected by 'Authenticated'
        # role and user is not nobody
        # Users from this folder can never be nobody.
        if 'Authenticated' in object_roles:
            return 1

        # Check for a role match with the normal roles given to
        # the user, then with local roles only if necessary. We
        # want to avoid as much overhead as possible.
        user_roles = self.getRoles()
        for role in object_roles:
            if role in user_roles:
                if self._check_context(object):
                    return 1
                return None

        # Check local roles, calling getRolesInContext to avoid too much
        # complexity, at the expense of speed.
        for role in self.getRolesInContext(object):
            if role in object_roles:
                return 1

        return None

    security.declarePrivate('authenticate')
    def authenticate(self, password, request=None):
        """Check that a user's password is correct."""
        # This method should be unused.
        raise NotImplementedError

    security.declarePublic('has_role')
    #def has_role(self, roles, object=None):

    security.declarePublic('has_permission')
    #def has_permission(self, permission, object):

    def __repr__(self):
        # I hope no code assumes that __repr__ is the username
        return "<CPSUser %s>" % self.getId()

InitializeClass(CPSUser)
