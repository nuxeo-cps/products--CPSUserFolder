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

from zLOG import LOG, DEBUG, WARNING, ERROR, TRACE

from types import ListType
import base64

from Acquisition import aq_base, aq_parent, aq_inner
from Globals import InitializeClass
from Globals import DTMLFile

from AccessControl import ClassSecurityInfo
from AccessControl.User import BasicUser, BasicUserFolder
from AccessControl.Permissions import manage_users as ManageUsers
from AccessControl.PermissionRole import rolesForPermissionOn
from AccessControl.PermissionRole import _what_not_even_god_should_do

from Products.CMFCore.utils import getToolByName
from Products.CMFCore.utils import SimpleItemWithProperties
from Products.CMFCore.permissions import ManagePortal
from Products.CPSUtil.PropertiesPostProcessor import PropertiesPostProcessor

from Products.CPSDirectory.BaseDirectory import AuthenticationFailed

from Products.CPSUserFolder import TimeoutCache


_marker = []
CACHE_KEY = 'CPSUserFolder'


class CPSUserFolder(PropertiesPostProcessor, SimpleItemWithProperties,
                    BasicUserFolder):
    """CPS User Folder

    User folder whose configuration is based on directories.

    This user folder makes a difference between the login field, which
    is what is used by identification and authentication, and the id
    field, which is whatever id the user will have once it's logged in.

    However the 'username' and the 'id' are still identical.

    Several internal caches are used:
      login -> id
        there may be several of those when several logins exist
      id -> user_info = {'password', 'roles', 'groups', 'entry'}
        the password may be None if no password has yet been checked
    """
    meta_type = 'CPSUserFolder'
    id = 'acl_users'
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
        {'id': 'users_password_field', 'type': 'string', 'mode': 'w',
         'label': "Users directory: password field"},
        {'id': 'users_roles_field', 'type': 'string', 'mode': 'w',
         'label': "Users directory: roles field"},
        {'id': 'users_groups_field', 'type': 'string', 'mode': 'w',
         'label': "Users directory: groups field"},
        {'id': 'groups_dir', 'type': 'string', 'mode': 'w',
         'label': "Groups directory"},
        {'id': 'roles_dir', 'type': 'string', 'mode': 'w',
         'label': "Roles directory"},
        {'id': 'groups_members_field', 'type': 'string', 'mode': 'w',
         'label': "Groups directory: members field"},
        {'id': 'roles_members_field', 'type': 'string', 'mode': 'w',
         'label': "Roles directory: members field"},
        {'id': 'cache_timeout', 'type': 'int', 'mode': 'w',
         'label': "Cache timeout"},
        )
    users_dir = 'members'
    users_login_field = ''
    users_password_field = ''
    users_roles_field = 'roles'
    users_groups_field = 'groups'
    groups_dir = 'groups'
    roles_dir = 'roles'
    groups_members_field  = 'members'
    roles_members_field = 'members'
    cache_timeout = 300

    manage_options = (
        SimpleItemWithProperties.manage_options[:1] +
        ({'label': 'Cache', 'action':'manage_userCache'},) +
        SimpleItemWithProperties.manage_options[1:]
        )

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

    def _postProcessProperties(self):
        """Post-processing after properties change."""
        PropertiesPostProcessor._postProcessProperties(self)
        # XXX this will only change this instance's cache
        self._setCacheTimeout(self.cache_timeout)

    #
    # Caching
    #

    def _getCache(self, which):
        cache_key = (CACHE_KEY, self.getPhysicalPath(), which)
        return TimeoutCache.getCache(cache_key,
                                     constructor=self._makeNewCache)

    def _makeNewCache(self):
        return TimeoutCache.TimeoutCache(timeout=self.cache_timeout)

    def _setCacheTimeout(self, timeout):
        self._getCache('id').setTimeout(self.cache_timeout)
        self._getCache('login').setTimeout(self.cache_timeout)

    def _clearUserCache(self):
        """Clear the user cache."""
        self._getCache('id').clear()
        self._getCache('login').clear()

    def _removeUserIdFromCache(self, userid):
        """Remove a user id from the cache."""
        if userid is not None:
            self._removeUserFromIdCache(userid)
            self._removeUserIdFromLoginCache(userid)

    # user cache

    def _getUserFromIdCache(self, id):
        """Maybe get a user from the cache."""
        return self._getCache('id')[id]

    def _setUserToIdCache(self, id, user):
        """Cache a user."""
        self._getCache('id')[id] = user

    def _removeUserFromIdCache(self, id):
        """Remove a user from the cache."""
        del self._getCache('id')[id]

    def _getCacheKeysWithValidity(self):
        """Get cache keys with validity, for zmi page."""
        return self._getCache('id').keysWithValidity()

    # login cache

    def _getUserIdFromLoginCache(self, name):
        return self._getCache('login')[name]

    def _setUserIdToLoginCache(self, name, id):
        self._getCache('login')[name] = id

    def _removeUserIdFromLoginCache(self, id):
        self._getCache('login').delValues(id)

    #
    # Internal methods
    #

    security.declarePrivate('_getGroupsDirectory')
    def _getGroupsDirectory(self):
        """Get the underlying users directory."""
        dtool = getToolByName(self, 'portal_directories', None)
        if dtool is None:
            # User folder has been instanciated outside a CPS site.
            return None
        try:
            dir = getattr(dtool, self.groups_dir)
        except AttributeError:
            LOG('CPSUserFolder', WARNING,
                "Missing directory '%s'" % self.groups_dir)
            dir = None
        return dir

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

    security.declarePrivate('_buildUser')
    def _buildUser(self, id, user_info):
        """Build a user object from information."""
        user = CPSUser(id, **user_info)
        # The user folder is a persistent reference, it must not be cached,
        # so it's not part of the normal user_info.
        user._setUserFolder(self)
        return user

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

        dir = self._getUsersDirectory()
        if dir is None:
            return None
        dir_id_field = dir.id_field

        # Find on which field identification is done
        if use_login:
            auth_field = self.users_login_field
            if not auth_field:
                auth_field = dir_id_field
        else:
            auth_field = dir_id_field

        # Check cache for userid
        if auth_field == dir_id_field:
            userid = name
        else:
            userid = self._getUserIdFromLoginCache(name)
            if userid is not None:
                LOG('getUserWithAuthentication', TRACE,
                    "Getting info from cache name=%s -> userid=%s"
                    % (name, userid))

        # Check cache for user
        user_is_from_cache = False
        if userid is not None:
            user_info = self._getUserFromIdCache(userid)
            if user_info is not None:
                user_is_from_cache = True
                cache_pw = user_info['password']
                if password is None or password == cache_pw:
                    LOG('getUserWithAuthentication', TRACE,
                        "Returning user %s from cache" % userid)
                    # Build a new user object from cache info
                    user = self._buildUser(userid, user_info)
                    return user
                elif cache_pw is not None:
                    # Incorrect password, purge from cache
                    LOG('getUserWithAuthentication', DEBUG,
                        "Incorrect password for cached user %s" % userid)
                    self._removeUserIdFromCache(userid)
                    userid = None

        try:
            if password is not None and not dir.isAuthenticating():
                LOG('getUserWithAuthentication', ERROR,
                    "Directory %s is not authenticating" % dir.getId())
                return None
        except ValueError, e:
            LOG('getUserWithAuthentication', ERROR,
                "Got %s(%s) while calling isAuthenticating on %s" %
                (e.__class__.__name__, e, dir.getId()))
            return None

        # Get entry authenticated
        entry = None
        try:
            if userid is not None:
                if password is not None:
                    entry = dir.getEntryAuthenticated(userid, password)
                else:
                    entry = dir._getEntry(userid)
            else:
                if password is not None:
                    # We'll have to refetch the entry authenticated.
                    return_fields = None
                else:
                    # We can directly fetch the entry.
                    return_fields = ['*']
                res = dir._searchEntries(return_fields=return_fields,
                                        **{auth_field: [name]})
                if not res:
                    LOG('getUserWithAuthentication', TRACE,
                        "No result for %s=%s" % (auth_field, name))
                    # XXX do negative cache for login
                    return None
                if len(res) > 1:
                    LOG('getUserWithAuthentication', ERROR,
                        "Search on %s=%s returned several entries, "
                        "confusing authentication rejected"
                        % (auth_field, name))
                    return None
                if password is not None:
                    # Refetch the entry authenticated.
                    userid = res[0]
                    entry = dir.getEntryAuthenticated(userid, password)
                else:
                    # Use the entry that the search returned.
                    userid, entry = res[0]
        except AuthenticationFailed:
            LOG('getUserWithAuthentication', TRACE,
                "Authentication failed for user %s" % userid)
            entry = None
        except KeyError, e:
            LOG('getUserWithAuthentication', DEBUG,
                "KeyError (%s) for user %s" % (e, userid))
            entry = None
        except ValueError, e:
            LOG('getUserWithAuthentication', ERROR,
                "Got %s(%s) while authenticating %s" %
                (e.__class__.__name__, e, name))
            entry = None
        if entry is None:
            self._removeUserIdFromCache(userid)
            return None

        # Build user
        #id = entry[dir_id_field] # XXX
        try:
            roles = entry[self.users_roles_field]
        except KeyError:
            LOG('getUserWithAuthentication', DEBUG,
                'User %s has no field %s' % (userid, self.users_roles_field))
            roles = ()
        try:
            groups = entry[self.users_groups_field]
        except KeyError:
            LOG('getUserWithAuthentication', DEBUG,
                'User %s has no field %s' % (userid, self.users_groups_field))
            groups = ()
        if password is None:
            # XXX no raise if users_password_field has not be set
            if self.users_password_field != '':
                try:
                    password = entry[self.users_password_field]
                except KeyError:
                    LOG('getUserWithAuthentication', DEBUG,
                        'User %s has no field %s' %
                        (userid, self.users_password_field))
        user = self._buildUser(userid, {
            'password': password,
            'roles': roles,
            'groups': groups,
            'entry': entry,
            })
        user_info = user._getInitUserInfo()

        # Set to cache
        # (the cache keeps existing timeouts)
        if auth_field != dir_id_field:
            self._setUserIdToLoginCache(name, userid)
        self._setUserToIdCache(userid, user_info)
        LOG('getUserWithAuthentication', DEBUG,
            "Setting user %s into cache" % userid)

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
    def getUserById(self, id, default=None):
        """Return the user corresponding to the given id."""
        user = self.getUser(id)
        if user is None:
            return default
        return user

    security.declarePrivate('_doAddUser')
    def _doAddUser(self, name, password, roles, domains, groups=(), **kw):
        """Create a new user."""
        dir = self._getUsersDirectory()
        if dir is None:
            raise ValueError("The directory %s doesn't exist" % self.users_dir)
        entry = kw
        entry.update({
            dir.id_field: name,
            self.users_password_field: password,
            self.users_roles_field: tuple(roles),
            self.users_groups_field: tuple(groups),
            })
        dir.createEntry(entry)

    security.declarePrivate('_doChangeUser')
    def _doChangeUser(self, name, password, roles, domains, groups=None, **kw):
        """Modify an existing user."""
        dir = self._getUsersDirectory()
        if dir is None:
            raise ValueError("The directory %s doesn't exist" % self.users_dir)
        entry = kw
        entry.update({
            dir.id_field: name,
            self.users_password_field: password,
            self.users_roles_field: tuple(roles),
            })
        if groups is not None:
            entry[self.users_groups_field] = tuple(groups)
        dir.editEntry(entry)
        # Invalidate cache for name.
        self._removeUserFromIdCache(name)

    security.declarePrivate('_doDelUsers')
    def _doDelUsers(self, names):
        """Delete one or more users."""
        dir = self._getUsersDirectory()
        if dir is None:
            raise ValueError("The directory %s doesn't exist" % self.users_dir)
        for name in names:
            dir.deleteEntry(name)
            # Invalidate cache for name.
            self._removeUserFromIdCache(name)

    security.declareProtected(ManageUsers, 'userFolderAddUser')
    def userFolderAddUser(self, name, password, roles, domains, **kw):
        """Create a new user."""
        return self._doAddUser(name, password, roles, domains, **kw)

    security.declareProtected(ManageUsers, 'userFolderEditUser')
    def userFolderEditUser(self, name, password, roles, domains, **kw):
        """Modify an existing user."""
        return self._doChangeUser(name, password, roles, domains, **kw)

    security.declareProtected(ManageUsers, 'userFolderDelUsers')
    def userFolderDelUsers(self, names):
        """Delete one or more users."""
        return self._doDelUsers(names)

    security.declarePrivate('searchEntries')
    def searchEntries(self, return_fields=None, **kw):
        """Search for entries in the user directory.

        API is that of BaseDirectory.searchEntries.
        """
        dir = self._getUsersDirectory()
        if dir is None:
            return []
        return dir._searchEntries(return_fields=return_fields, **kw)

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
        dir = self._getGroupsDirectory()
        if dir is None:
            return []
        return dir.listEntryIds()

    security.declareProtected(ManageUsers, 'getGroupById')
    def getGroupById(self, groupname, default=_marker):
        """Return the given group"""
        groups_dir = self._getGroupsDirectory()
        if groups_dir is not None:
            if not groupname.startswith('role:'):
                if groups_dir.hasEntry(groupname):
                    group_entry = groups_dir.getEntry(groupname, default)
                    group_members = group_entry.get(self.groups_members_field,
                                                    ())
                    return Group(groupname, group_members)
            if default is not _marker:
                return default
        else:
            raise ValueError, "The directory %s doesn't exist" % self.groups_dir

    #
    # Private UserFolder object interface
    #

    def identify(self, auth):
        """Add certificate based authentication (cf SecureAuth)
        """
        if auth and auth.lower().startswith('clcert '):
            name = base64.decodestring(auth.split(' ')[-1])
            password = None
            return name, password
        else:
            return BasicUserFolder.identify(self, auth)


    def authenticate(self, name, password, request):
        """Authenticate a user from a name and password or a from
        certificate (Apache and SecureAuth required)

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
            if request._auth and request._auth.lower().startswith('clcert '):
                # A certificate as been validated by an apache frontend: no
                # password required
                return self.getUserWithAuthentication(name, None, use_login=0)
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
        """Test if local roles blocking is implemented in this user folder.

        0 means no
        1 means supports 'group:role:Anonymous' -> '-'
        2 means supports 'group:role:Anonymous' -> '-SomeRole'
        """
        return 2

    security.declarePrivate('mergedLocalRoles')
    def mergedLocalRoles(self, object, withgroups=0):
        """Get the merged local roles of an object.

        Returns a dictionnary, with users as keys and roles as values.

        When called with withgroups=1, the keys are of the form user:foo and
        group:bar.
        """
        merged = {}
        object = aq_inner(object)
        stop_loop = 0
        blocked = {'': None}
        isblocked = blocked.has_key
        # this '' blocked role is to avoid testing before doing r[0]
        while 1:
            if hasattr(object, '__ac_local_roles__'):
                dict = object.__ac_local_roles__ or {}
                if callable(dict):
                    dict = dict()
                for k, v in dict.items():
                    if withgroups:
                        k = 'user:'+k # groups
                    # Skip blocked roles
                    v = [r for r in v
                         if not isblocked(r) and r[0] != '-']
                    if merged.has_key(k):
                        merged[k] = merged[k] + v
                    elif v:
                        merged[k] = v
            # deal with groups
            if withgroups:
                if hasattr(object, '__ac_local_group_roles__'):
                    dict = object.__ac_local_group_roles__ or {}
                    if callable(dict):
                        dict = dict()
                    for k, vv in dict.items():
                        k = 'group:'+k
                        # Skip blocked roles
                        v = [r for r in vv
                             if not isblocked(r) and r[0] != '-']
                        if merged.has_key(k):
                            merged[k] = merged[k] + v
                        elif v:
                            merged[k] = v
                        # Blocking for all users
                        if k == 'group:role:Anonymous':
                            for r in vv:
                                if r and r[0] == '-':
                                    if r == '-':
                                        stop_loop = 1
                                        break
                                    else:
                                        blocked[r[1:]] = None
                    if stop_loop:
                        break
            # end groups
            if hasattr(object, 'aq_parent'):
                object = aq_inner(object.aq_parent)
                continue
            if hasattr(object, 'im_self'):
                object = aq_inner(object.im_self)
                continue
            break
        return merged

    security.declarePrivate('mergedLocalRolesWithPath')
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

    security.declarePrivate('getAllowedRolesAndUsersOfObject')
    def getAllowedRolesAndUsersOfObject(self, ob):
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

    # old spelling
    _allowedRolesAndUsers = getAllowedRolesAndUsersOfObject

    security.declarePrivate('getAllowedRolesAndUsersOfUser')
    def getAllowedRolesAndUsersOfUser(self, user):
        """Get the current roles and groups a user represents."""
        res = list(user.getRoles())
        res.append('user:' + user.getUserName())
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
            res.append('group:' + group)
        return res

    # old spelling
    _getAllowedRolesAndUsers = getAllowedRolesAndUsersOfUser

    #
    # ZMI
    #

    security.declareProtected(ManagePortal, 'manage_userCache')
    manage_userCache = DTMLFile('zmi/cache', globals())

    security.declareProtected(ManagePortal, 'manage_purgeUserCache')
    def manage_purgeUserCache(self, REQUEST):
        """Purge user cache."""
        self._clearUserCache()
        REQUEST.RESPONSE.redirect(self.absolute_url()+'/manage_userCache'
                                  '?manage_tabs_message=Cache+Purged.')

    security.declareProtected(ManagePortal, 'getCacheKeysWithValidity')
    def getCacheKeysWithValidity(self):
        """Get cache keys with validity."""
        return self._getCacheKeysWithValidity()

InitializeClass(CPSUserFolder)


def addCPSUserFolder(container, id=None, REQUEST=None, **kw):
    """Add a CPS User Folder called 'acl_users'"""
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

    def __init__(self, id, password=None, roles=(), groups=(), entry=None):
        self._id = id
        self._password = password
        roles = tuple(roles)
        if 'Anonymous' not in roles:
            roles += ('Anonymous',)
        if 'Authenticated' not in roles:
            roles += ('Authenticated',)
        self._roles = roles
        self._groups = tuple(groups)
        self._entry = entry

    def _getInitUserInfo(self):
        """Get the arguments needed to build a new user object."""
        roles = list(self._roles)
        roles.remove('Anonymous')
        roles.remove('Authenticated')
        roles = tuple(roles)
        return {
            'password': self._password,
            'roles': self._roles,
            'groups': self._groups,
            'entry': self._entry,
            }

    def _setUserFolder(self, aclu):
        """Set the persistent reference to the user folder."""
        self._aclu = aclu

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
        return self._password

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
        if isinstance(value, ListType):
            value = value[:]
        return value

    # CPS extension
    security.declarePublic('setProperties')
    def setProperties(self, **kw):
        """Set the value of properties for the user."""
        id = self._id
        aclu = self._aclu
        dir = aclu._getUsersDirectory()

        # Remove the user from the cache
        aclu._removeUserIdFromCache(id)

        # Set the properties
        kw[dir.id_field] = id
        dir.editEntry(kw)

        # Now update this object to make it correspond to the new user.
        user = aclu.getUserById(id)
        if user is None:
            raise KeyError(id)

        LOG('setProperties', DEBUG, 'old entry = %s' % self._entry)
        self._roles = user._roles
        self._groups = user._groups
        self._entry = user._entry
        LOG('setProperties', DEBUG, '    entry = %s' % user._entry)

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
                for r in local_roles.get(name, ()):
                    if r:
                        lrd[r] = None
            local_group_roles = getattr(object, '__ac_local_group_roles__', None)
            if local_group_roles:
                if callable(local_group_roles):
                    local_group_roles = local_group_roles() or {}
                for g in groups:
                    for r in local_group_roles.get(g, ()):
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

############################################################################

class Group:
    """Wrapper for group entry

    Minimum implementation to keep compatibility with old
    NuxUserGroups and LDAPUserGroupsFolder code
    """

    def __init__(self, id, users):
        self.id  = id
        self.users = users

    def __repr__(self):
        # I hope no code assumes that __repr__ is the groupname
        return "<Group %s>" % self.id
    
    def getUsers(self):
        return self.users

    def addUsers(self, userids):
        raise NotImplementedError

    def userHasRole(self, userid, roles):
        raise NotImplementedError

    def getMemberRoles(self, userid):
        raise NotImplementedError

    def setMemberRoles(self, userid, roles):
        raise NotImplementedError

############################################################################    
    
