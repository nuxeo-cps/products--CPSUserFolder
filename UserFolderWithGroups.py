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
User with Groups, and User Folder with Groups

(Used to be in NuxUserGroups.)

Also, patch to add it back to a virtual NuxUserGroups product
to preserve backward compatibility.
"""

from zLOG import LOG, DEBUG, ERROR

from Globals import InitializeClass
from Globals import DTMLFile
from Globals import Persistent
from Globals import PersistentMapping
from AccessControl import ClassSecurityInfo
from ExtensionClass import Base
from Acquisition import Implicit
from Acquisition import aq_base, aq_parent, aq_inner

from AccessControl.Role import RoleManager
from AccessControl.User import BasicUser
from AccessControl.User import UserFolder
from AccessControl.User import reqattr
from AccessControl.Permissions import manage_users as ManageUsers
from AccessControl.Permissions import change_permissions as ChangePermissions
from AccessControl.PermissionRole import _what_not_even_god_should_do
from AccessControl.PermissionRole import rolesForPermissionOn
from Products.CMFCore.utils import getToolByName


_marker = []

#
# Patch RoleManager to have groups
#

class PatchRoleManager:
    security = ClassSecurityInfo()

    __ac_local_group_roles__ = None

    security.declareProtected(ChangePermissions, 'manage_access')
    manage_access = DTMLFile('zmi/ufwg_access', globals())

    security.declareProtected(ChangePermissions, 'manage_permissions')
    manage_permissions = DTMLFile('zmi/ufwg_permissions', globals())

    security.declareProtected(ChangePermissions, 'manage_listLocalRoles')
    manage_listLocalRoles = DTMLFile('zmi/ufwg_listLocalRoles',
                                     globals(),
                                     management_view='Security',
                                     help_topic='Security_Local-Roles.stx',
                                     help_product='OFSP')

    security.declareProtected(ChangePermissions, 'manage_editLocalGroupRoles')
    manage_editLocalGroupRoles = DTMLFile('zmi/ufwg_editLocalGroupRoles',
                                          globals(),
                                          management_view='Security')

    security.declareProtected(ChangePermissions, 'manage_addLocalGroupRoles')
    def manage_addLocalGroupRoles(self, groupid, roles=[], REQUEST=None):
        """Add local group roles to a user."""
        if not roles:
            raise ValueError, 'One or more roles must be given!'
        dict = self.__ac_local_group_roles__ or {}
        local_group_roles = list(dict.get(groupid, []))
        for r in roles:
            if r not in local_group_roles:
                local_group_roles.append(r)
        dict[groupid] = local_group_roles
        self.__ac_local_group_roles__ = dict
        if REQUEST is not None:
            stat = 'Your changes have been saved.'
            return self.manage_listLocalRoles(self, REQUEST, stat=stat)

    security.declareProtected(ChangePermissions, 'manage_setLocalGroupRoles')
    def manage_setLocalGroupRoles(self, groupid, roles=[], REQUEST=None):
        """Set local group roles for a user."""
        if not roles:
            raise ValueError, 'One or more roles must be given!'
        dict = self.__ac_local_group_roles__ or {}
        dict[groupid] = roles
        self.__ac_local_group_roles__ = dict
        if REQUEST is not None:
            stat = 'Your changes have been saved.'
            return self.manage_listLocalRoles(self, REQUEST, stat=stat)

    security.declareProtected(ChangePermissions, 'manage_delLocalGroupRoles')
    def manage_delLocalGroupRoles(self, groupids, REQUEST=None):
        """Remove all local group roles for a user."""
        dict = self.__ac_local_group_roles__ or {}
        for groupid in groupids:
            if dict.has_key(groupid):
                del dict[groupid]
        self.__ac_local_group_roles__ = dict
        if REQUEST is not None:
            stat = 'Your changes have been saved.'
            return self.manage_listLocalRoles(self, REQUEST, stat=stat)

    # used by listLocalRoles
    security.declareProtected(ChangePermissions, 'has_local_group_roles')
    def has_local_group_roles(self):
        dict = self.__ac_local_group_roles__ or {}
        return len(dict)

    # used by listLocalRoles
    security.declareProtected(ChangePermissions, 'get_local_group_roles')
    def get_local_group_roles(self):
        dict = self.__ac_local_group_roles__ or {}
        keys = dict.keys()
        keys.sort()
        info = []
        for key in keys:
            value = tuple(dict[key])
            info.append((key, value))
        return tuple(info)

    # used by listLocalRoles
    security.declareProtected(ChangePermissions, 'get_valid_groupids')
    def get_valid_groupids(self):
        item = self
        dict = {'role:Anonymous': None, 'role:Authenticated': None}
        while 1:
            if hasattr(aq_base(item), 'acl_users') and \
               hasattr(item.acl_users, 'getGroupNames'):
                for name in item.acl_users.getGroupNames():
                    dict[name] = None
            if not hasattr(item, 'aq_parent'):
                break
            item = item.aq_parent
        keys = dict.keys()
        keys.sort()
        return tuple(keys)

    # used by editLocalGroupRoles
    security.declareProtected(ChangePermissions, 'get_local_roles_for_groupid')
    def get_local_roles_for_groupid(self, groupid):
        dict = self.__ac_local_group_roles__ or {}
        return tuple(dict.get(groupid, []))

InitializeClass(PatchRoleManager)

# Add all PatchRoleManager methods to RoleManager class
for attr, val in PatchRoleManager.__dict__.items():
    if not attr.startswith('__') or attr == '__ac_local_group_roles__':
        setattr(RoleManager, attr, val)


#
# Patch BasicUser to have groups
#

class PatchBasicUser:
    security = ClassSecurityInfo()

    security.declarePublic('getGroups')
    def getGroups(self):
        """Returns the groups of the user"""
        groups = getattr(aq_base(self), '_usergroups', ())
        return tuple(groups)

    security.declarePrivate('_setGroups')
    def _setGroups(self, groupnames):
        self._usergroups = list(groupnames)

    security.declarePrivate('_addGroups')
    def _addGroups(self, groupnames):
        groups = getattr(aq_base(self), '_usergroups', [])
        groups.extend(groupnames)
        self._usergroups = groups

    security.declarePrivate('_delGroups')
    def _delGroups(self, groupnames):
        groups = getattr(aq_base(self), '_usergroups', [])
        for groupname in groupnames:
            groups.remove(groupname)
        self._usergroups = groups

    security.declarePublic('getRolesInContext')
    def getRolesInContext(self, object):
        """Return the list of roles assigned to the user,
           including local roles assigned in context of
           the passed in object."""
        name = self.getUserName()
        roles = self.getRoles()
        groups = self.getGroups() + ('role:Anonymous',)
        if 'Authenticated' in roles:
            groups = groups + ('role:Authenticated',)
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
            inner = getattr(object, 'aq_inner', object)
            parent = getattr(inner, 'aq_parent', None)
            if parent is not None:
                object = parent
                continue
            if hasattr(object, 'im_self'):
                object = object.im_self
                object = getattr(object, 'aq_inner', object)
                continue
            break
        roles = list(roles)
        for r, v in local.items():
            if v: # only if not blocked
                roles.append(r)
        return roles

    security.declarePublic('getRolesInContext')
    def allowed(self, object, object_roles=None):
        """Check whether the user has access to object. The user must
           have one of the roles in object_roles to allow access."""

        if object_roles is _what_not_even_god_should_do:
            return 0

        # Short-circuit the common case of anonymous access.
        if object_roles is None or 'Anonymous' in object_roles:
            return 1

        # Provide short-cut access if object is protected by 'Authenticated'
        # role and user is not nobody
        if 'Authenticated' in object_roles and (
            self.getUserName() != 'Anonymous User'):
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

InitializeClass(PatchBasicUser)

# Add all PatchBasicUser methods to BasicUser class
for attr, val in PatchBasicUser.__dict__.items():
    if not attr.startswith('__'):
        setattr(BasicUser, attr, val)

#
# Group class
#

class BasicGroup(Base):
    """Base class for Group objects.
    """

    security = ClassSecurityInfo()

    def __init__(self, id, title):
        self.id = id
        self.title = title

    security.declareProtected(ManageUsers, 'Title')
    def Title(self):
        """Group title"""
        return self.title

    security.declareProtected(ManageUsers, 'setTitle')
    def setTitle(self, title):
        self.title = title

InitializeClass(BasicGroup)


class Group(Implicit, Persistent, BasicGroup):
    """Standard persistent Group object."""

    security = ClassSecurityInfo()

    def __init__(self, id, title='', users=(), **kw):
        BasicGroup.__init__(self, id, title)
        self.users = list(users)

    security.declareProtected(ManageUsers, 'getUsers')
    def getUsers(self):
        """Group users"""
        return tuple(self.users)

    security.declarePrivate('_setUsers')
    def _setUsers(self, usernames):
        self.users = list(usernames)

    security.declarePrivate('_addUsers')
    def _addUsers(self, usernames):
        users = self.users
        users.extend(usernames)
        self.users = users

    security.declarePrivate('_delUsers')
    def _delUsers(self, usernames):
        users = self.users
        for username in usernames:
            users.remove(username)
        self.users = users

InitializeClass(Group)


class SpecialGroup(BasicGroup):
    """A dynamic non-persistent group that has no explicit members.
    """

    security = ClassSecurityInfo()

    security.declareProtected(ManageUsers, 'getUsers')
    def getUsers(self):
        """Group users"""
        return ()

    security.declarePrivate('_setUsers')
    def _setUsers(self, usernames):
        raise ValueError('Cannot set users')

    security.declarePrivate('_addUsers')
    def _addUsers(self, usernames):
        raise ValueError('Cannot add users')

    security.declarePrivate('_delUsers')
    def _delUsers(self, usernames):
        raise ValueError('Cannot del users')

InitializeClass(SpecialGroup)


class UserFolderWithGroups(UserFolder):
    """Standard User Folder with Groups.

    Groups are a mapping between group names and lists of users.
    Groups can be used to affect roles to a lot of users
    at the same time, and to centralize management.
    """

    meta_type = 'User Folder With Groups'
    title = 'User Folder With Groups'

    security = ClassSecurityInfo()

    def __init__(self):
        UserFolder.__init__(self)
        self.groups = PersistentMapping()

    #
    # Group API
    #

    security.declareProtected(ManageUsers, 'userFolderAddGroup')
    def userFolderAddGroup(self, groupname, title='', **kw):
        """Create a group"""
        if self.groups.has_key(groupname):
            raise ValueError, 'Group "%s" already exists' % groupname
        if groupname.startswith('role:'):
            raise ValueError, 'Group "%s" is reserved' % groupname
        group = Group(groupname, title=title, **kw)
        self.groups[groupname] = group

    security.declareProtected(ManageUsers, 'userFolderDelGroups')
    def userFolderDelGroups(self, groupnames):
        """Delete groups"""
        for groupname in groupnames:
            usernames = self.getGroupById(groupname).getUsers()
            self.delUsersFromGroup(usernames, groupname)
            del self.groups[groupname]

    security.declareProtected(ManageUsers, 'getGroupNames')
    def getGroupNames(self):
        """Return a list of group names"""
        return tuple(self.groups.keys())

    security.declareProtected(ManageUsers, 'getGroupById')
    def getGroupById(self, groupname, default=_marker):
        """Return the given group"""
        if groupname.startswith('role:'):
            return SpecialGroup(groupname, title=groupname)
        try:
            group = self.groups[groupname]
        except KeyError:
            if default is _marker: raise
            return default
        return group

    # Group management

    security.declareProtected(ManageUsers, 'setGroupsOfUser')
    def setGroupsOfUser(self, groupnames, username):
        """Set the groups of a user"""
        user = self.getUserById(username)
        oldgroups = user.getGroups()
        # uniquify
        dict = {}
        for u in groupnames:
            dict[u] = None
        groupnames = dict.keys()
        # update info in user
        user._setGroups(groupnames)
        # update info in groups
        addgroups = filter(lambda g, o=oldgroups: g not in o, groupnames)
        delgroups = filter(lambda g, n=groupnames: g not in n, oldgroups)
        for groupname in addgroups:
            group = self.getGroupById(groupname)
            group._addUsers((username,))
        for groupname in delgroups:
            group = self.getGroupById(groupname)
            group._delUsers((username,))

    security.declareProtected(ManageUsers, 'addGroupsToUser')
    def addGroupsToUser(self, groupnames, username):
        """Add one user to the groups"""
        # uniquify
        dict = {}
        for u in groupnames: dict[u] = None
        groupnames = dict.keys()
        # check values
        user = self.getUserById(username)
        oldgroups = user.getGroups()
        for groupname in groupnames:
            if groupname in oldgroups:
                raise ValueError, 'Group "%s" already exists' % groupname
        # update info in user
        user._addGroups(groupnames)
        # update info in groups
        for groupname in groupnames:
            group = self.getGroupById(groupname)
            group._addUsers((username,))

    security.declareProtected(ManageUsers, 'delGroupsFromUser')
    def delGroupsFromUser(self, groupnames, username):
        """Remove one user from the groups"""
        # uniquify
        dict = {}
        for u in groupnames:
            dict[u] = None
        groupnames = dict.keys()
        # check values
        user = self.getUserById(username)
        oldgroups = user.getGroups()
        for groupname in groupnames:
            if groupname not in oldgroups:
                raise ValueError, 'Group "%s" does not exist' % groupname
        # update info in user
        user._delGroups(groupnames)
        # update info in groups
        for groupname in groupnames:
            group = self.getGroupById(groupname)
            group._delUsers((username,))

    security.declareProtected(ManageUsers, 'setUsersOfGroup')
    def setUsersOfGroup(self, usernames, groupname):
        """Set the users of the group"""
        # uniquify
        dict = {}
        for u in usernames:
            dict[u] = None
        usernames = dict.keys()
        #
        group = self.getGroupById(groupname)
        oldusers = group.getUsers()
        addusers = filter(lambda u, o=oldusers: u not in o, usernames)
        delusers = filter(lambda u, n=usernames: u not in n, oldusers)
        # update info in group
        group._setUsers(usernames)
        # update info in users
        for username in addusers:
            user = self.getUserById(username)
            user._addGroups((groupname,))
        for username in delusers:
            user = self.getUserById(username)
            user._delGroups((groupname,))

    security.declareProtected(ManageUsers, 'addUsersToGroup')
    def addUsersToGroup(self, usernames, groupname):
        """Add the users to the group"""
        # uniquify
        dict = {}
        for u in usernames:
            dict[u] = None
        usernames = dict.keys()
        # check values
        group = self.getGroupById(groupname)
        oldusers = group.getUsers()
        for username in usernames:
            if username in oldusers:
                raise ValueError, 'User "%s" already exists' % username
        # update info in group
        group._addUsers(usernames)
        # update info in users
        for username in usernames:
            user = self.getUserById(username)
            user._addGroups((groupname,))

    security.declareProtected(ManageUsers, 'delUsersFromGroup')
    def delUsersFromGroup(self, usernames, groupname):
        """Remove the users from the group"""
        # uniquify
        dict = {}
        for u in usernames: dict[u] = None
        usernames = dict.keys()
        # check values
        group = self.getGroupById(groupname)
        oldusers = group.getUsers()
        for username in usernames:
            if username not in oldusers:
                raise ValueError, 'User "%s" does not exists' % username
        # update info in group
        group._delUsers(usernames)
        # update info in users
        for username in usernames:
            user = self.getUserById(username)
            user._delGroups((groupname,))

    #
    # Overriden UserFolder methods to provide groups parameter
    #

    def _doAddUser(self, name, password, roles, domains, groups=(), **kw):
        """Create a new user"""
        UserFolder._doAddUser(self, name, password, roles, domains, **kw)
        self.setGroupsOfUser(groups, name)

    def _doDelUsers(self, names):
        """Delete one or more users."""
        for username in names:
            user = self.getUser(username)
            if user is None:
                raise KeyError, 'User "%s" does not exist' % username
            groupnames = user.getGroups()
            self.delGroupsFromUser(groupnames, username)
        UserFolder._doDelUsers(self, names)

    def _doChangeUser(self, name, password, roles, domains, groups=None, **kw):
        UserFolder._doChangeUser(self, name, password, roles, domains, **kw)
        if groups is not None:
            self.setGroupsOfUser(groups, name)

    #
    # CPS APIs
    #

    security.declarePublic('hasLocalRolesBlocking')
    def hasLocalRolesBlocking(self):
        """Is local roles blocking implemented in this user folder."""
        return 1

    security.declarePrivate('mergedLocalRoles')
    def mergedLocalRoles(self, object, withgroups=0):
        """
        Return a merging of object and its ancestors' __ac_local_roles__.
        When called with withgroups=1, the keys are
        of the form user:foo and group:bar.
        """
        merged = {}
        object = aq_inner(object)
        stop_loop = 0
        while 1:
            if hasattr(object, '__ac_local_roles__'):
                dict = object.__ac_local_roles__ or {}
                if callable(dict):
                    dict = dict()
                for k, v in dict.items():
                    if withgroups:
                        k = 'user:'+k # groups
                    # Skip blocking roles
                    v = [r for r in v if r and r[0] != '-']
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
                    for k, v in dict.items():
                        k = 'group:'+k
                        # Blocking, simplest case: everyone is blocked.
                        if k == 'group:role:Anonymous' and '-' in v:
                            stop_loop = 1
                        # Skip blocking roles
                        v = [r for r in v if r and r[0] != '-']
                        if merged.has_key(k):
                            merged[k] = merged[k] + v
                        elif v:
                            merged[k] = v
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
        """
        Return a merging of object and its ancestors' __ac_local_roles__.
        When called with withgroups=1, the keys are
        of the form user:foo and group:bar.
        The path corresponding
        to the object where the role takes place is added
        with the role in the result. In this case of the form :
        {'user:foo': [{'url':url, 'roles':[Role0, Role1]},
                    {'url':url, 'roles':[Role1]}],..}.
        """
        # XXX this method has lame return values with full urls

        utool = getToolByName(object, 'portal_url')
        merged = {}
        object = getattr(object, 'aq_inner', object)

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
        if 'Anonymous' not in res:
            res.append('Anonymous')
        res.append('user:' + user.getUserName())
        if hasattr(aq_base(user), 'getGroups'):
            groups = user.getGroups() + ('role:Anonymous',)
            if 'Authenticated' in res:
                groups = groups + ('role:Authenticated',)
        else:
            groups = ('role:Anonymous',)
        for group in groups:
            res.append('group:' + group)
        return res

    # old spelling
    _getAllowedRolesAndUsers = getAllowedRolesAndUsersOfUser

    #
    # ZMI overrides
    #

    manage_options = (
        UserFolder.manage_options[:1] +        # Contents
        ({'label': 'User Groups', 'action': 'manage_userGroups',},) +
        UserFolder.manage_options[1:]          # etc.
        )

    _add_User = DTMLFile('zmi/ufwg_addUser', globals())
    _editUser = DTMLFile('zmi/ufwg_editUser', globals())

    manage_userGroups = DTMLFile('zmi/ufwg_mainGroup', globals())
    manage_addGroup = DTMLFile('zmi/ufwg_addGroup', globals())
    manage_showGroup = DTMLFile('zmi/ufwg_showGroup', globals())

    security.declareProtected(ManageUsers, 'manage_users')
    def manage_users(self, submit=None, REQUEST=None, RESPONSE=None):
        """Handle operations on users for the web based forms of the ZMI.
           Application code (code that is outside of the forms that implement
           the UI of a user folder) are encouraged to use
           manage_std_addUser instead."""

        if submit == 'Add':
            name = reqattr(REQUEST, 'name')
            password = reqattr(REQUEST, 'password')
            confirm = reqattr(REQUEST, 'confirm')
            roles = reqattr(REQUEST, 'roles')
            domains = reqattr(REQUEST, 'domains')
            groups = reqattr(REQUEST, 'groupnames')
            return self._addUser(name, password, confirm, roles, domains,
                                 REQUEST, groups)

        if submit == 'Change':
            name = reqattr(REQUEST, 'name')
            password = reqattr(REQUEST, 'password')
            confirm = reqattr(REQUEST, 'confirm')
            roles = reqattr(REQUEST, 'roles')
            domains = reqattr(REQUEST, 'domains')
            groups  = reqattr(REQUEST, 'groupnames')
            return self._changeUser(name, password, confirm, roles, domains,
                                    REQUEST, groups)

        return UserFolder.manage_users(self, submit, REQUEST, RESPONSE)

    security.declarePrivate('_addUser')
    def _addUser(self, name, password, confirm, roles, domains, REQUEST=None,
                 groups=None):
        if not roles:
            roles = []
        if not domains:
            domains = []
        if not groups:
            groups = []
        # error cases
        if ((not name) or
            (not password or not confirm) or
            (self.getUser(name) or (self._emergency_user and
                                    name == self._emergency_user.getUserName())) or
            ((password or confirm) and (password != confirm)) or
            (domains and not self.domainSpecValidate(domains))
            ):
            return UserFolder._addUser(self, name, password, confirm, roles,
                                       domains, REQUEST)

        self._doAddUser(name, password, roles, domains, groups)

        if REQUEST is not None:
            return self._mainUser(self, REQUEST)

    security.declarePrivate('_changeUser')
    def _changeUser(self, name, password, confirm, roles, domains,
                    REQUEST=None, groups=None):
        if password == 'password' and confirm == 'pconfirm':
            password = confirm = None
        if not roles:
            roles = []
        if not domains:
            domains = []
        # error cases
        if ((not name) or
            (password == confirm == '') or
            (not self.getUser(name)) or
            ((password or confirm) and (password != confirm)) or
            (domains and not self.domainSpecValidate(domains))
            ):
            return UserFolder._changeUser(self,name,password,confirm,roles,
                                          domains,REQUEST)

        self._doChangeUser(name, password, roles, domains, groups)

        if REQUEST is not None:
            return self._mainUser(self, REQUEST)

    #
    # ZMI for groups
    #

    security.declareProtected(ManageUsers, 'manage_editGroups')
    def manage_editGroups(self,
                          submit_add_=None,
                          submit_add=None,
                          submit_edit=None,
                          submit_del=None,
                          groupname=None,
                          groupnames=[],
                          usernames=[],
                          title=None,
                          REQUEST=None, **kw):
        """Group management"""
        if submit_add_ is not None:
            return self.manage_addGroup(self, REQUEST)
        if submit_add is not None:
            return self._addGroup(groupname, usernames, title, REQUEST)
        if submit_edit is not None:
            return self._editGroup(groupname, usernames, title, REQUEST)
        if submit_del is not None:
            return self._delGroups(groupnames, REQUEST)
        raise ValueError, 'Incorrect submit'

    security.declarePrivate('_addGroup')
    def _addGroup(self, groupname, usernames=[], title='', REQUEST=None,
                  **kw):
        usernames = filter(None, [u.strip() for u in usernames])
        if not groupname:
            return MessageDialog(
                title='Illegal value',
                message='A group name must be specified',
                action='manage_userGroups')
        if self.getGroupById(groupname, None) is not None:
            return MessageDialog(
                title='Illegal value',
                message='A group named "%s" already exists' % groupname,
                action='manage_userGroups')
        for username in usernames:
            if not self.getUserById(username):
                return MessageDialog(
                    title='Illegal value',
                    message='The user "%s" does not exist' % username,
                    action='manage_userGroups')

        self.userFolderAddGroup(groupname, title=title)
        self.setUsersOfGroup(usernames, groupname)

        if REQUEST is not None:
            return self.manage_userGroups(self, REQUEST)

    security.declarePrivate('_editGroup')
    def _editGroup(self, groupname, usernames=[], title='', REQUEST=None,
                   **kw):
        usernames = filter(None, [u.strip() for u in usernames])
        if not groupname:
            return MessageDialog(
                title='Illegal value',
                message='A group name must be specified',
                action='manage_userGroups')
        group = self.getGroupById(groupname, None)
        if group is None:
            return MessageDialog(
                   title='Illegal value',
                   message='The group "%s" does not exists' % groupname,
                   action='manage_userGroups')
        for username in usernames:
            if not self.getUserById(username):
                return MessageDialog(
                    title='Illegal value',
                    message='The user "%s" does not exist' % username,
                    action='manage_userGroups')

        group.setTitle(title)
        self.setUsersOfGroup(usernames, groupname)

        if REQUEST is not None:
            return self.manage_userGroups(self, REQUEST)

    security.declarePrivate('_delGroups')
    def _delGroups(self, groupnames, REQUEST=None, **kw):
        for groupname in groupnames:
            if self.getGroupById(groupname, None) is None:
                return MessageDialog(
                    title='Illegal value',
                    message='The group "%s" does not exists' % groupname,
                    action='manage_userGroups')

        self.userFolderDelGroups(groupnames)

        if REQUEST is not None:
            return self.manage_userGroups(self, REQUEST)

    # Helper used by ZMI management page
    security.declareProtected(ManageUsers, 'list_local_userids')
    def list_local_userids(self):
        """Return the list of user names or OverflowError"""
        mlu = getattr(aq_base(self), 'maxlistusers', None)
        if mlu is None:
            mlu = DEFAULTMAXLISTUSERS
        if mlu < 0:
            raise OverflowError
        usernames = self.getUserNames()
        if mlu != 0 and len(usernames) > mlu:
            raise OverflowError
        return usernames

InitializeClass(UserFolderWithGroups)


def addUserFolderWithGroups(dispatcher, id=None, REQUEST=None):
    """Add a User Folder With Groups"""
    f = UserFolderWithGroups()
    container = dispatcher.Destination()
    container._setObject('acl_users', f)
    container.__allow_groups__ = f
    if REQUEST is not None:
        dispatcher.manage_main(dispatcher, REQUEST)
