=============
CPSUserFolder
=============

CPSUserFolder is a user folder that uses CPSDirectory and CPSSchemas for
all its configuration.

It is designed to subsume all functionality from NuxUserGroups,
LDAPUserGroupsFolder and PluggableUserFolder. It is extendable through
addition directory types, for instance the LDAP backend uses an LDAP
directory.

CPSUserFolder also provides a replacement CMF membership and memberdata
tool that understand CPSSchemas' schemas and can talk directly to the
cps user folder.
