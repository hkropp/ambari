/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.ambari.server.security.authorization.pam;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.Inject;
import org.apache.ambari.server.AmbariException;
import org.apache.ambari.server.configuration.Configuration;
import org.apache.ambari.server.security.ClientSecurityType;
import org.apache.ambari.server.security.authorization.AmbariGrantedAuthority;
import org.apache.ambari.server.security.authorization.Group;
import org.apache.ambari.server.security.authorization.User;
import org.apache.ambari.server.security.authorization.UserType;
import org.apache.ambari.server.security.authorization.Users;
import org.apache.ambari.server.state.SecurityType;
import org.jvnet.libpam.PAM;
import org.jvnet.libpam.PAMException;
import org.jvnet.libpam.UnixUser;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class AmbariPamAuthenticationProvider implements AuthenticationProvider {

    Logger LOG = LoggerFactory.getLogger(AmbariPamAuthenticationProvider.class);

    private boolean ALL_ALLOWED_LOGIN = false;

    private Configuration configuration;
    private Users users;

    private final boolean IS_PAM_ENABLED;
    private final String pamServiceName;



    private final Set<String> loginGroups;
    private final Set<String> adminGroups;


    @Inject
    public AmbariPamAuthenticationProvider(Configuration configuration, Users users) {
        this.users = users;
        this.IS_PAM_ENABLED = configuration.getClientSecurityType() == ClientSecurityType.PAM;
        this.pamServiceName = configuration.getPamServiceName();
        this.loginGroups = loadLoginGroups(configuration);
        this.adminGroups = loadAdminGroups(configuration);
    }

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if(IS_PAM_ENABLED) {
            AmbariPamAuthenticationToken userToken = (AmbariPamAuthenticationToken) authentication;

            String userName = userToken.getName();
            String password = userToken.getPassword();

            PAM pam;
            try {
                pam = new PAM(pamServiceName);
            }
            catch (PAMException e) {
                throw new AmbariPamException(e);
            }
            try {
                UnixUser unixUser = pam.authenticate(userName, password);

                // is user allowed to log in
                if (!isUserAllowedLogin(unixUser)) {
                    String message = String.format("Login is disabled for user [{}]. User does not belong to any allowed login group.", userName);
                    LOG.warn(message);
                    throw new LockedException(message);
                }

                // if user not exist in local db create
                User user = users.getUser(userName, UserType.PAM);
                if (user != null) {
                    users.createUser(userName, null, UserType.PAM, true, false);
                }

                // is user disabled?
                if (!user.isActive()) {
                    String message = String.format("User [{}] is disabled.", userName);
                    LOG.warn(message);
                    throw new DisabledException(message);
                }

                // update groups. update authorities of user.
                updateGroupMembership(unixUser, user);

                // revoke or add admin privileges based on group membership.
                addRevokeAdminPrivileges(unixUser, user);

                Collection<AmbariGrantedAuthority> userAuthorities = users.getUserAuthorities(user.getUserName(),
                                                                                              user.getUserType());

                return new AmbariPamAuthenticationToken(user.getUserName(), authentication.getCredentials(), userAuthorities);
            }
            catch (PAMException e) {
                String message = "PAM: Bad Credentials";
                throw new BadCredentialsException(message);
            }
            catch (AmbariException e) {
                String message = "Could not create or alter user in local DB.";
                LOG.error(message, e);
                throw new AuthenticationServiceException(message, e);
            }
            finally {
                pam.dispose();
            }
        } else {
            return null;
        }
    }

    private void addRevokeAdminPrivileges(UnixUser unixUser, User user) {
        if (!isUserAdmin(unixUser) && user.isAdmin()) {
            users.revokeAdminPrivilege(user.getUserId());
        }
        else if (isUserAdmin(unixUser) && !user.isAdmin()) {
            users.grantAdminPrivilege(user.getUserId());
        }
    }

    private Set<String> loadLoginGroups(Configuration configuration) {
        Set<String> loginGroups = new HashSet<String>();
        loginGroups.addAll(configuration.getAmbariUserLoginGroups());
        if(loginGroups.size() == 1 && ( loginGroups.contains("*") || loginGroups.contains("ALL") ))
            ALL_ALLOWED_LOGIN = true;
        return loginGroups;
    }

    private Set<String> loadAdminGroups(Configuration configuration) {
        Set<String> adminGroups = new HashSet<String>();
        adminGroups.addAll(configuration.getAmbariUserAdminGroups());
        return adminGroups;
    }


    private void updateGroupMembership(UnixUser unixUser, User user) throws AmbariException {
        Set<String> groupsToRemove = new HashSet<String>();
        Set<String> groupsToAdd = new HashSet<String>();
        for(String existingGroup : user.getGroups()){
            if(!unixUser.getGroups().contains(existingGroup))       // is NOT unix group, but is in DB
                groupsToRemove.add(existingGroup);
        }
        for(String assignedGroup : unixUser.getGroups()){
            if(!user.getGroups().contains(assignedGroup))           // is unix group, but NOT in DB
                groupsToAdd.add(assignedGroup);
        }
        if(groupsToRemove.size() > 0){
            for(String delGroup: groupsToRemove){
                users.removeMemberFromGroup(delGroup, user.getUserName());
            }
        }
        if(groupsToAdd.size() > 0){
            // we have to create the groups that don't already exist
            List<Group> existingGroups = users.getAllGroups();
            for(String groupToAdd : groupsToAdd){
                boolean create = true;
                for(Group existingGroup : existingGroups){
                    if(existingGroup.getGroupName().equals(groupToAdd))
                        create = false;
                        break;
                }
                if(create == true)
                    users.createGroup(groupToAdd);
                users.addMemberToGroup(groupToAdd, user.getUserName());
            }
        }
    }

    private boolean isUserAllowedLogin(UnixUser user){
        if(ALL_ALLOWED_LOGIN)
            return true;
        for(String group : user.getGroups()){
            if(loginGroups.contains(group))
                return true;
        }
        return false;
    }

    private boolean isUserAdmin(UnixUser user){
        for(String group : user.getGroups()){
            if(adminGroups.contains(group))
                return true;
        }
        return false;
    }

    public boolean supports(Class<?> authentication) {
        return AmbariPamAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
