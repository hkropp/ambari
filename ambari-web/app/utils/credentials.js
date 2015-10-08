/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

var App = require('app');

/** @module utils.credentials **/
module.exports = {

  STORE_TYPES: {
    TEMPORARY: 'temporary',
    PERSISTENT: 'persisted',
    PERSISTENT_KEY: 'persistent',
    TEMPORARY_KEY: 'temporary',
    PERSISTENT_PATH: 'storage.persistent',
    TEMPORARY_PATH: 'storage.temporary'
  },

  /**
   * Store credentials to server
   *
   * @member utils.credentials
   * @param {string} clusterName cluster name
   * @param {string} alias credential alias name e.g. "kdc.admin.credentials"
   * @param {object} resource resource info to set e.g.
   * <code>
   * {
   *   principal: "USERNAME",
   *   key: "SecretKey",
   *   type: "persisted"
   * }
   * </code>
   *
   * Where:
   * <ul>
   *   <li>principal: the principal (or username) part of the credential to store</li>
   *   <li>key: the secret key part of the credential to store</li>
   *   <li>type: declares the storage facility type: "persisted" or "temporary"</li>
   * </ul>
   * @returns {$.Deferred} promise object
   */
  createCredentials: function(clusterName, alias, resource) {
    return App.ajax.send({
      sender: this,
      name: 'credentials.create',
      data: {
        clusterName: clusterName,
        resource: resource,
        alias: alias
      },
      error: 'createCredentialsErrorCallback'
    });
  },

  createCredentialsErrorCallback: function(req, ajaxOpts, error) {
    console.error('createCredentials ERROR:', error);
  },

  /**
   * Retrieve single credential from cluster by specified alias name
   *
   * @member utils.credentials
   * @param {string} clusterName cluster name
   * @param {string} alias credential alias name e.g. "kdc.admin.credentials"
   * @returns {$.Deferred} promise object
   */
  getCredential: function(clusterName, alias, callback) {
    return App.ajax.send({
      sender: this,
      name: 'credentials.get',
      data: {
        clusterName: clusterName,
        alias: alias,
        callback: callback
      },
      success: 'getCredentialSuccessCallback'
    });
  },

  getCredentialSuccessCallback: function(data, opt, params) {
    params.callback(Em.getWithDefault(data, 'Credential', null));
  },

  /**
   * Update credential by alias and cluster name
   *
   * @see createCredentials
   * @param {string} clusterName
   * @param {string} alias
   * @param {object} resource
   * @returns {$.Deferred} promise object
   */
  updateCredentials: function(clusterName, alias, resource) {
    return App.ajax.send({
      sender: this,
      name: 'credentials.update',
      data: {
        clusterName: clusterName,
        alias: alias,
        resource: resource
      }
    });
  },

  /**
   * Get credenial list from server by specified cluster name
   *
   * @param {string} clusterName cluster name
   * @param {function} callback
   * @returns {$.Deferred} promise object
   */
  credentials: function(clusterName, callback) {
    return App.ajax.send({
      sender: this,
      name: 'credentials.list',
      data: {
        clusterName: clusterName
      },
      success: 'credentialsSuccessCallback'
    });
  },

  credentialsSuccessCallback: function(data, opt, params) {
    params.callback(data.items.length ? data.items.mapProperty('Credential') : []);
  },

  /**
   * Remove credential from server by specified cluster name and alias
   *
   * @param {string} clusterName cluster name
   * @param {string} alias credential alias name e.g. "kdc.admin.credentials"
   */
  removeCredentials: function(clusterName, alias) {
    return App.ajax.send({
      sender: this,
      name: 'credentials.delete',
      data: {
        clusterName: clusterName,
        alias: alias
      }
    });
  },

  /**
   * Get info regarding credential storage type like <code>persistent</code> and <code>temporary</code>
   *
   * @param {string} clusterName cluster name
   * @param {function} callback
   * @returns {$.Deferred} promise object
   */
  storageInfo: function(clusterName, callback) {
    return App.ajax.send({
      sender: this,
      name: 'credentials.store.info',
      data: {
        clusterName: clusterName,
        callback: callback
      },
      success: 'storageInfoSuccessCallback'
    });
  },

  storageInfoSuccessCallback: function(json, opt, params, request) {
    if (json.Clusters) {
      var storage = Em.getWithDefault(json, 'Clusters.credential_store_properties', {});
      var storeTypesObject = {};

      storeTypesObject[this.STORE_TYPES.PERSISTENT_KEY] = storage[this.STORE_TYPES.PERSISTENT_PATH] === "true";
      storeTypesObject[this.STORE_TYPES.TEMPORARY_KEY] = storage[this.STORE_TYPES.TEMPORARY_PATH] === "true";
      params.callback(storeTypesObject);
    } else {
      params.callback(null);
    }
  },

  /**
   * Resolves promise with <code>true</code> value if secure store is persistent
   *
   * @param {string} clusterName
   * @returns {$.Deferred} promise object
   */
  isStorePersisted: function(clusterName) {
    return this.storeTypeStatus(clusterName, this.STORE_TYPES.PERSISTENT_KEY);
  },

  /**
   * Resolves promise with <code>true</code> value if secure store is temporary
   *
   * @param {string} clusterName
   * @returns {$.Deferred} promise object
   */
  isStoreTemporary: function(clusterName) {
    return this.storeTypeStatus(clusterName, this.STORE_TYPES.TEMPORARY_KEY);
  },

  /**
   * Get store type value for specified cluster and store type e.g. <b>persistent</b> or <b>temporary</b>
   *
   * @param {string} clusterName
   * @param {string} type store type e.g. <b>persistent</b> or <b>temporary</b>
   * @returns {$.Deferred} promise object
   */
  storeTypeStatus: function(clusterName, type) {
    var dfd = $.Deferred();
    this.storageInfo(clusterName, function(storage) {
      dfd.resolve(Em.get(storage, type));
    }).fail(function(error) {
      dfd.reject(error);
    });
    return dfd.promise();
  }
};