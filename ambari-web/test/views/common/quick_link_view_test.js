/**
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

var App = require('app');
require('views/common/quick_view_link_view');

describe('App.QuickViewLinks', function () {

  var quickViewLinks = App.QuickViewLinks.create({
    content: Em.Object.create()
  });

  describe("#linkTarget", function () {
    it("blank link", function () {
      quickViewLinks.set('content.serviceName', 'HDFS');
      quickViewLinks.propertyDidChange('linkTarget');
      expect(quickViewLinks.get('linkTarget')).to.equal('_blank');
    });
    it("non-blank link", function () {
      quickViewLinks.set('content.serviceName', 'S1');
      quickViewLinks.propertyDidChange('linkTarget');
      expect(quickViewLinks.get('linkTarget')).to.be.empty;
    });
  });

  describe("#ambariProperties", function () {
    beforeEach(function () {
      sinon.stub(App.router, 'get').returns({p: 1});
    });
    afterEach(function () {
      App.router.get.restore();
    });
    it("ambariProperties are updated", function () {
      expect(quickViewLinks.get('ambariProperties')).to.eql({p: 1});
    });
  });

  describe("#didInsertElement()", function () {
    beforeEach(function () {
      sinon.stub(App.router, 'get').returns({p: 1});
      sinon.stub(quickViewLinks, 'loadQuickLinksConfigurations');
    });
    afterEach(function () {
      App.router.get.restore();
      quickViewLinks.loadQuickLinksConfigurations.restore();
    });
    it("loadQuickLinksConfigurations is called once", function () {
      quickViewLinks.didInsertElement();
      expect(quickViewLinks.loadQuickLinksConfigurations.calledOnce).to.be.true;
    });
  });

  describe("#willDestroyElement()", function () {

    beforeEach(function () {
      quickViewLinks.setProperties({
        configProperties: [{}],
        actualTags: [""],
        quickLinks: [{}]
      });
      quickViewLinks.willDestroyElement();
    });

    it("configProperties empty", function () {
      expect(quickViewLinks.get('configProperties')).to.be.empty;
    });

    it("actualTags empty", function () {
      expect(quickViewLinks.get('actualTags')).to.be.empty;
    });

    it("quickLinks empty", function () {
      expect(quickViewLinks.get('quickLinks')).to.be.empty;
    });
  });

  describe("#setQuickLinks()", function () {
    beforeEach(function () {
      this.mock = sinon.stub(App, 'get');
      sinon.stub(quickViewLinks, 'loadTags', Em.K);
    });
    afterEach(function () {
      this.mock.restore();
      quickViewLinks.loadTags.restore();
    });
    it("data loaded", function () {
      this.mock.returns(true);
      quickViewLinks.setQuickLinks();
      expect(quickViewLinks.loadTags.calledOnce).to.be.true;
    });
    it("data not loaded", function () {
      this.mock.returns(false);
      quickViewLinks.setQuickLinks();
      expect(quickViewLinks.loadTags.called).to.be.false;
    });
  });

  describe("#loadTags()", function () {
    beforeEach(function () {
      sinon.stub(App.ajax, 'send');
    });
    afterEach(function () {
      App.ajax.send.restore();
    });
    it("call $.ajax", function () {
      quickViewLinks.loadTags();
      expect(App.ajax.send.calledWith({
        name: 'config.tags',
        sender: quickViewLinks,
        success: 'loadTagsSuccess',
        error: 'loadTagsError'
      })).to.be.true;
    });
  });

  describe("#loadTagsSuccess()", function () {
    beforeEach(function () {
      sinon.stub(quickViewLinks, 'setConfigProperties', function () {
        return {
          done: function (callback) {
            callback();
          }
        }
      });
      sinon.stub(quickViewLinks, 'getQuickLinksHosts');
      var data = {
        Clusters: {
          desired_configs: {
            site1: {
              tag: 'tag1'
            }
          }
        }
      };
      quickViewLinks.loadTagsSuccess(data);
    });
    afterEach(function () {
      quickViewLinks.setConfigProperties.restore();
      quickViewLinks.getQuickLinksHosts.restore();
    });
    it("actualTags is valid", function () {
      expect(quickViewLinks.get('actualTags')[0]).to.eql(Em.Object.create({
        siteName: 'site1',
        tagName: 'tag1'
      }));
    });
    it("setConfigProperties is called once", function () {
      expect(quickViewLinks.setConfigProperties.calledOnce).to.be.true;
    });
    it("getQuickLinksHosts is called once", function () {
      expect(quickViewLinks.getQuickLinksHosts.calledOnce).to.be.true;
    });
  });

  describe("#loadTagsError()", function () {
    beforeEach(function () {
      sinon.stub(quickViewLinks, 'getQuickLinksHosts');
    });
    afterEach(function () {
      quickViewLinks.getQuickLinksHosts.restore();
    });
    it("call loadQuickLinksConfigurations", function () {
      quickViewLinks.loadTagsError();
      expect(quickViewLinks.getQuickLinksHosts.calledOnce).to.be.true;
    });
  });

  describe("#loadQuickLinksConfigSuccessCallback()", function () {
    var mock;

    beforeEach(function () {
      sinon.stub(App.store, 'commit', Em.K);
      mock = sinon.stub(quickViewLinks, 'getQuickLinksConfiguration');
    });
    afterEach(function () {
      App.store.commit.restore();
      mock.restore();
    });
    it("requiredSites consistent", function () {
      var quickLinksConfigHBASE = {
        protocol: {
          type: "http"
        },
        links: [
          {
            port: {
              site: "hbase-site"
            }
          }
        ]
      };
      var quickLinksConfigYARN = {
        protocol: {
          checks: [
            {
              site: "yarn-site"
            }
          ],
          type: "https"
        },
        links: [
          {
            port: {
              site: "yarn-site"
            }
          }
        ]
      };
      quickViewLinks.set('content.serviceName', 'HBASE');
      mock.returns(quickLinksConfigHBASE);
      quickViewLinks.loadQuickLinksConfigSuccessCallback({items: []});
      quickViewLinks.set('content.serviceName', 'YARN');
      mock.returns(quickLinksConfigYARN);
      quickViewLinks.loadQuickLinksConfigSuccessCallback({items: []});
      expect(quickViewLinks.get('requiredSiteNames')).to.be.eql(["core-site", "hdfs-site", "hbase-site", "yarn-site"]);
    });
  });

  describe("#getQuickLinksHosts()", function () {
    beforeEach(function () {
      sinon.stub(App.ajax, 'send');
      sinon.stub(App.HostComponent, 'find').returns([
        Em.Object.create({
          isMaster: true,
          hostName: 'host1'
        })
      ]);
    });
    afterEach(function () {
      App.ajax.send.restore();
      App.HostComponent.find.restore();
    });
    it("call $.ajax", function () {
      quickViewLinks.getQuickLinksHosts();
      expect(App.ajax.send.calledWith({
        name: 'hosts.for_quick_links',
        sender: quickViewLinks,
        data: {
          clusterName: App.get('clusterName'),
          masterHosts: 'host1',
          urlParams: ''
        },
        success: 'setQuickLinksSuccessCallback'
      })).to.be.true;
    });
    it("call $.ajax, HBASE service", function () {
      quickViewLinks.set('content.serviceName', 'HBASE');
      quickViewLinks.getQuickLinksHosts();
      expect(App.ajax.send.calledWith({
        name: 'hosts.for_quick_links',
        sender: quickViewLinks,
        data: {
          clusterName: App.get('clusterName'),
          masterHosts: 'host1',
          urlParams: ',host_components/metrics/hbase/master/IsActiveMaster'
        },
        success: 'setQuickLinksSuccessCallback'
      })).to.be.true;
    });
  });

  describe("#setQuickLinksSuccessCallback()", function () {
    beforeEach(function () {
      this.mock = sinon.stub(quickViewLinks, 'getHosts');
      sinon.stub(quickViewLinks, 'setEmptyLinks');
      sinon.stub(quickViewLinks, 'setSingleHostLinks');
      sinon.stub(quickViewLinks, 'setMultipleHostLinks');
      quickViewLinks.set('content.quickLinks', []);
    });
    afterEach(function () {
      this.mock.restore();
      quickViewLinks.setEmptyLinks.restore();
      quickViewLinks.setSingleHostLinks.restore();
      quickViewLinks.setMultipleHostLinks.restore();
    });
    it("no hosts", function () {
      this.mock.returns([]);
      quickViewLinks.setQuickLinksSuccessCallback();
      expect(quickViewLinks.setEmptyLinks.calledOnce).to.be.true;
    });
    it("quickLinks is not configured", function () {
      this.mock.returns([{}]);
      quickViewLinks.setQuickLinksSuccessCallback();
      expect(quickViewLinks.setEmptyLinks.calledOnce).to.be.false;
    });
    it("single host", function () {
      this.mock.returns([{hostName: 'host1'}]);
      quickViewLinks.setQuickLinksSuccessCallback();
      expect(quickViewLinks.setSingleHostLinks.calledWith([{hostName: 'host1'}])).to.be.true;
    });
    it("multiple hosts", function () {
      this.mock.returns([{hostName: 'host1'}, {hostName: 'host2'}]);
      quickViewLinks.setQuickLinksSuccessCallback();
      expect(quickViewLinks.setMultipleHostLinks.calledWith(
        [{hostName: 'host1'}, {hostName: 'host2'}]
      )).to.be.true;
    });
  });

  describe("#getPublicHostName()", function () {
    it("host present", function () {
      var hosts = [{
        Hosts: {
          host_name: 'host1',
          public_host_name: 'public_name'
        }
      }];
      expect(quickViewLinks.getPublicHostName(hosts, 'host1')).to.equal('public_name');
    });
    it("host absent", function () {
      expect(quickViewLinks.getPublicHostName([], 'host1')).to.be.null;
    });
  });

  describe("#setConfigProperties()", function () {
    var mock = {getConfigsByTags: Em.K};
    beforeEach(function () {
      sinon.stub(App.router, 'get').returns(mock);
      sinon.spy(mock, 'getConfigsByTags');
    });
    afterEach(function () {
      mock.getConfigsByTags.restore();
      App.router.get.restore();
    });
    it("getConfigsByTags called with correct data", function () {
      quickViewLinks.set('actualTags', [{siteName: 'hdfs-site'}]);
      quickViewLinks.set('requiredSiteNames', ['hdfs-site']);
      quickViewLinks.setConfigProperties();
      expect(mock.getConfigsByTags.calledWith([{siteName: 'hdfs-site'}])).to.be.true;
    });
  });

  describe("#setEmptyLinks()", function () {
    it("empty links are set", function () {
      quickViewLinks.setEmptyLinks();
      expect(quickViewLinks.get('quickLinks')).to.eql([{
        label: quickViewLinks.t('quick.links.error.label'),
        url: 'javascript:alert("' + quickViewLinks.t('contact.administrator') + '");return false;' // eslint-disable-line no-script-url
      }]);
      expect(quickViewLinks.get('isLoaded')).to.be.true;
    });
  });

  describe("#processOozieHosts()", function () {
    it("host status is valid", function () {
      quickViewLinks.set('content.hostComponents', [Em.Object.create({
        componentName: 'OOZIE_SERVER',
        workStatus: 'STARTED',
        hostName: 'host1'
      })]);
      var host = {hostName: 'host1'};
      quickViewLinks.processOozieHosts([host]);
      expect(host.status).to.equal(Em.I18n.t('quick.links.label.active'));
    });
  });

  describe("#processHdfsHosts()", function () {
    beforeEach(function () {
      quickViewLinks.set('content.activeNameNode', null);
      quickViewLinks.set('content.standbyNameNode', null);
      quickViewLinks.set('content.standbyNameNode2', null);
    });
    it("active namenode host", function () {
      quickViewLinks.set('content.activeNameNode', Em.Object.create({hostName: 'host1'}));
      var host = {hostName: 'host1'};
      quickViewLinks.processHdfsHosts([host]);
      expect(host.status).to.equal(Em.I18n.t('quick.links.label.active'));
    });
    it("standby namenode host", function () {
      quickViewLinks.set('content.standbyNameNode', Em.Object.create({hostName: 'host1'}));
      var host = {hostName: 'host1'};
      quickViewLinks.processHdfsHosts([host]);
      expect(host.status).to.equal(Em.I18n.t('quick.links.label.standby'));
    });
    it("second standby namenode host", function () {
      quickViewLinks.set('content.standbyNameNode2', Em.Object.create({hostName: 'host1'}));
      var host = {hostName: 'host1'};
      quickViewLinks.processHdfsHosts([host]);
      expect(host.status).to.equal(Em.I18n.t('quick.links.label.standby'));
    });
  });

  describe("#processHbaseHosts()", function () {
    it("isActiveMaster is true", function () {
      var response = {
        items: [
          {
            Hosts: {
              host_name: 'host1'
            },
            host_components: [
              {
                HostRoles: {
                  component_name: 'HBASE_MASTER'
                },
                metrics: {
                  hbase: {
                    master: {
                      IsActiveMaster: 'true'
                    }
                  }
                }
              }
            ]
          }
        ]
      };
      var host = {hostName: 'host1'};
      quickViewLinks.processHbaseHosts([host], response);
      expect(host.status).to.equal(Em.I18n.t('quick.links.label.active'));
    });
    it("isActiveMaster is false", function () {
      var response = {
        items: [
          {
            Hosts: {
              host_name: 'host1'
            },
            host_components: [
              {
                HostRoles: {
                  component_name: 'HBASE_MASTER'
                },
                metrics: {
                  hbase: {
                    master: {
                      IsActiveMaster: 'false'
                    }
                  }
                }
              }
            ]
          }
        ]
      };
      var host = {hostName: 'host1'};
      quickViewLinks.processHbaseHosts([host], response);
      expect(host.status).to.equal(Em.I18n.t('quick.links.label.standby'));
    });
    it("isActiveMaster is undefined", function () {
      var response = {
        items: [
          {
            Hosts: {
              host_name: 'host1'
            },
            host_components: [
              {
                HostRoles: {
                  component_name: 'HBASE_MASTER'
                }
              }
            ]
          }
        ]
      };
      var host = {hostName: 'host1'};
      quickViewLinks.processHbaseHosts([host], response);
      expect(host.status).to.be.undefined;
    });
  });

  describe("#processYarnHosts()", function () {
    it("haStatus is ACTIVE", function () {
      quickViewLinks.set('content.hostComponents', [Em.Object.create({
        componentName: 'RESOURCEMANAGER',
        hostName: 'host1',
        haStatus: 'ACTIVE'
      })]);
      var host = {hostName: 'host1'};
      quickViewLinks.processYarnHosts([host]);
      expect(host.status).to.equal(Em.I18n.t('quick.links.label.active'));
    });
    it("haStatus is STANDBY", function () {
      quickViewLinks.set('content.hostComponents', [Em.Object.create({
        componentName: 'RESOURCEMANAGER',
        hostName: 'host1',
        haStatus: 'STANDBY'
      })]);
      var host = {hostName: 'host1'};
      quickViewLinks.processYarnHosts([host]);
      expect(host.status).to.equal(Em.I18n.t('quick.links.label.standby'));
    });
    it("haStatus is undefined", function () {
      quickViewLinks.set('content.hostComponents', [Em.Object.create({
        componentName: 'RESOURCEMANAGER',
        hostName: 'host1'
      })]);
      var host = {hostName: 'host1'};
      quickViewLinks.processYarnHosts([host]);
      expect(host.status).to.be.undefined;
    });
  });

  describe("#findHosts()", function () {
    beforeEach(function () {
      sinon.stub(quickViewLinks, 'getPublicHostName').returns('public_name');
    });
    afterEach(function () {
      quickViewLinks.getPublicHostName.restore();
    });
    it("public_name from getPublicHostName", function () {
      quickViewLinks.set('content.hostComponents', [Em.Object.create({
        componentName: 'C1',
        hostName: 'host1'
      })]);
      expect(quickViewLinks.findHosts('C1', {})).to.eql([{
        hostName: 'host1',
        publicHostName: 'public_name'
      }]);
    });
  });

  describe('#setProtocol', function () {
    var tests = [
      //Yarn
      {
        serviceName: "YARN",
        configProperties: [
          {type: 'yarn-site', properties: {'yarn.http.policy': 'HTTPS_ONLY'}}
        ],
        quickLinksConfig: {
          protocol:{
            type:"https",
            checks:[
              {property:"yarn.http.policy",
                desired:"HTTPS_ONLY",
                site:"yarn-site"}
            ]
          }
        },
        m: "https for yarn (checks for https passed)",
        result: "https"
      },
      {
        serviceName: "YARN",
        configProperties: [
          {type: 'yarn-site', properties: {'yarn.http.policy': 'HTTP_ONLY'}}
        ],
        quickLinksConfig: {
          protocol:{
            type:"http",
            checks:[
              {property:"yarn.http.policy",
                desired:"HTTP_ONLY",
                site:"yarn-site"}
            ]
          }
        },
        m: "http for yarn (checks for http passed)",
        result: "http"
      },
      {
        serviceName: "YARN",
        configProperties: [
          {type: 'yarn-site', properties: {'yarn.http.policy': 'HTTP_ONLY'}}
        ],
        quickLinksConfig: {
          protocol:{
            type:"https",
            checks:[
              {property:"yarn.http.policy",
                desired:"HTTPS_ONLY",
                site:"yarn-site"}
            ]
          }
        },
        m: "http for yarn (checks for https did not pass)",
        result: "http"
      },
      {
        serviceName: "YARN",
        configProperties: [
          {type: 'yarn-site', properties: {'yarn.http.policy': 'HTTPS_ONLY'}}
        ],
        quickLinksConfig: {
          protocol:{
            type:"http",
            checks:[
              {property:"yarn.http.policy",
                desired:"HTTP_ONLY",
                site:"yarn-site"}
            ]
          }
        },
        m: "https for yarn (checks for http did not pass)",
        result: "https"
      },
      {
        serviceName: "YARN",
        configProperties: [
          {type: 'yarn-site', properties: {'yarn.http.policy': 'HTTP_ONLY'}}
        ],
        quickLinksConfig: {
          protocol:{
            type:"HTTP_ONLY",
            checks:[
              {property:"yarn.http.policy",
                desired:"HTTPS_ONLY",
                site:"yarn-site"}
            ]
          }
        },
        m: "http for yarn (override checks with specific protocol type)",
        result: "http"
      },
      {
        serviceName: "YARN",
        configProperties: [
          {type: 'yarn-site', properties: {'yarn.http.policy': 'HTTPS_ONLY'}}
        ],
        quickLinksConfig: {
          protocol:{
            type:"HTTPS_ONLY",
            checks:[
              {property:"yarn.http.policy",
                desired:"HTTPS_ONLY",
                site:"yarn-site"}
            ]
          }
        },
        m: "https for yarn (override checks with specific protocol type)",
        result: "https"
      },
      //Any service - override hadoop.ssl.enabled
      {
        serviceName: "MyService",
        configProperties: [
          {type: 'myservice-site', properties: {'myservice.http.policy': 'HTTPS_ONLY'}},
          {type: 'hdfs-site', properties: {'dfs.http.policy':'HTTP_ONLY'}}
        ],
        quickLinksConfig: {
          protocol:{
            type:"https",
            checks:[
              {property:"myservice.http.policy",
                desired:"HTTPS_ONLY",
                site:"myservice-site"}
            ]
          }
        },
        m: "https for MyService (checks for https passed, override hadoop.ssl.enabled)",
        result: "https"
      },
      //Oozie
      {
        serviceName: "OOZIE",
        configProperties: [
          {type: 'oozie-site', properties: {'oozie.https.port': '12345', 'oozie.https.keystore.file':'/tmp/oozie.jks', 'oozie.https.keystore.pass':'mypass'}}
        ],
        quickLinksConfig: {
          protocol:{
            type:"https",
            checks:
              [
                {
                  "property":"oozie.https.port",
                  "desired":"EXIST",
                  "site":"oozie-site"
                },
                {
                  "property":"oozie.https.keystore.file",
                  "desired":"EXIST",
                  "site":"oozie-site"
                },
                {
                  "property":"oozie.https.keystore.pass",
                  "desired":"EXIST",
                  "site":"oozie-site"
                }
              ]
          }
        },
        m: "https for oozie (checks for https passed)",
        result: "https"
      },
      {
        serviceName: "OOZIE",
        configProperties: [
          {type: 'oozie-site', properties: {"oozie.base.url":"http://c6401.ambari.apache.org:11000/oozie"}}
        ],
        quickLinksConfig: {
          protocol:{
            type:"https",
            checks:
              [
                {
                  "property":"oozie.https.port",
                  "desired":"EXIST",
                  "site":"oozie-site"
                },
                {
                  "property":"oozie.https.keystore.file",
                  "desired":"EXIST",
                  "site":"oozie-site"
                },
                {
                  "property":"oozie.https.keystore.pass",
                  "desired":"EXIST",
                  "site":"oozie-site"
                }
              ]
          }
        },
        m: "http for oozie (checks for https did not pass)",
        result: "http"
      },
      //Ranger: HDP 2.2
      {
        serviceName: "RANGER",
        configProperties: [{type: 'ranger-site', properties: {'http.enabled': 'false'}}],
        quickLinksConfig: {
          protocol:{
            type:"https",
            checks:
              [
                {
                  "property":"http.enabled",
                  "desired":"false",
                  "site":"ranger-site"
                }
              ]
          }
        },
        m: "https for ranger (HDP2.2, checks passed)",
        result: "https"
      },
      {
        serviceName: "RANGER",
        configProperties: [{type: 'ranger-site', properties: {'http.enabled': 'true'}}],
        quickLinksConfig: {
          protocol:{
            type:"https",
            checks:
              [
                {
                  "property":"http.enabled",
                  "desired":"false",
                  "site":"ranger-site"
                }
              ]
          }
        },
        m: "http for ranger (HDP2.2, checks for https did not pass)",
        result: "http"
      },
      //Ranger: HDP 2.3
      {
        serviceName: "RANGER",
        configProperties:
          [
            {
              type: 'ranger-admin-site',
              properties: {'ranger.service.http.enabled': 'false', 'ranger.service.https.attrib.ssl.enabled': 'true'}
            },
          ],
        quickLinksConfig: {
          protocol:{
            type:"https",
            checks:
              [
                {
                  "property":"ranger.service.http.enabled",
                  "desired":"false",
                  "site":"ranger-admin-site"
                },
                {
                  "property":"ranger.service.https.attrib.ssl.enabled",
                  "desired":"true",
                  "site":"ranger-admin-site"
                }
              ]
          }
        },

        m: "https for ranger (HDP2.3, checks passed)",
        result: "https"
      },
      {
        serviceName: "RANGER",
        configProperties:
          [
            {
              type: 'ranger-admin-site',
              properties: {'ranger.service.http.enabled': 'true', 'ranger.service.https.attrib.ssl.enabled': 'false'}
            },
          ],
        quickLinksConfig: {
          protocol:{
            type:"https",
            checks:
              [
                {
                  "property":"ranger.service.http.enabled",
                  "desired":"false",
                  "site":"ranger-admin-site"
                },
                {
                  "property":"ranger.service.https.attrib.ssl.enabled",
                  "desired":"true",
                  "site":"ranger-admin-site"
                }
              ]
          }
        },
        m: "http for ranger (HDP2.3, checks for https did not pass)",
        result: "http"
      }
    ];

    tests.forEach(function (t) {
      it(t.m, function () {
        quickViewLinks.set('servicesSupportsHttps', t.servicesSupportsHttps);
        expect(quickViewLinks.setProtocol(t.configProperties, t.quickLinksConfig)).to.equal(t.result);
      });
    });
  });

  describe('#setPort', function () {
    var testData = [
      Em.Object.create({
        'protocol': 'http',
        'port':{
          'http_property':'yarn.timeline-service.webapp.address',
          'http_default_port':'8188',
          'https_property':'yarn.timeline-service.webapp.https.address',
          'https_default_port':'8090',
          'regex': '\\w*:(\\d+)',
          'site':'yarn-site'
        },
        'configProperties':
          [
            {
              'type': 'yarn-site',
              'properties': {'yarn.timeline-service.webapp.address': 'c6401.ambari.apache.org:8188'}
            },
          ],
        'result': '8188'
      }),

      Em.Object.create({
        'protocol': 'https',
        'port':{
          'http_property':'yarn.timeline-service.webapp.address',
          'http_default_port':'8188',
          'https_property':'yarn.timeline-service.webapp.https.address',
          'https_default_port':'8090',
          'regex': '\\w*:(\\d+)',
          'site':'yarn-site'
        },
        'configProperties':
          [
            {
              'type': 'yarn-site',
              'properties': {'yarn.timeline-service.webapp.https.address': 'c6401.ambari.apache.org:8090'}
            },
          ],
        'result': '8090'
      })
    ];

    after(function () {
      quickViewLinks.set('configProperties', []);
    });

    testData.forEach(function (item) {
      it(item.service_id + ' ' + item.protocol, function () {
        quickViewLinks.set('configProperties', item.configProperties || []);
        expect(quickViewLinks.setPort(item.port, item.protocol, item.configProperties)).to.equal(item.result);
      })
    }, this);
  });

});
