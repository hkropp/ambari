/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

package org.apache.ambari.server.serveraction.upgrades;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;

import org.apache.ambari.server.AmbariException;
import org.apache.ambari.server.ServiceNotFoundException;
import org.apache.ambari.server.actionmanager.HostRoleStatus;
import org.apache.ambari.server.agent.CommandReport;
import org.apache.ambari.server.serveraction.AbstractServerAction;
import org.apache.ambari.server.state.Cluster;
import org.apache.ambari.server.state.Clusters;
import org.apache.ambari.server.state.Config;
import org.apache.commons.lang.StringUtils;

import com.google.inject.Inject;

/**
 * Computes Yarn properties for SPARK.
 *
 * Properties list:
 * - yarn.nodemanager.aux-services.spark_shuffle.class
 * - yarn.nodemanager.aux-services  (add spark_shuffle to the list)
 *
 * These properties available starting from HDP-2.4 stack.
 */
public class SparkShufflePropertyConfig extends AbstractServerAction {
  private static final String YARN_SITE_CONFIG_TYPE = "yarn-site";

  private static final String YARN_NODEMANAGER_AUX_SERVICES = "yarn.nodemanager.aux-services";
  private static final String SPARK_SHUFFLE_AUX_STR = "spark_shuffle";
  private static final String YARN_NODEMANAGER_AUX_SERVICES_SPARK_SHUFFLE_CLASS = "yarn.nodemanager.aux-services.spark_shuffle.class";
  private static final String YARN_NODEMANAGER_AUX_SERVICES_SPARK_SHUFFLE_CLASS_VALUE = "org.apache.spark.network.yarn.YarnShuffleService";

  @Inject
  private Clusters clusters;

  @Override
  public CommandReport execute(ConcurrentMap<String, Object> requestSharedDataContext)
      throws AmbariException, InterruptedException {

    String clusterName = getExecutionCommand().getClusterName();
    Cluster cluster = clusters.getCluster(clusterName);
    Config yarnSiteConfig = cluster.getDesiredConfigByType(YARN_SITE_CONFIG_TYPE);

    if (yarnSiteConfig == null) {
      return  createCommandReport(0, HostRoleStatus.FAILED,"{}",
              String.format("Source type %s not found", YARN_SITE_CONFIG_TYPE), "");
    }

    try {
      cluster.getService("SPARK");  // check if SPARK service present
      Map<String, String> yarnSiteProperties = yarnSiteConfig.getProperties();

      final List<String> auxSevices;
      final String oldAuxServices = yarnSiteProperties.get(YARN_NODEMANAGER_AUX_SERVICES);
      final String newAuxServices;

      if (yarnSiteProperties.containsKey(YARN_NODEMANAGER_AUX_SERVICES)) {
        auxSevices = new ArrayList<>(Arrays.asList(oldAuxServices.split(",", -1)));
      } else {
        auxSevices = new ArrayList<>();
      }
      auxSevices.add(SPARK_SHUFFLE_AUX_STR);
      newAuxServices = StringUtils.join(auxSevices, ",");

      yarnSiteProperties.put(YARN_NODEMANAGER_AUX_SERVICES, newAuxServices);
      yarnSiteProperties.put(YARN_NODEMANAGER_AUX_SERVICES_SPARK_SHUFFLE_CLASS, YARN_NODEMANAGER_AUX_SERVICES_SPARK_SHUFFLE_CLASS_VALUE);
      yarnSiteConfig.setProperties(yarnSiteProperties);
      yarnSiteConfig.persist(false);

      return createCommandReport(0, HostRoleStatus.COMPLETED, "{}",
        String.format("%s was set from %s to %s. %s was set to %s",
                YARN_NODEMANAGER_AUX_SERVICES, oldAuxServices, newAuxServices,
                YARN_NODEMANAGER_AUX_SERVICES_SPARK_SHUFFLE_CLASS_VALUE, YARN_NODEMANAGER_AUX_SERVICES_SPARK_SHUFFLE_CLASS_VALUE), "");

    } catch (ServiceNotFoundException e) {
      return createCommandReport(0, HostRoleStatus.COMPLETED, "{}",
          String.format("%s not updated as no SPARK service present on the cluster", YARN_NODEMANAGER_AUX_SERVICES), "");
    }
  }
}
