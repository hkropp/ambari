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
package org.apache.ambari.server.events;

/**
 * The {@link HostAddedEvent} is fired when a host is added to a cluster.
 */
public class HostAddedEvent extends ClusterEvent {

  /**
   * The host's name.
   */
  protected final String m_hostName;

  /**
   * Constructor.
   *
   * @param clusterId
   *          the ID of the cluster.
   * @param hostName
   *          the name of the host.
   */
  public HostAddedEvent(long clusterId, String hostName) {
    super(AmbariEventType.HOST_ADDED, clusterId);
    m_hostName = hostName;
  }

  /**
   * Gets the host's name that the event belongs to.
   *
   * @return the hostName
   */
  public String getHostName() {
    return m_hostName;
  }
}
