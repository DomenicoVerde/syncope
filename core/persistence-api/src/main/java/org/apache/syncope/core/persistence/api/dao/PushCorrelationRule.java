/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.syncope.core.persistence.api.dao;

import org.apache.syncope.common.lib.policy.PushCorrelationRuleConf;
import org.apache.syncope.core.persistence.api.entity.Any;
import org.apache.syncope.core.persistence.api.entity.resource.Provision;
import org.identityconnectors.framework.common.objects.filter.Filter;

/**
 * Interface for correlation rule to be evaluated during PushJob execution.
 */
@FunctionalInterface
public interface PushCorrelationRule {

    default void setConf(PushCorrelationRuleConf conf) {
    }

    /**
     * Return a search condition.
     *
     * @param any user, group or any object
     * @param provision resource provision
     * @return search condition.
     */
    Filter getFilter(Any<?> any, Provision provision);
}
