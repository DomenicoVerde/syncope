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
package org.apache.syncope.core.rest.cxf.service;

import java.util.List;
import org.apache.syncope.common.lib.to.UserTO;
import org.apache.syncope.common.lib.to.WorkflowTask;
import org.apache.syncope.common.lib.to.WorkflowTaskExecInput;
import org.apache.syncope.core.logic.UserWorkflowTaskLogic;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.apache.syncope.common.rest.api.service.UserWorkflowTaskService;

@Service
public class UserWorkflowTaskServiceImpl extends AbstractServiceImpl implements UserWorkflowTaskService {

    @Autowired
    private UserWorkflowTaskLogic logic;

    @Override
    public List<WorkflowTask> getAvailableTasks(final String userKey) {
        return logic.getAvailableTasks(userKey);
    }

    @Override
    public UserTO executeNextTask(final WorkflowTaskExecInput workflowTaskExecInput) {
        return logic.executeNextTask(workflowTaskExecInput);
    }
}
