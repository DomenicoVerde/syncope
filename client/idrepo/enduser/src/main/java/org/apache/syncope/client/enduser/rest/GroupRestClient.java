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
package org.apache.syncope.client.enduser.rest;

import java.util.List;
import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.Response;
import org.apache.syncope.common.lib.request.GroupCR;
import org.apache.syncope.common.lib.request.GroupUR;
import org.apache.syncope.common.lib.to.GroupTO;
import org.apache.syncope.common.lib.to.ProvisioningResult;
import org.apache.syncope.common.rest.api.beans.AnyQuery;
import org.apache.syncope.common.rest.api.service.AnyService;
import org.apache.syncope.common.rest.api.service.GroupService;
import org.apache.syncope.common.rest.api.service.SyncopeService;

/**
 * Console client for invoking Rest Group's services.
 */
public class GroupRestClient extends AbstractAnyRestClient<GroupTO> {

    private static final long serialVersionUID = -8549081557283519638L;

    @Override
    protected Class<? extends AnyService<GroupTO>> getAnyServiceClass() {
        return GroupService.class;
    }

    public static ProvisioningResult<GroupTO> create(final GroupCR groupCR) {
        Response response = getService(GroupService.class).create(groupCR);
        return response.readEntity(new GenericType<ProvisioningResult<GroupTO>>() {
        });
    }

    public ProvisioningResult<GroupTO> update(final String etag, final GroupUR updateReq) {
        ProvisioningResult<GroupTO> result;
        synchronized (this) {
            result = getService(etag, GroupService.class).update(updateReq).
                    readEntity(new GenericType<ProvisioningResult<GroupTO>>() {
                    });
            resetClient(getAnyServiceClass());
        }
        return result;
    }

    public static List<GroupTO> searchAssignableGroups(
        final String realm,
        final String term,
        final int page,
        final int size) {

        return getService(SyncopeService.class).searchAssignableGroups(realm, term, page, size).getResult();
    }

    @Override
    public int count(final String realm, final String fiql, final String type) {
        return getService(GroupService.class).
                search(new AnyQuery.Builder().realm(realm).fiql(fiql).page(1).size(1).build()).
                getTotalCount();
    }

}
