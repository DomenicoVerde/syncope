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
package org.apache.syncope.client.console.rest;

import java.util.List;
import org.apache.syncope.common.lib.to.ApplicationTO;
import org.apache.syncope.common.rest.api.service.ApplicationService;

public class ApplicationRestClient extends BaseRestClient {

    private static final long serialVersionUID = -381814125643246243L;

    public static void delete(final String key) {
        getService(ApplicationService.class).delete(key);
    }

    public static ApplicationTO read(final String key) {
        return getService(ApplicationService.class).read(key);
    }

    public static void update(final ApplicationTO applicationTO) {
        getService(ApplicationService.class).update(applicationTO);
    }

    public static void create(final ApplicationTO applicationTO) {
        getService(ApplicationService.class).create(applicationTO);
    }

    public static List<ApplicationTO> list() {
        return getService(ApplicationService.class).list();
    }

}
