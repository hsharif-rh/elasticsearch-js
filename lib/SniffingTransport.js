/*
 * Licensed to Elasticsearch B.V. under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch B.V. licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

'use strict'

const { Transport } = require('@elastic/transport')

const noop = () => {}

class SniffingTransport extends Transport {
  sniff (opts, callback = noop) {
    if (this._isSniffing === true) return
    this._isSniffing = true

    if (typeof opts === 'function') {
      callback = opts
      opts = { reason: Transport.sniffReasons.DEFAULT }
    }

    const { reason } = opts

    const request = {
      method: 'GET',
      path: this.sniffEndpoint
    }

    this.request(request, { id: opts.requestId }, (err, result) => {
      this._isSniffing = false
      if (this._sniffEnabled === true) {
        this._nextSniff = Date.now() + this.sniffInterval
      }

      if (err != null) {
        result.meta.sniff = { hosts: [], reason }
        this.emit('sniff', err, result)
        return callback(err)
      }

      const protocol = result.meta.connection.url.protocol || /* istanbul ignore next */ 'http:'
      const hosts = this.connectionPool.nodesToHost(result.body.nodes, protocol)
      this.connectionPool.update(hosts)

      result.meta.sniff = { hosts, reason }
      this.emit('sniff', null, result)
      callback(null, hosts)
    })
  }
}

module.exports = SniffingTransport
