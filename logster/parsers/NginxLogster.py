###  A sample logster parser file that can be used to count the number
###  of response codes found in an Apache access log.
###
###  For example:
###  sudo ./logster --dry-run --output=ganglia SampleLogster /var/log/httpd/access_log
###
###
###  Copyright 2011, Etsy, Inc.
###
###  This file is part of Logster.
###
###  Logster is free software: you can redistribute it and/or modify
###  it under the terms of the GNU General Public License as published by
###  the Free Software Foundation, either version 3 of the License, or
###  (at your option) any later version.
###
###  Logster is distributed in the hope that it will be useful,
###  but WITHOUT ANY WARRANTY; without even the implied warranty of
###  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
###  GNU General Public License for more details.
###
###  You should have received a copy of the GNU General Public License
###  along with Logster. If not, see <http://www.gnu.org/licenses/>.
###

import time
import re

from logster.logster_helper import MetricObject, LogsterParser
from logster.logster_helper import LogsterParsingException

class NginxLogster(LogsterParser):

    def __init__(self, option_string=None):
        '''Initialize any data structures or variables needed for keeping track
        of the tasty bits we find in the log we are parsing.'''
        self.http_1xx = 0
        self.http_2xx = 0
        self.http_3xx = 0
        self.http_4xx = 0
        self.http_5xx = 0
        self.metrics = []

        # Regular expression for matching lines we are interested in, and capturing
        # fields from the line (in this case, http_status_code).

        """
        $remote_addr - $remote_user [$time_local] $host "$request" $status $bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for" $upstream_response_time;
        """
        self.reg = re.compile('(?P<remote_addr>\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3}) - - \[(?P<time_local>.*)\] (?P<host>\S+) "(?P<request>\w{3,6}.* \w{0,4}/\d\.\d)" (?P<http_status_code>\d+) (?P<bytes_sent>\d+) "(?P<http_referer>\S+)" ["](?P<http_user_agent>.*)["] ["](?P<http_x_forwarded_for>\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3})["] (?P<upstream_response_time>\d+\.\d+)')

    def parse_line(self, line):
        '''This function should digest the contents of one line at a time, updating
        object's state variables. Takes a single argument, the line to be parsed.'''

        try:
            # Apply regular expression to each line and extract interesting bits.
            regMatch = self.reg.match(line)

            if regMatch:
                linebits = regMatch.groupdict()
                host = linebits['host']
                response_time = float(linebits['upstream_response_time'])
                response_time_in_ms = int(int(response_time) * 1000 + (response_time - int(response_time)) * 1000)
                http_code = linebits['http_status_code']
                status = int(http_code)

                if (status < 200):
                    self.http_1xx += 1
                elif (status < 300):
                    self.http_2xx += 1
                elif (status < 400):
                    self.http_3xx += 1
                elif (status < 500):
                    self.http_4xx += 1
                else:
                    self.http_5xx += 1
                self.metrics.append(MetricObject("statsd.http.code,http_host=%s,http_code=%s" % (host, http_code), 1, "", metric_type='c'))
                self.metrics.append(MetricObject("statsd.http.response_time,http_host=%s" % (host), response_time_in_ms, "", metric_type='h'))
            else:
                raise LogsterParsingException("regmatch failed to match")

        except Exception as e:
            raise LogsterParsingException("regmatch or contents failed with %s" % e)


    def get_state(self, duration):
        '''Run any necessary calculations on the data collected from the logs
        and return a list of metric objects.'''
        self.duration = float(duration)

        # Return a list of metrics objects
        return self.metrics
