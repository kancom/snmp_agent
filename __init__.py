# -*- coding: utf-8 -*-


"""snmp agent with AgentX protocol for KPI."""


__author__    = "Andrey Kashirin <support@sysqual.net>"
__date__      = "2016-10-22 15:11:01 MSK"
__copyright__ = "Copyright (C) 2018 by SysQual, LLC"
__license__   = "proprietary"
__version__   = "2.5"


import re
import sys
import argparse
import pyagentx
import datetime
import subprocess
from flask import json, Response
#~ from flask import request

from riva_platform.lib.meta import PlatformThread
from riva_platform.utils import EndpointAction, FlaskAppWrapper, shutdown_flask

#~ import pdb; pdb.set_trace()

API_VERSION = 'v1.0'
REST_PORT = 9875
ROUTE = "/snmp/api/" + API_VERSION + '/'
HTTP_200_OK = 200
HTTP_503_SERVICE_UNAVAILABLE = 503
PROD_USER = 'discovery'

STAT_FILE_PATH = "/dev/shm/" + PROD_USER +"/production/"
STAT_RDR_PATH = "/opt/" + PROD_USER +"/bin/kroki-stats"

SHELL_CMD4CORE = "for file in `ls {}*.stats`; do {} $file; done"
SHELL_CMD4UPLOADER = "if [ -e {}di-data-uploader.kpi  ]; then cat {}di-data-uploader.kpi; fi"
SHELL_CMD4NGINX = "curl 127.0.0.1:4480/nginx_status 2>&1 | grep connections | grep -oP '[0-9]+'"
SHELL_CMD4SNMP = 'if pgrep ruby > /dev/null; then ps H --ppid `pgrep --oldest ruby` -w -o "ppid pid tid stat %mem %cpu comm cmd" --no-headers; fi'

kpi_pttrn4nginx = "([0-9]+)" #3
kpi_pttrn4core = "\[([0-9]+)\]\s+([^:]+):\s([0-9]+)" #[4671] parser.dissect.failed: 0
kpi_pttrn4snmp = "\s*" + "([^\s]+)\s+" * 6 + "([^\s]+\s?(?!/)[^\s]+)(\s{2,}|\s(?=/))(.*)" #26135 26271 26515 Sl    0.2  0.0 di-data-uploader     /usr/bin/perl -w /opt/discovery/bin/di-data-uploader

def get_stats():
    cmd = SHELL_CMD4CORE.format(STAT_FILE_PATH, STAT_RDR_PATH)
    result = ""
    try:
        result = subprocess.check_output(cmd, shell=True)
    finally:
        return result

def get_stats_snmp():
    result = ""
    try:
        result = subprocess.check_output(SHELL_CMD4SNMP, shell=True)
    finally:
        return result

def get_dbupload_kpi():
    result = ""
    cmd = SHELL_CMD4UPLOADER.format(STAT_FILE_PATH, STAT_FILE_PATH)
    try:
        result = subprocess.check_output(cmd, shell=True)
    finally:
        return result

def get_ch_kpi():
    out = ""
    cmd = "ps -A | grep clickhouse-serv | awk '{print $1}'"
    try:
        out = subprocess.check_output(cmd, shell=True)
        out = out.replace("\n", "")
    except Exception as e:
        out = ""
    if out != "":
        cmd = "clickhouse-client  --query=\"select concat('[{}] db.',lower(metric), ': ', toString(value)) from system.asynchronous_metrics\"".format(out)
        try:
            out = subprocess.check_output(cmd, shell=True)
        except Exception as e:
            out = ""
    return out

def get_nginx_kpi():
    result = ""
    try:
        result = subprocess.check_output(SHELL_CMD4NGINX, shell=True)
    finally:
        return result

class rivaSWRunEntry(pyagentx.Updater):
    def update(self):
        def set_SWRunPPID(idx, value):
          self.set_GAUGE32('2.'+str(idx), value)
        def set_SWRunPID(idx, value):
          self.set_GAUGE32('3.'+str(idx), value)
        def set_SWRunTID(idx, value):
          self.set_GAUGE32('4.'+str(idx), value)
        def set_SWRunPath(idx, value):
          self.set_OCTETSTRING('5.'+str(idx), value)
        def set_SWRunName(idx, value):
          self.set_OCTETSTRING('6.'+str(idx), value)
        def set_SWRunStatus(idx, value):
          self.set_OCTETSTRING('7.'+str(idx), value)
        def set_SWRunCPU(idx, value):
          self.set_GAUGE32('8.'+str(idx), value)
        def set_SWRunMem(idx, value):
          self.set_GAUGE32('9.'+str(idx), value)

        prog = re.compile(kpi_pttrn4snmp)
        stats = get_stats_snmp()

        i = 1
        if stats:
            for line in stats.splitlines():
                match = prog.match(line)
                if match:
                    set_SWRunPPID(i, int(match.group(1)))
                    set_SWRunPID(i, int(match.group(2)))
                    set_SWRunTID(i, int(match.group(3)))
                    set_SWRunStatus(i, match.group(4))
                    set_SWRunMem(i, 100*float(match.group(5)))
                    set_SWRunCPU(i, 100*float(match.group(6)))
                    set_SWRunName(i, match.group(7))
                    set_SWRunPath(i, match.group(9)) #9!
                    i = i + 1
        else:
            set_SWRunPPID(i, int(0))
            set_SWRunPID(i, int(0))
            set_SWRunTID(i, int(0))
            set_SWRunStatus(i, '')
            set_SWRunMem(i, float(0))
            set_SWRunCPU(i, float(0))
            set_SWRunName(i, '')
            set_SWRunPath(i, '') #9!


# Updater class that set OID values
class rivaKPIEntry(pyagentx.Updater):
    def update(self):
        def set_kpiPID(idx, value):
          self.set_GAUGE32('2.'+str(idx), value)

        def set_kpiName(idx, value):
          self.set_OCTETSTRING('3.'+str(idx), value)

        def set_kpiValue(idx, value):
          self.set_COUNTER64('4.'+str(idx), value)

        stats = get_stats()
        prog = re.compile(kpi_pttrn4core)
        i = 1
        for line in stats.splitlines():
            match = prog.match(line)
            if match:
                set_kpiPID(i, int(match.group(1)))
                set_kpiName(i, match.group(2))
                set_kpiValue(i, int(match.group(3)))
                i = i + 1

        stats = get_dbupload_kpi()
        for line in stats.splitlines():
            match = prog.match(line)
            if match:
                set_kpiPID(i, int(match.group(1)))
                set_kpiName(i, match.group(2))
                set_kpiValue(i, int(match.group(3)))
                i = i + 1

        stats = get_ch_kpi()
        for line in stats.splitlines():
            match = prog.match(line)
            if match:
                set_kpiPID(i, int(match.group(1)))
                set_kpiName(i, match.group(2))
                set_kpiValue(i, int(match.group(3)))
                i = i + 1

        stats = get_nginx_kpi().strip()
        match = re.match(kpi_pttrn4nginx, stats)
        if match:
            set_kpiPID(i, 0)
            set_kpiName(i, 'gui.activeconns')
            set_kpiValue(i, int(match.group(1)))
            i = i + 1

class rivaAgent(pyagentx.Agent):
    def setup(self):
        # Register Updater class that responsd to
        self.register('1.3.6.1.4.1.20624.5.1.1', rivaKPIEntry)
        self.register('1.3.6.1.4.1.20624.6.1.1', rivaSWRunEntry)

class RESTapi(PlatformThread):

    def __init__(self, *args, **kwargs):
        super(RESTapi, self).__init__(*args, **kwargs)
        self.flask_app = FlaskAppWrapper(__name__)
        self.flask_app.add_endpoint(endpoint=ROUTE+'kpi',
                                    endpoint_name='kpi',
                                    handler=self.rest_kpi,
                                    )

    def body(self, *args, **kwargs):
        self.flask_app.run(host='0.0.0.0', port=REST_PORT,
                           debug=False, use_reloader=False)

    def stop(self):
        shutdown_flask()

    def rest_kpi(self):
        kpis = dict(datetime=datetime.datetime.now().strftime('%s'),
                    results=[]
                    )
        core_stats = get_stats()
        dbupload_stats = get_dbupload_kpi()
        ch_stats = get_ch_kpi()
        ngnx_stats = get_nginx_kpi().strip()

        prog = re.compile(kpi_pttrn4core)
        for line in core_stats.splitlines():
            match = prog.match(line)
            if match:
                kpis["results"].append(dict(pid=match.group(1),
                                counter=match.group(2),
                                value=match.group(3)
                                  )
                            )

        for line in dbupload_stats.splitlines():
            match = prog.match(line)
            if match:
                kpis["results"].append(dict(pid=match.group(1),
                                counter=match.group(2),
                                value=match.group(3)
                                  )
                            )

        for line in ch_stats.splitlines():
            match = prog.match(line)
            if match:
                kpis["results"].append(dict(pid=match.group(1),
                                counter=match.group(2),
                                value=match.group(3)
                                  )
                            )

        match = re.match(kpi_pttrn4nginx, ngnx_stats)
        if match:
            kpis["results"].append(dict(pid=0,
                                counter='gui.activeconns',
                                value=match.group(1)
                                  )
                            )
        if kpis["results"]:
            response = Response(json.dumps(kpis),
                            status=HTTP_200_OK,
                            mimetype=u'application/json')
            #~ response.headers.add('Access-Control-Allow-Origin',
                #~ request.referrer[:str.find(request.referrer, '/administration')]) #request.url_root
            #~ response.headers.add('Access-Control-Allow-Methods', 'GET')
            #~ response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
            #~ response.headers.add('Access-Control-Allow-Credentials', 'true')
            #~ response.headers.add('Access-Control-Allow-Headers', 'Cache-Control')
            #~ response.headers.add('Access-Control-Allow-Headers', 'X-Requested-With')
            return response
        else:
            return Response(
                        json.dumps({'msg':'Not alive'}),
                        status=HTTP_503_SERVICE_UNAVAILABLE,
                        mimetype=u'application/json'
                        )

def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="Report bugs to %s" % __author__
    )
    parser.add_argument(
        "-v", "--version", action="store_true",
        help="Print version and exit"
    )
    args = parser.parse_args(sys.argv[1:])
    if args.version:
        print '%s' % __version__
        return 0

    #pyagentx.setup_logging()
    agent = None
    try:
        restapi = RESTapi()
        restapi.start()
        agent = rivaAgent()
        agent.start()
    except Exception as e:
        print "Unhandled exception:", e
        agent.stop()
    except KeyboardInterrupt:
        agent.stop()
        restapi.stop()

if __name__ == "__main__":
        main()
