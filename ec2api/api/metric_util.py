'''
Created on Jan 29, 2016

@author: souvik
'''
from metrics.ThreadLocalMetrics import ThreadLocalMetrics, ThreadLocalMetricsFactory
from metrics.Metrics import Unit
from oslo_log import log as logging
from time import time
LOG = logging.getLogger(__name__)

'''
This decorator wraps around any method and captures latency around it. If the parameter 'report_error' is set to True
then it also emits metrics on whether the method throws an exception or not
'''
class ReportMetrics(object):
    '''
    @:param metric_name This variable declares what is the latency of an afforsaid sub component call.
    @:param report_error If this is set to True it adds an error counter to 1 if there is an error and 0 if there are no
     error
    '''
    def __init__(self, metric_name, report_error = False):
        self.__metric_name = metric_name
        self.__report_error = report_error
    def __call__(self, function):
        def metrics_wrapper(*args, **kwargs):
            start_time = time()
            error = 0
            try:
                return function(*args, **kwargs)
            except Exception as e:
                LOG.error("Exception while executing " + function.__name__)
                error = 1
                raise e
            finally:
                end_time = time()
                try:
                    metrics = ThreadLocalMetrics.get()
                    metric_time = self.__metric_name + "_time"
                    metrics.add_time(metric_time, int((end_time - start_time)*1000), Unit.MILLIS)
                    if self.__report_error == True:
                        metric_error = self.__metric_name + "_error"
                        metrics.add_count(metric_error, error)
                except AttributeError as e:
                    LOG.exception("No threadlocal metrics object: %s", e)

        return metrics_wrapper

class MetricUtil(object):
    '''
    Metric Utility class to put and fetch request scoped metrics in cinder api
    '''
    METRICS_OBJECT = "metrics_object"
    def __init__(self):
        '''
        Constructor for Metric Utils. 
        '''


    def initialize_thread_local_metrics(self, service_log_path, program_name):

        try:
            metrics = self.fetch_thread_local_metrics()
        except AttributeError:
            metrics = ThreadLocalMetricsFactory(service_log_path).with_marketplace_id(self.get_marketplace_id())\
                            .with_program_name(program_name).create_metrics()
        return metrics

    def __add_request_details(self, metrics, tenant_id, remote_address, request_id,  path_info):
        metrics.add_property("TenantId",  tenant_id)
        metrics.add_property("RemoteAddress", remote_address)
        metrics.add_property("RequestId", request_id)
        metrics.add_property("PathInfo", path_info)
        # Project id is not provided to protect the identity of the user
        # Domain is not provided is it is not used

    def fetch_thread_local_metrics(self):
        return ThreadLocalMetrics.get()

    def get_marketplace_id(self):
        # TODO:Get this from from config/keystone
        return "IDC1"

    def closeMetrics(self, request):
        metrics = self.fetch_thread_local_metrics()
        metrics.close()


