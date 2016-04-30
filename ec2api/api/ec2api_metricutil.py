from utils.metricutil import metricutil
# Wrapper for Cinder Volume
class Ec2APIMetricsWrapper(SyncFlowMetricsWrapper):
    def __init__(self, operation_name):
        super(CinderVolumeMetricsWrapper, self).__init__("Ec2API", "/var/log/ec2api/service.log")
